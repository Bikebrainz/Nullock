// Regression corpus for the CRLF / HTTP-response-splitting probe's pure logic
// (no network). An adversarial audit found that the confirmation read ONLY the
// parsed headers, so a server that decoded the CR/LF but NOT the %3a colon
// emitted a colon-less physical line that the parser dropped -- a real split
// graded clean. splitConfirmed now also scans the raw header block. This locks:
//   - parsed-header confirmation (the common case);
//   - colon-less split line at a header-block boundary IS confirmed;
//   - a marker echoed only in the BODY is NOT confirmed (no false positive);
//   - a marker name appearing MID-LINE (reflected into another header's value)
//     is NOT confirmed (must start the line / be a real split);
//   - queryWith preserves other params and splices the raw payload verbatim;
//   - buildRequest's CR/LF guards on method/host/basePath/query/headers.
//
// It also locks the multi-sink additions -- POST body, path-segment, and
// reflected request-header injection points:
//   - bodyWith / pathWith splice the raw payload into a body param / path segment;
//   - buildRequest emits a form body (Content-Type + Content-Length) for POST and
//     NOT for GET (the body gate), respecting a caller-supplied Content-Type;
//   - buildHeaderProbe is the OPT-IN raw-send path: it carries one probe header's
//     value VERBATIM (even a literal CR/LF -- the very thing buildRequest drops),
//     while keeping the request line + every OTHER carried header CR/LF-guarded;
//   - selectedPoints parses the `in` selector (default/unknown -> query).
//
// Run via:  ctest -R crlf_injection -V

#include "crlf_injection.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>

using namespace Nullock::Core::CrlfInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using HdrList = QList<QPair<QString, QString>>;
HdrList H(std::initializer_list<QPair<QString, QString>> l) { return HdrList(l); }
const QString NAME = QStringLiteral("X-Nullock-Crlf");
const QString MARK = QStringLiteral("nlk424242");
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== splitConfirmed =================================================
    // Primary: the parser surfaced our planted header with our value.
    chk("parsed header X-Nullock-Crlf == marker -> confirmed",
        splitConfirmed(QByteArray(), H({{"X-Nullock-Crlf", "nlk424242"}}), NAME, MARK));
    chk("parsed header present but different value -> NOT confirmed",
        !splitConfirmed(QByteArray(), H({{"X-Nullock-Crlf", "nlk000000"}}), NAME, MARK));

    // Fallback: a colon-less split line the parser dropped (server decoded the
    // CR/LF but not %3a) still confirms via the raw header block.
    {
        QByteArray raw = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/html\r\n"
                         "X-Nullock-Crlf%3anlk424242\r\n"   // colon-less, parser drops it
                         "\r\n<html>body</html>";
        chk("colon-less split line in header block -> confirmed (raw fallback)",
            splitConfirmed(raw, H({{"Content-Type", "text/html"}}), NAME, MARK));
    }
    // No false positive: the marker echoed only in the BODY is not a split.
    {
        QByteArray raw = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/html\r\n\r\n"
                         "<html>X-Nullock-Crlf nlk424242 reflected here</html>";
        chk("marker only in BODY -> NOT confirmed (no FP)",
            !splitConfirmed(raw, H({{"Content-Type", "text/html"}}), NAME, MARK));
    }
    // No false positive: our payload reflected MID-LINE into another header's
    // value (server kept the CR/LF as literal text) is not a real split.
    {
        QByteArray raw = "HTTP/1.1 302 Found\r\n"
                         "Location: nlk%0d%0aX-Nullock-Crlf%3anlk424242\r\n\r\n";
        chk("marker mid-line in a Location value -> NOT confirmed (no FP)",
            !splitConfirmed(raw, H({{"Location", "nlk%0d%0aX-Nullock-Crlf%3anlk424242"}}), NAME, MARK));
    }
    // Baseline-clean: nothing planted -> not confirmed.
    chk("clean response -> NOT confirmed",
        !splitConfirmed(QByteArray("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhi"),
                        H({{"Server", "nginx"}}), NAME, MARK));
    // No delimited header block (body-only bytes) -> NOT confirmed even if a line
    // happens to look like the marker header (defensive contract hardening).
    chk("no header separator -> NOT confirmed (no body scan)",
        !splitConfirmed(QByteArray("X-Nullock-Crlf: nlk424242\njust body text"),
                        H({}), NAME, MARK));

    // ===== queryWith: preserve others, splice raw payload verbatim ========
    chk("queryWith replaces target raw, keeps others, no re-encoding of '%'",
        [](){ const QString q = queryWith("a=1&b=2", "b", "nlk%0d%0aX-Nullock-Crlf%3anlk1");
              return q.contains("a=1") && q.contains("b=nlk%0d%0aX-Nullock-Crlf%3anlk1")
                  && !q.contains("b=2"); }());
    chk("queryWith on empty existing -> single raw pair",
        queryWith("", "url", "nlk%0d%0aX") == "url=nlk%0d%0aX");

    // ===== buildRequest: CR/LF guard parity ==============================
    {
        Request req; req.host = "victim.tld"; req.basePath = "/"; req.method = "GET";
        chk("build: request line", buildRequest(req, "a=1").startsWith("GET /?a=1 HTTP/1.1\r\n"));
        chk("build: Host", buildRequest(req, "").contains("Host: victim.tld\r\n"));
        Request bh = req; bh.host = "victim.tld\r\nEvil: 1";
        chk("build: CRLF host -> no injected header", !buildRequest(bh, "").contains("\r\nEvil: 1"));
        Request bm = req; bm.method = "GET\r\nEvil: 1";
        chk("build: CRLF method -> no injected header", !buildRequest(bm, "").contains("\r\nEvil: 1"));
        Request bp = req; bp.basePath = "/a\r\nEvil: 1";
        chk("build: CRLF basePath -> no injected header", !buildRequest(bp, "").contains("\r\nEvil: 1"));
        chk("build: CRLF query -> no injected header", !buildRequest(req, "a\r\nEvil: 1").contains("\r\nEvil: 1"));
        Request bhe = req; bhe.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("build: CRLF carried header dropped", !buildRequest(bhe, "").contains("Evil: 1"));
    }

    // ===== buildRequest: POST body emission (the body gate) ===============
    {
        Request req; req.host = "victim.tld"; req.basePath = "/"; req.method = "POST";
        const QByteArray body = "url=nlk%0d%0aX-Nullock-Crlf%3anlk1";
        const QByteArray out = buildRequest(req, "", body);
        chk("build POST: request line uses POST", out.startsWith("POST / HTTP/1.1\r\n"));
        chk("build POST: form Content-Type",
            out.contains("\r\nContent-Type: application/x-www-form-urlencoded\r\n"));
        chk("build POST: Content-Length matches body",
            out.contains("\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n"));
        chk("build POST: body appended after blank line", out.endsWith("\r\n\r\n" + body));
        // A GET carrying a stray body must NOT emit one (the gate keeps GET intact).
        Request g = req; g.method = "GET";
        const QByteArray gout = buildRequest(g, "", body);
        chk("build GET+body -> no body (gate)",
            !gout.contains("Content-Length") && !gout.contains(body) && gout.endsWith("\r\n\r\n"));
        // A caller-supplied Content-Type is respected, not duplicated.
        Request ct = req; ct.headers.append({QStringLiteral("Content-Type"), QStringLiteral("text/plain")});
        const QByteArray cout = buildRequest(ct, "", body);
        chk("build POST: caller Content-Type respected (no dup)",
            cout.contains("Content-Type: text/plain\r\n")
            && !cout.contains("application/x-www-form-urlencoded"));
    }

    // ===== bodyWith: x-www-form-urlencoded body splicing ==================
    chk("bodyWith replaces target raw, keeps others, no '%' re-encoding",
        [](){ const QString b = bodyWith("a=1&b=2", "b", "nlk%0d%0aX-Nullock-Crlf%3anlk1");
              return b.contains("a=1") && b.contains("b=nlk%0d%0aX-Nullock-Crlf%3anlk1")
                  && !b.contains("b=2"); }());
    chk("bodyWith on empty existing -> single raw pair",
        bodyWith("", "url", "nlk%0d%0aX") == "url=nlk%0d%0aX");

    // ===== pathWith: trailing path-segment splicing =======================
    chk("pathWith appends payload as a trailing segment (single slash)",
        pathWith("/app", "nlk%0d%0aX-Nullock-Crlf%3anlk1") == "/app/nlk%0d%0aX-Nullock-Crlf%3anlk1");
    chk("pathWith on root keeps a single slash", pathWith("/", "nlk%0d%0aX") == "/nlk%0d%0aX");
    chk("pathWith empty base -> rooted", pathWith("", "x") == "/x");
    chk("pathWith preserves a trailing-slash base", pathWith("/a/", "x") == "/a/x");

    // ===== buildHeaderProbe: the opt-in raw-send path =====================
    {
        Request req; req.host = "victim.tld"; req.basePath = "/"; req.method = "GET";
        const QByteArray out = buildHeaderProbe(req, "Referer", "nlk%0d%0aX-Nullock-Crlf%3anlk1");
        chk("hdr-probe: carries the probe header value verbatim",
            out.contains("Referer: nlk%0d%0aX-Nullock-Crlf%3anlk1\r\n"));
        chk("hdr-probe: request line is GET / and CR/LF-safe", out.startsWith("GET / HTTP/1.1\r\n"));
        // The opt-in path carries even a LITERAL CR/LF value -- the very thing the
        // safe builder refuses, which is why the two builders are distinct.
        const QByteArray raw = buildHeaderProbe(req, "X-Forwarded-Host", "evil\r\nX-Nullock-Crlf: nlk1");
        chk("hdr-probe: literal-CRLF value carried raw (opt-in)",
            raw.contains("X-Forwarded-Host: evil\r\nX-Nullock-Crlf: nlk1\r\n"));
        Request bhe = req; bhe.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("build (safe) still DROPS that same literal-CRLF carried header",
            !buildRequest(bhe, "").contains("Evil: 1"));
        // Request line stays CR/LF-safe on the raw path too: a crafted host can't
        // splice a new header line.
        Request bh = req; bh.host = "victim.tld\r\nEvil: 1";
        chk("hdr-probe: CRLF host -> no spliced header line",
            !buildHeaderProbe(bh, "Referer", "x").contains("\r\nEvil: 1"));
        // The header NAME is neutralized (only the VALUE is raw).
        chk("hdr-probe: CRLF in header NAME -> no spliced header line",
            !buildHeaderProbe(req, "X-T\r\nEvil", "x").contains("\r\nEvil: "));
        // OTHER carried headers keep the drop-guard.
        Request oc = req; oc.headers.append({QStringLiteral("X-Other"), QStringLiteral("ok\r\nEvil: 1")});
        chk("hdr-probe: OTHER carried CRLF header still dropped",
            !buildHeaderProbe(oc, "Referer", "x").contains("Evil: 1"));
        // A carried header colliding with the probe name is replaced, not duplicated.
        Request col = req; col.headers.append({QStringLiteral("Referer"), QStringLiteral("orig")});
        const QByteArray cb = buildHeaderProbe(col, "Referer", "nlkPAYLOAD");
        chk("hdr-probe: probe header replaces a colliding carried one",
            cb.contains("Referer: nlkPAYLOAD\r\n") && !cb.contains("Referer: orig"));
        // An empty header name yields nothing (defensive).
        chk("hdr-probe: empty header name -> empty", buildHeaderProbe(req, "", "x").isEmpty());
    }

    // ===== selectedPoints: the `in` selector ==============================
    chk("selectedPoints empty -> query (default)", selectedPoints("") == QStringList{"query"});
    chk("selectedPoints 'query' -> query", selectedPoints("query") == QStringList{"query"});
    chk("selectedPoints 'all' -> four points",
        selectedPoints("all").size() == 4 && selectedPoints("all").contains("header"));
    chk("selectedPoints 'body,header' -> exactly those two",
        selectedPoints("body,header") == (QStringList{"body", "header"}));
    chk("selectedPoints is case-insensitive", selectedPoints("HEADER") == QStringList{"header"});
    chk("selectedPoints unknown -> query fallback", selectedPoints("bogus") == QStringList{"query"});
    chk("defaultHeaderNames includes Referer + X-Forwarded-Host",
        defaultHeaderNames().contains("Referer") && defaultHeaderNames().contains("X-Forwarded-Host"));

    std::fprintf(stderr, "crlf_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

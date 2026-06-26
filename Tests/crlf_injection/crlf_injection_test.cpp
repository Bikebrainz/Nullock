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
// Run via:  ctest -R crlf_injection -V

#include "crlf_injection.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

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

    std::fprintf(stderr, "crlf_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

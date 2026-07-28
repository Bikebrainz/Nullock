// Regression corpus for the HTTP/3-detection probe's pure logic.
//
// buildGet() writes the request-line target (path/query) and the Host header
// RAW, so each must reject CR/LF or a target-influenced field could inject a
// header / split the request line on the live connection. parseAltSvc() parses
// the EXTERNAL RFC-7838 Alt-Svc response header and must be memory-safe + classify
// h3 correctly. This locks both, plus looksHttp3.
//
// Run via:  ctest -R http3_logic -V

#include "http3_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::Http3Detect;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
Request baseReq() {
    Request r; r.host = "target.example"; r.port = 443; r.tls = true; return r;
}
int countSub(const QByteArray &h, const QByteArray &needle) {
    int n = 0, from = 0;
    while ((from = h.indexOf(needle, from)) != -1) { ++n; from += needle.size(); }
    return n;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== buildGet: well-formed =======================================
    {
        const QByteArray out = buildGet(baseReq());
        chk("get: default path '/'", out.startsWith("GET / HTTP/1.1\r\n"));
        chk("get: Host from req.host", out.contains("\r\nHost: target.example\r\n"));
        chk("get: hardcoded UA", out.contains("User-Agent: Nullock/http3-detect\r\n"));
        chk("get: terminated", out.endsWith("Connection: close\r\n\r\n"));
        chk("get: exactly one Host", countSub(out, "Host: ") == 1);
    }
    {
        // audit-12: this body-less GET forces Accept-Encoding: identity + Connection:
        // close, so a carried Content-Length / Transfer-Encoding (advertises a body
        // that never arrives -> the detect probe stalls or the socket desyncs),
        // Accept-Encoding (server compresses, defeating the forced identity the
        // Alt-Svc read depends on) or Connection must all be dropped. This was the one
        // GET builder the repo-wide carried-header sweep missed.
        Request r = baseReq();
        r.headers.append({ QStringLiteral("Content-Length"),    QStringLiteral("100") });
        r.headers.append({ QStringLiteral("Transfer-Encoding"), QStringLiteral("chunked") });
        r.headers.append({ QStringLiteral("Accept-Encoding"),   QStringLiteral("gzip, deflate, br") });
        r.headers.append({ QStringLiteral("Connection"),        QStringLiteral("keep-alive") });
        const QByteArray cg = buildGet(r);
        chk("get: carried Content-Length dropped (body-less GET)", !cg.contains("Content-Length"));
        chk("get: carried Transfer-Encoding dropped", !cg.contains("Transfer-Encoding"));
        chk("get: carried Accept-Encoding dropped -> exactly one, identity",
            countSub(cg, "Accept-Encoding:") == 1 && cg.contains("Accept-Encoding: identity\r\n")
            && !cg.contains("gzip"));
        chk("get: carried Connection dropped -> exactly one, close",
            countSub(cg, "Connection:") == 1 && cg.contains("Connection: close\r\n")
            && !cg.contains("keep-alive"));
        // The drop is not over-broad: a clean carried header is still emitted.
        Request clean = baseReq();
        clean.headers.append({ QStringLiteral("X-Trace"), QStringLiteral("ok") });
        chk("get: a clean carried header IS emitted", buildGet(clean).contains("X-Trace: ok\r\n"));
    }
    { Request r = baseReq(); r.path = "/foo"; chk("get: path used", buildGet(r).startsWith("GET /foo HTTP/1.1\r\n")); }
    {
        Request r = baseReq(); r.path = "/foo"; r.query = "a=b";
        chk("get: path?query", buildGet(r).startsWith("GET /foo?a=b HTTP/1.1\r\n"));
    }

    // ===== buildGet: CRLF-injection guard (host / path / query) =========
    {
        Request r = baseReq(); r.host = "target.example\r\nX-Injected: 1";
        const QByteArray out = buildGet(r);
        chk("guard: CR/LF in host -> empty", out.isEmpty());
        chk("guard: no injected header from a CRLF host", !out.contains("X-Injected"));
    }
    {
        // THE MEDIUM DRIVER: path injection rides the live request line.
        Request r = baseReq(); r.path = "/x\r\nX-Smuggled: 1";
        const QByteArray out = buildGet(r);
        chk("guard: CR/LF in path -> empty (request-line injection)", out.isEmpty());
        chk("guard: no smuggled header from a CRLF path", !out.contains("X-Smuggled"));
    }
    { Request r = baseReq(); r.path = "/a\nb"; chk("guard: bare LF in path -> empty", buildGet(r).isEmpty()); }
    {
        Request r = baseReq(); r.query = "a=b\r\nX-Q: 1";
        const QByteArray out = buildGet(r);
        chk("guard: CR/LF in query -> empty", out.isEmpty());
        chk("guard: no injected header from a CRLF query", !out.contains("X-Q"));
    }

    // ===== buildGet: custom-header handling ============================
    {
        Request r = baseReq(); r.headers = { {"Cookie", "s=1"} };
        chk("hdr: normal custom header included", buildGet(r).contains("\r\nCookie: s=1\r\n"));
    }
    {
        Request r = baseReq(); r.headers = { {"X-Bad", "v\r\nX-Smug: 1"} };
        const QByteArray out = buildGet(r);
        chk("hdr: CR/LF header value skipped (request still built)", !out.isEmpty() && !out.contains("X-Bad"));
        chk("hdr: no smuggled header leaks", !out.contains("X-Smug"));
    }
    {
        Request r = baseReq(); r.headers = { {"Host", "evil.example"} };
        const QByteArray out = buildGet(r);
        chk("hdr: custom Host dropped (no duplicate)", countSub(out, "Host: ") == 1 && !out.contains("evil.example"));
    }
    {
        // The header-NAME CR/LF guard (line 21) is a DISTINCT barrier from the value
        // guard (line 22): a name carrying CR/LF must be skipped so it can't split
        // the request line / inject a header. The value case above never exercises it.
        Request r = baseReq(); r.headers = { {"X\r\nInjected: 1", "v"} };
        const QByteArray out = buildGet(r);
        chk("hdr: CR/LF in a header NAME is skipped (nothing injected)", !out.contains("Injected"));
    }

    // ===== looksHttp3 ==================================================
    chk("h3: 'h3' is h3", looksHttp3("h3"));
    chk("h3: 'h3-29' is h3", looksHttp3("h3-29"));
    chk("h3: 'h3-Q050' is h3", looksHttp3("h3-Q050"));
    chk("h3: 'h2' is NOT h3", !looksHttp3("h2"));
    chk("h3: 'h3x' is NOT h3 (anchored on '-')", !looksHttp3("h3x"));
    chk("h3: 'H3' is NOT h3 (case-sensitive protocol-id)", !looksHttp3("H3"));
    chk("h3: empty is NOT h3", !looksHttp3(""));

    // ===== parseAltSvc ================================================
    {
        const auto ps = parseAltSvc("h3=\":443\"; ma=86400");
        chk("alt: one entry", ps.size() == 1);
        chk("alt: id h3, isHttp3", ps.size() == 1 && ps[0].id == "h3" && ps[0].isHttp3);
        chk("alt: authority quotes stripped", ps.size() == 1 && ps[0].authority == ":443");
        chk("alt: ma parsed", ps.size() == 1 && ps[0].maxAge == 86400);
    }
    chk("alt: h3-29 is http3", [] { const auto p = parseAltSvc("h3-29=\":443\""); return p.size() == 1 && p[0].isHttp3; }());
    chk("alt: h2 is not http3", [] { const auto p = parseAltSvc("h2=\":443\""); return p.size() == 1 && !p[0].isHttp3; }());
    chk("alt: 'clear' yields nothing", parseAltSvc("clear").isEmpty());
    chk("alt: 'h3x=' is not http3 (anti-FP)", [] { const auto p = parseAltSvc("h3x=\":443\""); return p.size() == 1 && !p[0].isHttp3; }());
    chk("alt: empty-authority 'h3=' still advertises h3", [] { const auto p = parseAltSvc("h3="); return p.size() == 1 && p[0].isHttp3; }());
    chk("alt: bare 'h3' (no '=') is skipped", parseAltSvc("h3").isEmpty());
    chk("alt: leading '=' (empty id) skipped", parseAltSvc("=foo").isEmpty());
    chk("alt: overflow ma= stays -1 (no crash)", [] {
        const auto p = parseAltSvc("h3=\":443\"; ma=99999999999999");
        return p.size() == 1 && p[0].maxAge == -1;
    }());
    {
        const auto ps = parseAltSvc("h3=\":443\", h2=\":443\"");
        chk("alt: multi-entry parsed", ps.size() == 2 && ps[0].isHttp3 && !ps[1].isHttp3);
    }
    chk("alt: quoted authority with host preserved", [] {
        const auto p = parseAltSvc("h3=\"alt.example:443\"");
        return p.size() == 1 && p[0].authority == "alt.example:443";
    }());

    std::fprintf(stderr, "http3_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

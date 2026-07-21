// Regression corpus for the SSRF scanner's pure request builder.
//
// buildRequest() writes method, basePath, and host RAW into the request line /
// Host header, so each must reject CR/LF or an attacker-influenced target field
// could inject a header or split the request. The guard previously covered
// method + basePath but NOT host; this locks all three plus the custom-header
// stripping (Host / Content-Length dropped, CR/LF headers skipped), and locks
// knownSsrfParams (lowercase, deduped, generics excluded).
//
// Run via:  ctest -R ssrf_logic -V

#include "ssrf_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QSet>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::SsrfScan;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

Request baseReq() {
    Request r;
    r.host = "target.example";
    r.port = 443;
    r.tls = true;
    r.method = "GET";
    r.basePath = "/api";
    return r;
}
int countSub(const QByteArray &h, const QByteArray &needle) {
    int n = 0, from = 0;
    while ((from = h.indexOf(needle, from)) != -1) { ++n; from += needle.size(); }
    return n;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== well-formed request ==========================================
    {
        const QByteArray out = buildRequest(baseReq(), QString());
        chk("valid: request line (no query -> no '?')", out.startsWith("GET /api HTTP/1.1\r\n"));
        chk("valid: Host from req.host", out.contains("\r\nHost: target.example\r\n"));
        chk("valid: hardcoded UA", out.contains("\r\nUser-Agent: Nullock/ssrf\r\n"));
        chk("valid: Accept-Encoding identity", out.contains("\r\nAccept-Encoding: identity\r\n"));
        chk("valid: terminated with blank line + Connection close", out.endsWith("Connection: close\r\n\r\n"));
        chk("valid: exactly one Host header", countSub(out, "Host: ") == 1);
    }
    {
        Request r = baseReq();
        const QByteArray out = buildRequest(r, "u=http%3A%2F%2F169.254.169.254%2F");
        chk("query: appended after '?'", out.startsWith("GET /api?u=http%3A%2F%2F169.254.169.254%2F HTTP/1.1\r\n"));
    }

    // ===== CRLF-injection guard: method / basePath / HOST ===============
    {
        Request r = baseReq(); r.method = "GET\r\nX-Injected: 1";
        chk("guard: CR/LF in method -> empty", buildRequest(r, QString()).isEmpty());
    }
    { Request r = baseReq(); r.method = "GET\n"; chk("guard: bare LF in method -> empty", buildRequest(r, QString()).isEmpty()); }
    {
        Request r = baseReq(); r.basePath = "/api\r\nX-Injected: 1";
        chk("guard: CR/LF in basePath -> empty", buildRequest(r, QString()).isEmpty());
    }
    { Request r = baseReq(); r.basePath = "/a\nb"; chk("guard: bare LF in basePath -> empty", buildRequest(r, QString()).isEmpty()); }
    {
        // THE FIX: host is written into the Host header and must be guarded too.
        Request r = baseReq(); r.host = "target.example\r\nX-Injected: 1";
        const QByteArray out = buildRequest(r, QString());
        chk("guard(FIX): CR/LF in host -> empty", out.isEmpty());
        chk("guard(FIX): no injected header leaks from a CRLF host", !out.contains("X-Injected"));
    }
    { Request r = baseReq(); r.host = "a\nb"; chk("guard(FIX): bare LF in host -> empty", buildRequest(r, QString()).isEmpty()); }
    { Request r = baseReq(); r.host = "a\rb"; chk("guard(FIX): bare CR in host -> empty", buildRequest(r, QString()).isEmpty()); }

    // ===== custom-header handling =======================================
    {
        Request r = baseReq();
        r.headers = { {"X-Custom", "yes"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: a normal custom header is included", out.contains("\r\nX-Custom: yes\r\n"));
    }
    {
        Request r = baseReq();
        r.headers = { {"X-Bad", "ok\r\nX-Smuggled: 1"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: a CR/LF header VALUE is skipped (request still built)", !out.isEmpty() && !out.contains("X-Bad"));
        chk("hdr: no smuggled header leaks", !out.contains("X-Smuggled"));
    }
    {
        Request r = baseReq();
        r.headers = { {"Host", "evil.example"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: a custom Host header is dropped (no duplicate Host)", countSub(out, "Host: ") == 1);
        chk("hdr: the custom Host value does not appear", !out.contains("evil.example"));
    }
    {
        Request r = baseReq();
        r.headers = { {"Content-Length", "9999"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: a custom Content-Length is dropped", !out.contains("Content-Length"));
    }

    // ===== knownSsrfParams ==============================================
    {
        const QStringList ps = knownSsrfParams();
        chk("params: includes the canonical url sink", ps.contains("url"));
        chk("params: includes redirect_uri", ps.contains("redirect_uri"));
        chk("params: includes callback_url", ps.contains("callback_url"));
        bool allLower = true;
        for (const QString &p : ps) if (p != p.toLower()) { allLower = false; break; }
        chk("params: every entry is lowercase (caller matches on toLower)", allLower);
        chk("params: no duplicates", QSet<QString>(ps.begin(), ps.end()).size() == ps.size());
        // generic short/search names are deliberately excluded (would steal the probe budget).
        chk("params: excludes generic 'q'", !ps.contains("q"));
        chk("params: excludes generic 'query'", !ps.contains("query"));
        chk("params: excludes generic 'search'", !ps.contains("search"));
        chk("params: a sane non-empty list", ps.size() > 30);
    }

    // ===== controlProvesFetch: the FAIL-CLOSED confirmation gate ==========
    // The shaped "control" (same-shape, non-fetchable sibling) is the only signal
    // that separates a real fetch from a reflection/echo template. A hit is
    // reported ONLY when the control ran cleanly AND did not reproduce the sig.
    chk("gate: control ran + no sig reproduced -> fetch-proven (report)",
        controlProvesFetch(true, false));
    chk("gate: control ran + sig reproduced -> shape-tracking (suppress)",
        !controlProvesFetch(true, true));
    // THE FIX: a FAILED control must NOT license a finding (was fail-open).
    chk("gate(FIX): control FAILED, no sig -> unproven (suppress, fail-closed)",
        !controlProvesFetch(false, false));
    chk("gate(FIX): control FAILED, sig present -> suppress",
        !controlProvesFetch(false, true));

    std::fprintf(stderr, "ssrf_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

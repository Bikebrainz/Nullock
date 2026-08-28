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
    // basePath's guard is `contains('\r') || contains('\n')`; the CR/LF and bare-LF
    // cases above both carry '\n', so the bare-CR HALF of the OR was unpinned
    // (host pins both halves at 83/84, basePath only the LF half). A lone CR is a
    // real request-line splice on lenient parsers.
    { Request r = baseReq(); r.basePath = "/a\rb"; chk("guard: bare CR in basePath -> empty", buildRequest(r, QString()).isEmpty()); }
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
        // CR/LF in the header NAME (not only the value) must be skipped too, else
        // "X-Evil\r\nX-Smuggled: 1" smuggles a second header line. (Value case above.)
        Request r = baseReq();
        r.headers = { {"X-Evil\r\nX-Smuggled: 1", "v"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: a CR/LF header NAME is skipped (no smuggle)", !out.contains("X-Smuggled"));
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
    {
        // The Host / Content-Length drop compares case-INSENSITIVELY, so a lowercase
        // carried "host"/"content-length" must be dropped too. Assert on the VALUE:
        // countSub("Host: ") stays 1 even if a lowercase "host:" line leaks, so it
        // would NOT discriminate a broken (case-sensitive) compare.
        Request r = baseReq();
        r.headers = { {"host", "evil.example"}, {"content-length", "31337"} };
        const QByteArray out = buildRequest(r, QString());
        chk("hdr: lowercase carried host dropped (case-insensitive)", !out.contains("evil.example"));
        chk("hdr: lowercase carried content-length dropped (case-insensitive)", !out.contains("31337"));
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

    // ---- ssrfCandidateParams: probe EVERY recognized param (maybefix #9) ----
    // The old auto-detect picked the FIRST recognized param and stopped, so a
    // real sink (url=) after a decoy (path=) was never probed. This helper
    // returns ALL recognized params in query order so the scanner probes each.
    {
        const QStringList c = ssrfCandidateParams("path=/etc&url=http://sink&q=hi");
        chk("candidates: both path and url returned (not just the first)",
            c.size() == 2 && c.contains("path") && c.contains("url"));
        chk("candidates: preserve query order (path before url)",
            c.size() == 2 && c.at(0) == "path" && c.at(1) == "url");
        chk("candidates: unrecognized (q) excluded",
            !ssrfCandidateParams("q=hi&search=x").contains("q"));
        chk("candidates: none recognized -> empty",
            ssrfCandidateParams("q=1&search=2&page=x").isEmpty()
            == false /* 'page' IS a known sink name */);
        chk("candidates: truly-generic query -> empty",
            ssrfCandidateParams("q=1&search=2").isEmpty());
        chk("candidates: dedup case-insensitive (URL + url -> one)",
            ssrfCandidateParams("URL=a&url=b").size() == 1);
        chk("candidates: original case preserved for injection",
            ssrfCandidateParams("TargetUrl=x").value(0) == "TargetUrl");
    }

    // ---- ssrfConfirms: the full per-probe verdict (was inline) ---------
    // controlProvesFetch was tested; the baseline-absence guard + detection
    // that compose the actual VULNERABLE decision were inline in confirm().
    {
        // Fetch-proven: not on baseline, probe carried it, control clean.
        chk("ssrfConfirms: baseline-absent + fetched + clean control -> VULNERABLE",
            ssrfConfirms(false, true, true, true, false));
        // Baseline already serves the signature -> served unconditionally, no fetch.
        chk("ssrfConfirms: signature already on baseline -> NOT confirmed",
            !ssrfConfirms(true, true, true, true, false));
        // Probe didn't transport / didn't carry the signature -> no detection.
        chk("ssrfConfirms: probe did not transport -> NOT confirmed",
            !ssrfConfirms(false, false, false, true, false));
        chk("ssrfConfirms: probe transported but no signature -> NOT confirmed",
            !ssrfConfirms(false, true, false, true, false));
        // Control reproduced the signature -> shape-tracking, not a fetch.
        chk("ssrfConfirms: control reproduced signature -> NOT confirmed (shape-tracking)",
            !ssrfConfirms(false, true, true, true, true));
        // Control failed to run -> FP defeater unrun, fail closed.
        chk("ssrfConfirms: control failed to run -> NOT confirmed (fail closed)",
            !ssrfConfirms(false, true, true, false, false));
    }

    // ---- isRoleLike: the IMDS credential-fetch gate (was inline) -------
    {
        chk("isRoleLike: a plain role name -> true", isRoleLike("ec2-instance-role"));
        chk("isRoleLike: empty -> false", !isRoleLike(QString()));
        chk("isRoleLike: 128 chars -> true (boundary)", isRoleLike(QString(128, QLatin1Char('a'))));
        chk("isRoleLike: 129 chars -> false (over boundary)", !isRoleLike(QString(129, QLatin1Char('a'))));
        chk("isRoleLike: contains a space -> false", !isRoleLike("role with space"));
        chk("isRoleLike: contains '<' (HTML error page) -> false", !isRoleLike("<html>err"));
        chk("isRoleLike: contains '{' (JSON envelope) -> false", !isRoleLike("{\"error\":1}"));
        // Must NOT reject legal AWS role characters (+=,.@_-).
        chk("isRoleLike: a legal AWS role with +=,.@_- chars -> true",
            isRoleLike("my.role+test=a,b@1_x-y"));
    }

    std::fprintf(stderr, "ssrf_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

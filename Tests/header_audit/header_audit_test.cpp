// Regression corpus for the security-header / CSP analyzer's pure logic (no
// network). An adversarial audit confirmed 10 gaps; this locks the fixes:
//   FN fixes (must now FIRE):
//     - a CSP with neither script-src nor default-src -> csp-no-script-restriction
//       (script is fully unrestricted, previously silent);
//     - scheme-prefixed wildcard https://* (and http://*) -> csp-wildcard-source;
//     - HSTS max-age=0 -> hsts-disabled, missing max-age -> hsts-invalid;
//     - a permissive X-Frame-Options (ALLOWALL/ALLOW-FROM) does NOT protect;
//     - a permissive or report-only frame-ancestors does NOT protect.
//   FP fixes (must NOT misfire):
//     - a malformed 'sha... token does NOT suppress the unsafe-inline finding;
//     - a real nonce/sha256 hash DOES suppress it;
//     - hostMatches' dot-guard: *.example.com does not match evilexample.com.
//   Plus parseCsp first-occurrence and buildRequest's CR/LF guards.
//
// Run via:  ctest -R header_audit -V

#include "header_audit.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::HeaderAudit;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using HdrList = QList<QPair<QString, QString>>;
HdrList H(std::initializer_list<QPair<QString, QString>> l) { return HdrList(l); }

// Keys analyze() emits for the given headers / TLS state.
QStringList keys(const HdrList &h, bool tls) {
    Result r;
    analyze(h, tls, r);
    QStringList ks;
    for (const auto &f : r.findings) ks << f.key;
    return ks;
}
bool has(const QStringList &ks, const char *k) { return ks.contains(QString::fromLatin1(k)); }
// A single CSP header, audited with TLS off (to isolate CSP-derived keys).
QStringList csp(const char *policy) {
    return keys(H({{"Content-Security-Policy", QString::fromLatin1(policy)}}), false);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== #1 no script governance -> high finding ========================
    chk("CSP img-src only (no script-src/default-src) -> csp-no-script-restriction",
        has(csp("img-src 'self'; upgrade-insecure-requests"), "csp-no-script-restriction"));
    chk("CSP frame-ancestors only -> still csp-no-script-restriction",
        has(csp("frame-ancestors 'none'"), "csp-no-script-restriction"));
    chk("CSP with script-src 'self' -> NOT csp-no-script-restriction",
        !has(csp("script-src 'self'"), "csp-no-script-restriction"));
    chk("CSP with only default-src -> NOT csp-no-script-restriction (governed)",
        !has(csp("default-src 'self'"), "csp-no-script-restriction"));

    // ===== #2/#4 scheme-prefixed wildcard ================================
    chk("script-src https://* -> csp-wildcard-source (the FN fix)",
        has(csp("script-src https://*"), "csp-wildcard-source"));
    chk("script-src http://* -> csp-wildcard-source",
        has(csp("script-src http://*"), "csp-wildcard-source"));
    chk("script-src * -> csp-wildcard-source (still)",
        has(csp("script-src *"), "csp-wildcard-source"));
    chk("script-src https: -> csp-wildcard-source (still)",
        has(csp("script-src https:"), "csp-wildcard-source"));
    chk("script-src 'self' https://cdn.example.com -> NOT wildcard",
        !has(csp("script-src 'self' https://cdn.example.com"), "csp-wildcard-source"));

    // ===== #10 hash-prefix tightening ====================================
    chk("unsafe-inline + a real 'sha256- hash -> unsafe-inline suppressed",
        !has(csp("script-src 'unsafe-inline' 'sha256-abc123'"), "csp-unsafe-inline"));
    chk("unsafe-inline + a nonce -> unsafe-inline suppressed",
        !has(csp("script-src 'unsafe-inline' 'nonce-r4nd0m'"), "csp-unsafe-inline"));
    chk("unsafe-inline + a malformed 'shazam token -> unsafe-inline STILL fires (FP fix)",
        has(csp("script-src 'unsafe-inline' 'shazam'"), "csp-unsafe-inline"));
    // A correct PREFIX but a malformed token -- an empty value, or no closing quote
    // -- is dropped by the browser, so it must NOT suppress the high finding (a
    // prefix-only startsWith check would fail OPEN and hide it on a policy where
    // injected inline script still executes).
    chk("unsafe-inline + empty 'nonce-' (no value) -> STILL fires",
        has(csp("script-src 'unsafe-inline' 'nonce-'"), "csp-unsafe-inline"));
    chk("unsafe-inline + empty 'sha256-' (no digest) -> STILL fires",
        has(csp("script-src 'unsafe-inline' 'sha256-'"), "csp-unsafe-inline"));
    chk("unsafe-inline + unterminated 'nonce-abc (no closing quote) -> STILL fires",
        has(csp("script-src 'unsafe-inline' 'nonce-abc"), "csp-unsafe-inline"));
    chk("unsafe-inline + a well-formed 'sha256-abc' STILL suppresses (no over-fire)",
        !has(csp("script-src 'unsafe-inline' 'sha256-abc'"), "csp-unsafe-inline"));

    // ===== parseCsp first-occurrence + bypassable host ====================
    chk("duplicate script-src: first ('unsafe-inline') wins, not the later 'self'",
        has(csp("script-src 'unsafe-inline'; script-src 'self'"), "csp-unsafe-inline"));
    chk("script-src ajax.googleapis.com -> csp-bypassable-host",
        has(csp("script-src https://ajax.googleapis.com"), "csp-bypassable-host"));

    // ===== #3/#7 HSTS max-age semantics ===================================
    chk("HSTS max-age=0 -> hsts-disabled (not the 'short' low)",
        [](){ const QStringList k = keys(H({{"Strict-Transport-Security", "max-age=0"}}), true);
              return has(k, "hsts-disabled") && !has(k, "hsts-weak"); }());
    chk("HSTS with no max-age -> hsts-invalid",
        has(keys(H({{"Strict-Transport-Security", "includeSubDomains"}}), true), "hsts-invalid"));
    chk("HSTS max-age=100 -> hsts-weak (short window)",
        has(keys(H({{"Strict-Transport-Security", "max-age=100"}}), true), "hsts-weak"));
    chk("HSTS max-age=31536000; includeSubDomains -> no hsts finding",
        [](){ const QStringList k = keys(H({{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"}}), true);
              return !has(k, "hsts-weak") && !has(k, "hsts-disabled") && !has(k, "hsts-no-subdomains"); }());
    chk("HSTS quoted max-age=\"31536000\" (RFC6797) -> NOT invalid (quote tolerated)",
        [](){ const QStringList k = keys(H({{"Strict-Transport-Security", "max-age=\"31536000\"; includeSubDomains"}}), true);
              return !has(k, "hsts-invalid") && !has(k, "hsts-weak") && !has(k, "hsts-disabled"); }());
    // audit-3 int-overflow fix: a max-age beyond LLONG_MAX (bare toLongLong -> 0)
    // must NOT be mis-graded as hsts-disabled, and the subdomain check must still
    // run (a strong, effectively-permanent policy that lacks includeSubDomains).
    chk("HSTS max-age beyond LLONG_MAX -> not disabled/weak, subdomain check still runs",
        [](){ const QStringList k = keys(H({{"Strict-Transport-Security", "max-age=100000000000000000000"}}), true);
              return !has(k, "hsts-disabled") && !has(k, "hsts-weak") && has(k, "hsts-no-subdomains"); }());

    // ===== #5 X-Frame-Options validation =================================
    chk("XFO: ALLOWALL -> clickjacking-missing (permissive, FN fix)",
        has(keys(H({{"X-Frame-Options", "ALLOWALL"}}), false), "clickjacking-missing"));
    chk("XFO: ALLOW-FROM https://x -> clickjacking-missing (deprecated/ignored)",
        has(keys(H({{"X-Frame-Options", "ALLOW-FROM https://x"}}), false), "clickjacking-missing"));
    chk("XFO: DENY -> NOT clickjacking-missing",
        !has(keys(H({{"X-Frame-Options", "DENY"}}), false), "clickjacking-missing"));
    chk("XFO: SAMEORIGIN (mixed case) -> NOT clickjacking-missing",
        !has(keys(H({{"X-Frame-Options", "SameOrigin"}}), false), "clickjacking-missing"));

    // ===== #6 frame-ancestors validation =================================
    chk("frame-ancestors 'none' (enforced) -> NOT clickjacking-missing",
        !has(csp("frame-ancestors 'none'"), "clickjacking-missing"));
    chk("frame-ancestors * (permissive) -> clickjacking-missing (FN fix)",
        has(csp("frame-ancestors *"), "clickjacking-missing"));
    chk("report-only frame-ancestors 'none' -> clickjacking-missing (RO doesn't block)",
        has(keys(H({{"Content-Security-Policy-Report-Only", "frame-ancestors 'none'"}}), false),
            "clickjacking-missing"));

    // ===== #8 hostMatches dot-guard (must NOT false-match) ================
    chk("hostMatches: *.amazonaws.com covers s3.amazonaws.com",
        hostMatches("*.amazonaws.com", "s3.amazonaws.com"));
    chk("hostMatches: evilexample.com is NOT covered by *.example.com (dot guard)",
        !hostMatches("evilexample.com", "*.example.com"));
    chk("hostMatches: a.example.com IS covered by *.example.com",
        hostMatches("a.example.com", "*.example.com"));

    // ===== hostOf ========================================================
    chk("hostOf strips scheme/path/port", hostOf("https://cdn.example.com:443/lib.js") == "cdn.example.com");
    chk("hostOf https://* -> *", hostOf("https://*") == "*");

    // ===== modern defense-in-depth headers ===============================
    // Positive: header absent -> finding fires. An empty header set leaves all
    // of these missing (COOP additionally needs an HTML Content-Type to fire).
    chk("Permissions-Policy absent -> missing-permissions-policy",
        has(keys(H({}), false), "missing-permissions-policy"));
    chk("COEP absent -> missing-coep",
        has(keys(H({}), false), "missing-coep"));
    chk("CORP absent -> missing-corp",
        has(keys(H({}), false), "missing-corp"));
    chk("X-Permitted-Cross-Domain-Policies absent -> missing-permitted-cross-domain-policies",
        has(keys(H({}), false), "missing-permitted-cross-domain-policies"));
    chk("COOP absent on an HTML document -> missing-coop",
        has(keys(H({{"Content-Type", "text/html; charset=utf-8"}}), false), "missing-coop"));
    chk("COOP absent on a non-HTML (JSON) response -> NOT missing-coop (doc-gated)",
        !has(keys(H({{"Content-Type", "application/json"}}), false), "missing-coop"));

    // Negative: header present -> finding suppressed.
    chk("Permissions-Policy present -> NOT missing-permissions-policy",
        !has(keys(H({{"Permissions-Policy", "geolocation=()"}}), false), "missing-permissions-policy"));
    chk("legacy Feature-Policy present -> NOT missing-permissions-policy",
        !has(keys(H({{"Feature-Policy", "geolocation 'none'"}}), false), "missing-permissions-policy"));
    chk("COOP present (HTML) -> NOT missing-coop",
        !has(keys(H({{"Content-Type", "text/html"}, {"Cross-Origin-Opener-Policy", "same-origin"}}), false),
             "missing-coop"));
    chk("COEP present -> NOT missing-coep",
        !has(keys(H({{"Cross-Origin-Embedder-Policy", "require-corp"}}), false), "missing-coep"));
    chk("CORP present -> NOT missing-corp",
        !has(keys(H({{"Cross-Origin-Resource-Policy", "same-origin"}}), false), "missing-corp"));
    chk("X-Permitted-Cross-Domain-Policies present -> NOT missing-permitted-cross-domain-policies",
        !has(keys(H({{"X-Permitted-Cross-Domain-Policies", "none"}}), false),
             "missing-permitted-cross-domain-policies"));

    // ===== audit-11: presence-only checks must not accept the WORST value =====
    {
        // SameSite=None explicitly opts INTO cross-site sending -- it is the one value
        // that grants no CSRF protection, yet a presence-only check credited it.
        chk("cookie: SameSite=None is NOT credited as protection",
            has(keys(H({{"Set-Cookie", "sid=abc123; Path=/; Secure; HttpOnly; SameSite=None"}}), true),
                "cookie-insecure"));
        // ...while a real SameSite value on an otherwise-complete cookie stays clean.
        chk("cookie: SameSite=Lax with Secure+HttpOnly -> no finding",
            !has(keys(H({{"Set-Cookie", "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"}}), true),
                 "cookie-insecure"));
        // Referrer-Policy: unsafe-url sends the FULL URL everywhere -- the very leak
        // the finding exists to raise, so presence alone must not silence it.
        const QStringList rpUnsafe = keys(H({{"Referrer-Policy", "unsafe-url"}}), false);
        chk("referrer: unsafe-url raises a finding (presence is not protection)",
            has(rpUnsafe, "referrer-policy-unsafe"));
        chk("referrer: a sane policy raises neither referrer finding",
            !has(keys(H({{"Referrer-Policy", "no-referrer"}}), false), "referrer-policy-unsafe")
            && !has(keys(H({{"Referrer-Policy", "no-referrer"}}), false), "referrer-policy-missing"));
        chk("referrer: absent still raises the missing finding",
            has(keys(H({{"X-Other", "1"}}), false), "referrer-policy-missing"));
    }

    // ===== buildRequest: CR/LF guard parity ==============================
    {
        Request req; req.host = "victim.tld"; req.basePath = "/";
        chk("build: request line", buildRequest(req).startsWith("GET / HTTP/1.1\r\n"));
        chk("build: Host", buildRequest(req).contains("Host: victim.tld\r\n"));
        Request bh = req; bh.host = "victim.tld\r\nEvil: 1";
        chk("build: CRLF host -> no injected header", !buildRequest(bh).contains("\r\nEvil: 1"));
        Request bp = req; bp.basePath = "/a\r\nEvil: 1";
        chk("build: CRLF basePath -> no injected header", !buildRequest(bp).contains("\r\nEvil: 1"));
        Request bq = req; bq.query = "a=1\r\nEvil: 1";
        chk("build: CRLF query -> no injected header", !buildRequest(bq).contains("\r\nEvil: 1"));
        Request bhe = req; bhe.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("build: CRLF carried header dropped", !buildRequest(bhe).contains("Evil: 1"));

        // audit-11: this body-less GET forces Accept-Encoding: identity + Connection:
        // close, so a carried Content-Length / Transfer-Encoding (advertises a body
        // that never arrives -> the probe stalls or the socket desyncs),
        // Accept-Encoding (server compresses, defeating the forced identity) or
        // Connection (contradicts the forced close) must all be dropped.
        Request carried = req;
        carried.headers.append({QStringLiteral("Content-Length"), QStringLiteral("100")});
        carried.headers.append({QStringLiteral("Transfer-Encoding"), QStringLiteral("chunked")});
        carried.headers.append({QStringLiteral("Accept-Encoding"), QStringLiteral("gzip, deflate, br")});
        carried.headers.append({QStringLiteral("Connection"), QStringLiteral("keep-alive")});
        const QByteArray cg = buildRequest(carried);
        chk("build: carried Content-Length dropped (body-less GET)", !cg.contains("Content-Length"));
        chk("build: carried Transfer-Encoding dropped", !cg.contains("Transfer-Encoding"));
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            cg.count("Accept-Encoding:") == 1 && cg.contains("Accept-Encoding: identity\r\n")
            && !cg.contains("gzip"));
        chk("build: carried Connection dropped -> exactly one, close",
            cg.count("Connection:") == 1 && cg.contains("Connection: close\r\n")
            && !cg.contains("keep-alive"));
        // A clean carried header is still emitted (the drop is not over-broad).
        Request clean = req;
        clean.headers.append({QStringLiteral("X-Trace"), QStringLiteral("ok")});
        chk("build: a clean carried header IS emitted", buildRequest(clean).contains("X-Trace: ok\r\n"));

        // audit-11: an empty basePath must normalize to "/" -- else the request line is
        // the malformed "GET  HTTP/1.1" (double space, no target).
        Request noPath; noPath.host = "victim.tld";
        chk("build: empty basePath normalizes to '/'",
            buildRequest(noPath).startsWith("GET / HTTP/1.1\r\n"));
    }

    std::fprintf(stderr, "header_audit_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

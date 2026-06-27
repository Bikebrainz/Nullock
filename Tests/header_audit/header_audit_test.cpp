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
    }

    std::fprintf(stderr, "header_audit_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

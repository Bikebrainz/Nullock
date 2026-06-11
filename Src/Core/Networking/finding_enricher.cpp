#include "finding_enricher.hpp"

#include <QHash>

namespace Nullock::Core::FindingEnricher {

namespace {

struct Mapping {
    const char *cwe;
    const char *owasp;
    double      cvssScore;
    const char *cvssVector;
    const char *compliance;   // comma-separated; split at use site
    const char *fix;
};

// Hand-curated table. Sources: CWE Top 25, OWASP Top 10 2021,
// FIRST CVSS v3.1 calculator, PCI-DSS v4.0, SOC2 CC* family.
// Add new detector kinds here when shipping new detectors.
const QHash<QString, Mapping> &table() {
    static const QHash<QString, Mapping> m = {
        // ---- Header hygiene ------------------------------------------
        { "missing-csp", {
            "CWE-1021", "A05:2021-Security Misconfiguration", 4.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "PCI-DSS-6.5.7,SOC2-CC6.1",
            "Add Content-Security-Policy with explicit allow-list." } },
        { "missing-hsts", {
            "CWE-319", "A02:2021-Cryptographic Failures", 4.3,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "PCI-DSS-4.2.1,SOC2-CC6.6",
            "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload." } },
        { "missing-xfo", {
            "CWE-1021", "A05:2021-Security Misconfiguration", 3.7,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "PCI-DSS-6.5.7",
            "Add X-Frame-Options: DENY (or use CSP frame-ancestors)." } },
        { "missing-xcto", {
            "CWE-693", "A05:2021-Security Misconfiguration", 3.1,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "PCI-DSS-6.5.7",
            "Add X-Content-Type-Options: nosniff." } },
        { "missing-rp", {
            "CWE-200", "A04:2021-Insecure Design", 3.1,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "GDPR-Art32",
            "Add Referrer-Policy: strict-origin-when-cross-origin." } },

        // ---- CSP granular --------------------------------------------
        { "csp-unsafe-inline", {
            "CWE-79", "A03:2021-Injection", 5.4,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "PCI-DSS-6.5.7",
            "Replace 'unsafe-inline' with hashes / nonces." } },
        { "csp-unsafe-eval", {
            "CWE-95", "A03:2021-Injection", 5.4,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "PCI-DSS-6.5.1",
            "Remove 'unsafe-eval'; refactor to avoid Function/eval." } },
        { "csp-no-frame-ancestors", {
            "CWE-1021", "A05:2021-Security Misconfiguration", 4.3,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "PCI-DSS-6.5.7",
            "Add frame-ancestors 'none' (or explicit allow-list)." } },

        // ---- Cookie hardening ----------------------------------------
        { "cookie-no-httponly", {
            "CWE-1004", "A05:2021-Security Misconfiguration", 5.4,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "PCI-DSS-6.5.10",
            "Add HttpOnly attribute (and Secure on TLS)." } },
        { "cookie-no-secure", {
            "CWE-614", "A02:2021-Cryptographic Failures", 5.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "PCI-DSS-6.5.10,SOC2-CC6.6",
            "Add Secure attribute -- send cookie only over TLS." } },
        { "cookie-no-samesite", {
            "CWE-1275", "A05:2021-Security Misconfiguration", 4.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "OWASP-ASVS-3.4.3",
            "Add SameSite=Lax (or Strict for session cookies)." } },
        { "cookie-host-prefix-violation", {
            "CWE-565", "A04:2021-Insecure Design", 5.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "",
            "__Host- prefix requires Secure, Path=/, no Domain attribute." } },

        // ---- Information disclosure ----------------------------------
        { "leaked-aws-key",        { "CWE-798", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-3.5.2,SOC2-CC6.1", "Rotate the leaked credential immediately; audit usage." } },
        { "leaked-aws-secret",     { "CWE-798", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-3.5.2,SOC2-CC6.1", "Rotate the leaked credential immediately; audit usage." } },
        { "leaked-gh-token",       { "CWE-798", "A07:2021-Identification and Authentication Failures", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "", "Revoke the token on github.com/settings/tokens." } },
        { "leaked-gh-app",         { "CWE-798", "A07:2021-Identification and Authentication Failures", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "", "Rotate the App installation token." } },
        { "leaked-slack",          { "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Revoke at api.slack.com/apps." } },
        { "leaked-stripe",         { "CWE-798", "A07:2021-Identification and Authentication Failures", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "PCI-DSS-3.5.2", "Rotate via the Stripe dashboard immediately." } },
        { "leaked-sendgrid",       { "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Rotate via SendGrid API key page." } },
        { "leaked-mapbox",         { "CWE-798", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Rotate via Mapbox account settings." } },
        { "leaked-google-api",     { "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Rotate at console.cloud.google.com/apis/credentials." } },
        { "leaked-private-key",    { "CWE-321", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-3.5.2,SOC2-CC6.1", "Rotate the key and audit anywhere it was deployed." } },

        // ---- Active probes -------------------------------------------
        { "reflected-xss",  { "CWE-79",  "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "PCI-DSS-6.5.7", "HTML-escape the reflected value at the output sink." } },
        { "open-redirect",  { "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Validate target against an allow-list before issuing 3xx." } },
        { "open-redirect-variant",  { "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Filter redirect schemes and host components." } },
        { "open-redirect-suspect",  { "CWE-601", "A01:2021-Broken Access Control", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "", "Validate target against an allow-list before issuing 3xx." } },
        { "sqli-error",     { "CWE-89",  "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries / ORM bindings." } },
        { "sqli-blind-time-mysql",        { "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries; never concatenate user input." } },
        { "sqli-blind-time-postgresql",   { "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries; never concatenate user input." } },
        { "sqli-blind-time-mssql",        { "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries; never concatenate user input." } },
        { "sqli-blind-time-sqlite",       { "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries; never concatenate user input." } },
        { "ssti-jinja-twig",   { "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Render user data via context, never inline into template source." } },
        { "ssti-erb",          { "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Render user data via context, never inline into template source." } },
        { "ssti-freemarker",   { "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Render user data via context, never inline into template source." } },
        { "ssti-velocity",     { "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Render user data via context, never inline into template source." } },
        { "ssti-smarty",       { "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Render user data via context, never inline into template source." } },
        { "lfi",            { "CWE-22",  "A01:2021-Broken Access Control", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", "", "Canonicalize paths and validate against an allow-list of files." } },
        { "cmd-injection",  { "CWE-78",  "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Don't shell out with user input; pass args as an exec() argv array." } },
        { "crlf-injection", { "CWE-93",  "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Strip CR/LF from any value that ends up in a response header." } },
        { "path-traversal", { "CWE-22",  "A01:2021-Broken Access Control", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Canonicalize and reject paths that escape the document root." } },
        { "ssrf-cloud-metadata", { "CWE-918", "A10:2021-Server-Side Request Forgery", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.8", "Use IMDSv2 (token-required); block 169.254.0.0/16 at egress." } },
        { "oast-token-fired",    { "CWE-918", "A10:2021-Server-Side Request Forgery", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Check /api/oast/poll after a delay to confirm OOB callback." } },
        { "ssrf-oast-confirmed", { "CWE-918", "A10:2021-Server-Side Request Forgery", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "PCI-DSS-6.5.8", "Confirmed OOB fetch -- block egress to internal ranges; allow-list outbound hosts." } },
        { "log4shell-oast-confirmed", { "CWE-917", "A03:2021-Injection", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Confirmed JNDI lookup -- patch log4j to 2.17+; set log4j2.formatMsgNoLookups." } },
        { "xxe-oast-confirmed",  { "CWE-611", "A05:2021-Security Misconfiguration", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Confirmed external-entity fetch -- disable DTDs / external entities in the XML parser." } },
        { "rce-oast-confirmed",  { "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Confirmed OOB from a command context -- treat as RCE; never shell out with user input." } },
        { "nosql-injection-suspect", { "CWE-943", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Whitelist allowed query operators; refuse JSON shapes with $-keys." } },
        { "ldap-injection-suspect",  { "CWE-90",  "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Escape LDAP metacharacters; use a vetted bind library." } },
        { "mass-assignment-suspect", { "CWE-915", "A04:2021-Insecure Design", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "", "Explicit allow-list of fields the user is permitted to set." } },
        { "proto-pollution-reflected", { "CWE-1321", "A04:2021-Insecure Design", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "", "Reject __proto__ / constructor / prototype keys before merge." } },
        { "hpp-stack-divergence",   { "CWE-235", "A04:2021-Insecure Design", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Normalize duplicate parameters before parsing." } },
        { "auth-bypass-original-url", { "CWE-285", "A01:2021-Broken Access Control", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.8", "Strip X-Original-URL / X-Rewrite-URL at the edge; never trust them." } },
        { "auth-bypass-rewrite-url",  { "CWE-285", "A01:2021-Broken Access Control", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.8", "Strip X-Original-URL / X-Rewrite-URL at the edge; never trust them." } },
        { "auth-bypass-xff",          { "CWE-285", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Strip X-Forwarded-For at the edge or validate the proxy chain." } },
        { "auth-bypass-real-ip",      { "CWE-285", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Strip X-Real-IP at the edge or validate the proxy chain." } },
        { "auth-bypass-orig-ip",      { "CWE-285", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Strip X-Originating-IP at the edge or validate the proxy chain." } },
        { "http-smuggling-clte-suspect", { "CWE-444", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "", "Reject messages with both Content-Length and Transfer-Encoding." } },
        { "cache-poison-xfh",         { "CWE-444", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Strip X-Forwarded-Host / treat as untrusted in cache keys." } },
        { "web-cache-deception",      { "CWE-525", "A04:2021-Insecure Design", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Don't cache responses to paths whose effective handler is dynamic." } },
        { "race-condition-suspect",   { "CWE-362", "A04:2021-Insecure Design", 7.5, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", "", "Add a unique-row constraint / SELECT FOR UPDATE around the mutation." } },

        // ---- Parameter mining (hidden inputs) -----------------------
        { "hidden-param-reflected", { "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Undocumented reflected param -- test it for XSS / injection; remove if unused." } },
        { "hidden-param",           { "CWE-200", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Undocumented param alters behavior -- review for hidden/debug functionality." } },

        // ---- IDOR / BOLA --------------------------------------------
        { "idor-horizontal", { "CWE-639", "A01:2021-Broken Access Control", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", "PCI-DSS-6.5.8", "Enforce per-object authorization server-side; don't trust client-supplied ids." } },

        // ---- Mass assignment (OWASP API #6) -------------------------
        { "mass-assignment", { "CWE-915", "A08:2021-Software and Data Integrity Failures", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "", "Bind an explicit allow-list of writable fields; never auto-bind the request body onto the model." } },

        // ---- Active CORS exploitability -----------------------------
        { "cors-reflected-credentialed", { "CWE-942", "A05:2021-Security Misconfiguration", 8.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "", "Reflect only an exact allow-list of trusted origins; never reflect arbitrary Origin with Allow-Credentials." } },
        { "cors-arbitrary-origin",       { "CWE-942", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Validate Origin against an exact allow-list; don't reflect untrusted origins." } },
        { "cors-null-origin",            { "CWE-942", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", "", "Never allow the 'null' origin -- it's reachable from sandboxed iframes / data URLs." } },
        { "cors-wildcard-credentials",   { "CWE-942", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "ACAO:* with Allow-Credentials is a broken policy; pin exact origins." } },
        { "cors-scheme-downgrade",       { "CWE-942", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Allowing the http origin of an https site enables credentialed reads from a MITM position; pin https only." } },

        // ---- JS recon -----------------------------------------------
        { "source-map-exposed", { "CWE-540", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't deploy .map files to production; strip sourceMappingURL from prod bundles." } },

        // ---- Verb tampering -----------------------------------------
        { "auth-bypass-verb-tampering", { "CWE-650", "A01:2021-Broken Access Control", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "PCI-DSS-6.5.8", "Enforce authorization independent of HTTP method; deny by default and ignore method-override headers." } },

        // ---- JWT weaknesses (passive analysis + active toolkit) ------
        { "jwt-alg-none",   { "CWE-347", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Reject alg:none; pin the expected algorithm server-side." } },
        { "jwt-no-exp",     { "CWE-613", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Require and enforce an 'exp' claim; keep lifetimes short." } },
        { "jwt-expired",    { "CWE-613", "A07:2021-Identification and Authentication Failures", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Confirm the server actually rejects expired tokens." } },
        { "jwt-long-exp",   { "CWE-613", "A07:2021-Identification and Authentication Failures", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Shorten token lifetime; use refresh tokens for longevity." } },
        { "jwt-kid",        { "CWE-347", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Treat kid as untrusted; never use it to build a file path or SQL." } },
        { "jwt-priv-claim", { "CWE-345", "A04:2021-Insecure Design", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't trust client-presented role/privilege claims without server checks." } },

        // ---- DOM-XSS taint (from the dom_taint extension) ------------
        { "dom-taint-html", { "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "PCI-DSS-6.5.7", "Sanitize before the markup sink; use textContent / a sanitizer." } },
        { "dom-taint-code", { "CWE-95", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "", "Never pass attacker-controllable data to eval/Function/setTimeout-string." } },
        { "dom-taint-nav",  { "CWE-601", "A01:2021-Broken Access Control", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "", "Validate the destination / src against an allow-list before assigning." } },

        // ---- GraphQL active probes ----------------------------------
        { "graphql-introspection-active", { "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Disable introspection in production." } },
        { "graphql-field-suggestion",     { "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Disable field suggestions (NoSchemaIntrospectionCustomRule)." } },
        { "graphql-alias-amplification",  { "CWE-770", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "", "Cap alias/field counts; enforce query-cost limits." } },
        { "graphql-depth-bypass",         { "CWE-770", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "", "Enforce a maximum query depth." } },
        { "graphql-batched-queries",      { "CWE-770", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "", "Disable batched queries or rate-limit per operation." } },

        // ---- CVE correlation ----------------------------------------
        { "cve-correlated", { "CWE-1395", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Upgrade the component to the fixed version named in the advisory." } },

        // ---- Information disclosure -- secondary --------------------
        { "git-head-exposed", { "CWE-538", "A05:2021-Security Misconfiguration", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.5", "Block .git/ at the reverse proxy; redeploy without VCS metadata." } },
        { "phpinfo-output",   { "CWE-200", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Delete the phpinfo() page; disable expose_php." } },
        { "exposed-dev-file", { "CWE-538", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-6.5.5", "Block exposed dev/VCS paths at the reverse proxy." } },
        { "spring-actuator",  { "CWE-200", "A05:2021-Security Misconfiguration", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "", "Restrict actuator endpoints; require management auth." } },
        { "spring-actuator-env",      { "CWE-200", "A05:2021-Security Misconfiguration", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "", "Disable /actuator/env; expose only /health if anything." } },
        { "spring-actuator-heap",     { "CWE-200", "A05:2021-Security Misconfiguration", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "", "Disable /actuator/heapdump immediately." } },
        { "deser-java",   { "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use safe-deserialization library; reject untrusted streams." } },
        { "deser-pickle", { "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use JSON; never pickle.loads untrusted bytes." } },
        { "deser-php",    { "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use json_encode/decode; never unserialize() untrusted." } },
        { "deser-ruby",   { "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use JSON; never Marshal.load untrusted bytes." } },
        { "deser-dotnet", { "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Stop using BinaryFormatter (deprecated); switch to System.Text.Json." } },

        // ---- Defaults for CMS / framework (info-only) ---------------
        { "cms-wordpress",  { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Tag for engagement notes; check WordPress + plugins for CVEs." } },
        { "cms-drupal",     { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Check Drupal core + contrib modules against drupal.org security advisories." } },
        { "cms-magento",    { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Check Magento version against Adobe Commerce security bulletins." } },
        { "cms-sitecore",   { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Check Sitecore version against Sitecore Knowledge Base advisories." } },
        { "cms-confluence", { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Check Confluence version against Atlassian advisories." } },
    };
    return m;
}

// Generic severity-based score for unknown kinds. Better than 0.0.
double defaultScoreForSeverity(const QString &s) {
    if (s == "critical") return 9.0;
    if (s == "high")     return 7.0;
    if (s == "medium")   return 5.0;
    if (s == "low")      return 3.0;
    if (s == "info")     return 0.0;
    return 0.0;
}

} // namespace

bool hasMapping(const QString &kind) {
    return table().contains(kind);
}

void enrich(Finding &f) {
    auto it = table().constFind(f.kind);
    if (it == table().constEnd()) {
        // Unknown kind -- give a generic severity-derived score so the
        // finding still has a CVSS number for sorting / SARIF.
        f.cvssScore = defaultScoreForSeverity(f.severity);
        return;
    }
    const Mapping &m = *it;
    f.cwe        = QString::fromLatin1(m.cwe);
    f.owasp      = QString::fromLatin1(m.owasp);
    // A 0.0 table score is a placeholder meaning "score isn't fixed for
    // this kind" -- e.g. cve-correlated carries a per-CVE CVSS, CMS tags
    // are informational. Fall back to a severity-derived number rather
    // than forcing 0.0 onto a critical finding.
    if (m.cvssScore > 0.0) {
        f.cvssScore  = m.cvssScore;
        f.cvssVector = QString::fromLatin1(m.cvssVector);
    } else if (f.cvssScore <= 0.0) {
        f.cvssScore  = defaultScoreForSeverity(f.severity);
    }
    f.fixSummary = QString::fromLatin1(m.fix);
    const QString comp = QString::fromLatin1(m.compliance);
    f.compliance.clear();
    if (!comp.isEmpty())
        f.compliance = comp.split(',', Qt::SkipEmptyParts);
}

} // namespace Nullock::Core::FindingEnricher

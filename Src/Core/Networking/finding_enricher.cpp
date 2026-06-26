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
        // Single-session enumeration lead: object ids are guessable and return
        // distinct objects, but it is NOT proven the access is unauthorized
        // (a public catalog is enumerable by design). Lower CVSS than a
        // confirmed break; confirm with a multi-identity replay (authz-divergence).
        { "idor-enumerable", { "CWE-639", "A01:2021-Broken Access Control", 5.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "PCI-DSS-6.5.8", "Enforce per-object authorization server-side; don't trust client-supplied ids. Confirm whether enumerable neighbors are actually unauthorized via a second-identity replay." } },

        // ---- Mass assignment (OWASP API #6) -------------------------
        { "mass-assignment", { "CWE-915", "A08:2021-Software and Data Integrity Failures", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "", "Bind an explicit allow-list of writable fields; never auto-bind the request body onto the model." } },

        // ---- Active CORS exploitability -----------------------------
        { "cors-reflected-credentialed", { "CWE-942", "A05:2021-Security Misconfiguration", 8.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "", "Reflect only an exact allow-list of trusted origins; never reflect arbitrary Origin with Allow-Credentials." } },
        { "cors-arbitrary-origin",       { "CWE-942", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Validate Origin against an exact allow-list; don't reflect untrusted origins." } },
        { "cors-null-origin",            { "CWE-942", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", "", "Never allow the 'null' origin -- it's reachable from sandboxed iframes / data URLs." } },
        { "cors-wildcard-credentials",   { "CWE-942", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "ACAO:* with Allow-Credentials is a broken policy; pin exact origins." } },
        { "cors-scheme-downgrade",       { "CWE-942", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Allowing the http origin of an https site enables credentialed reads from a MITM position; pin https only." } },
        { "cors-origin-normalization",   { "CWE-942", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", "", "The Origin allow-list normalizes the host (e.g. strips a trailing FQDN dot) before comparing, then reflects the raw origin; compare the exact, byte-for-byte origin string." } },

        // ---- JS recon -----------------------------------------------
        { "source-map-exposed", { "CWE-540", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't deploy .map files to production; strip sourceMappingURL from prod bundles." } },

        // ---- Verb tampering -----------------------------------------
        { "auth-bypass-verb-tampering", { "CWE-650", "A01:2021-Broken Access Control", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "PCI-DSS-6.5.8", "Enforce authorization independent of HTTP method; deny by default and ignore method-override headers." } },

        // ---- HTTP request smuggling ----------------------------------
        { "request-smuggling", { "CWE-444", "A05:2021-Security Misconfiguration", 9.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L", "", "Make the whole chain agree on request length: reject messages with both Content-Length and Transfer-Encoding, normalize at the front-end, and use HTTP/2 end-to-end where possible." } },

        // ---- NoSQL injection -----------------------------------------
        { "nosql-injection", { "CWE-943", "A03:2021-Injection", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "", "Reject query operators in user input: cast values to the expected type (string) and never let a parsed object reach the query; use an allow-list of fields." } },

        // ---- XXE -----------------------------------------------------
        { "xxe-injection", { "CWE-611", "A05:2021-Security Misconfiguration", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L", "PCI-DSS-6.5.1", "Disable DOCTYPE/external-entity resolution in the XML parser (e.g. FEATURE_SECURE_PROCESSING, disallow-doctype-decl)." } },

        // ---- SQL injection -------------------------------------------
        { "sql-injection", { "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Use parameterized queries / prepared statements everywhere; never concatenate input into SQL, and apply least-privilege DB accounts." } },
        { "ldap-injection", { "CWE-90", "A03:2021-Injection", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.1", "Escape user input per RFC 4515 before placing it in an LDAP search filter (or use a filter-builder API); allow-list expected characters and never concatenate raw input into the filter or DN." } },
        { "xpath-injection", { "CWE-643", "A03:2021-Injection", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.1", "Never concatenate user input into an XPath expression; use parameterized/precompiled XPath with variable binding, and allow-list expected characters." } },

        // ---- Reflected XSS -------------------------------------------
        { "reflected-xss", { "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "PCI-DSS-6.5.7", "Context-encode all reflected input (HTML-entity in body, attribute-encode in attributes, JS-encode in script); add a strict CSP as defense in depth." } },

        // ---- OS command injection ------------------------------------
        { "command-injection", { "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Never pass user input to a shell; use an exec API with an argument array and validate against a strict allow-list." } },

        // ---- Path traversal / LFI ------------------------------------
        { "path-traversal", { "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-6.5.8", "Resolve the requested path and confirm it stays within an allow-listed base directory (canonicalize, then prefix-check); never pass user input to file APIs raw." } },

        // ---- CRLF / HTTP response splitting --------------------------
        { "crlf-injection", { "CWE-113", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Strip or reject CR/LF in any user input that reaches a response header; use the framework's header API, never string concatenation." } },

        // ---- Web cache deception -------------------------------------
        { "web-cache-deception", { "CWE-525", "A05:2021-Security Misconfiguration", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", "", "Make the cache honor Cache-Control (don't cache by extension alone), and have the app reject unexpected path suffixes (404 instead of serving the page)." } },

        // ---- Sensitive file exposure ---------------------------------
        { "sensitive-file-exposure", { "CWE-538", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Remove the file from the web root / block the path at the server; rotate any leaked secrets." } },

        // ---- Subdomain takeover --------------------------------------
        { "subdomain-takeover", { "CWE-284", "A05:2021-Security Misconfiguration", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "", "Remove the dangling DNS record, or re-claim the referenced service; audit CNAMEs for de-provisioned targets." } },

        // ---- Exposed network services (port-scan -> findings bridge) --
        { "exposed-database",             { "CWE-668", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-1.3.1", "A database/data-store port is internet-reachable. Bind it to localhost or a private subnet, firewall the port, and require authentication." } },
        { "exposed-remote-admin",         { "CWE-668", "A05:2021-Security Misconfiguration", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-1.3.1", "A remote-administration service (RDP/VNC/Telnet) is reachable. Put it behind a VPN/bastion, restrict source IPs, and enforce MFA; replace cleartext protocols." } },
        { "exposed-management-interface", { "CWE-668", "A05:2021-Security Misconfiguration", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "", "An orchestration/management API (Docker/etcd/Kubernetes/Consul/Webmin) is exposed and is often unauthenticated. Firewall it to an admin network and require auth/mTLS." } },
        { "exposed-file-share",           { "CWE-668", "A05:2021-Security Misconfiguration", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "", "A file-share/RPC service (SMB/NFS/MSRPC/portmapper) faces the internet. Restrict it to the LAN/VPN and require authentication." } },
        { "exposed-cleartext-service",    { "CWE-319", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "A cleartext protocol (FTP/Telnet/POP3/IMAP/SNMP/LDAP) is reachable; credentials and data travel unencrypted. Switch to the TLS variant and disable the plaintext port." } },
        { "open-port",                    { "CWE-200", "A05:2021-Security Misconfiguration", 1.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "An open TCP port was found. Confirm the service is meant to be reachable; close or firewall it if not (reduce attack surface)." } },
        { "robots-disallowed-path",       { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "robots.txt Disallow points crawlers away from this path -- often an unlinked admin/backup/internal endpoint. Review it (and don't rely on robots.txt for access control)." } },
        { "waf-detected",                 { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Protective infrastructure (WAF/CDN/LB) identified in front of the target -- informational context for the engagement (expect rate-limiting/blocking; consider origin-IP discovery)." } },
        { "http3-advertised",             { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Host advertises HTTP/3 (QUIC) via Alt-Svc -- a distinct attack surface from the TCP path (separate stack/edge, sometimes different routing). Test the h3 path too and ensure it enforces the same controls as HTTP/1.1 and HTTP/2." } },
        { "content-discovered",           { "CWE-538", "A05:2021-Security Misconfiguration", 0.0, "", "", "An unlinked path was discovered by wordlist brute-force (admin/backup/config/VCS dir, etc.). Review whether it should be reachable; remove or authenticate dev/backup/VCS artifacts and don't rely on obscurity." } },
        { "host-header-injection",        { "CWE-20",  "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "An attacker-controlled Host/forwarded-host header reached a generated URL (Location or an absolute link in the body). Build absolute URLs (password-reset links, redirects, canonical tags) from a configured canonical hostname, never from the request Host or X-Forwarded-Host; allowlist the Host header at the edge." } },
        { "host-header-reflected",        { "CWE-20",  "A05:2021-Security Misconfiguration", 0.0, "", "", "An injected Host/forwarded-host value is reflected into the response body (not in a URL context). Confirm whether it reaches a redirect, an absolute link, or a password-reset email before treating it as exploitable host-header injection." } },

        // ---- HTTP method exposure ------------------------------------
        { "dangerous-http-methods", { "CWE-650", "A05:2021-Security Misconfiguration", 0.0, "", "", "Write methods (PUT/DELETE/PATCH) are ADVERTISED in the OPTIONS Allow header -- not confirmed callable or unauthenticated. Confirm intrusively (if authorized) whether they execute without auth before treating as exploitable; disable unused write methods and enforce auth + a per-route allow-list." } },
        { "webdav-enabled",         { "CWE-650", "A05:2021-Security Misconfiguration", 0.0, "", "", "WebDAV verbs are ADVERTISED in the OPTIONS Allow header -- not confirmed functional or unauthenticated (proxies/frameworks often echo a broad method list the backend rejects). Confirm with an authorized PROPFIND/PUT before treating as exploitable; disable WebDAV if unused (it can allow file upload/overwrite)." } },
        { "http-trace-enabled",     { "CWE-693", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Disable the TRACE method to prevent Cross-Site Tracing." } },

        // ---- TLS / certificate weaknesses ----------------------------
        { "tls-expired",              { "CWE-298", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "", "Renew the certificate; automate renewal so it can't lapse." } },
        { "tls-cert-expiring-soon",   { "CWE-298", "A02:2021-Cryptographic Failures", 2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", "", "Renew before expiry; automate renewal." } },
        { "tls-not-yet-valid",        { "CWE-298", "A02:2021-Cryptographic Failures", 4.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Check the server clock and certificate validity window." } },
        { "tls-self-signed",          { "CWE-295", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Use a certificate from a trusted CA so clients can verify it." } },
        { "tls-weak-key",             { "CWE-326", "A02:2021-Cryptographic Failures", 7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "", "Reissue with at least a 2048-bit RSA (or ECDSA P-256) key." } },
        { "tls-hostname-mismatch",    { "CWE-295", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Issue a certificate whose CN/SAN covers this host." } },
        { "tls-deprecated-protocol",  { "CWE-327", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Disable TLS 1.0/1.1; require TLS 1.2+." } },
        { "tls-legacy-protocol-enabled", { "CWE-327", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Disable TLS 1.0/1.1 at the server/load-balancer; require TLS 1.2+." } },

        // ---- Exposed secrets in client code --------------------------
        { "secret-exposed", { "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Move the credential server-side; rotate it immediately (assume compromised) and scope front-end keys to least privilege." } },

        // ---- Security headers / CSP ----------------------------------
        { "csp-missing",         { "CWE-693", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Deploy a Content-Security-Policy with a nonce/hash-based script-src and 'strict-dynamic'." } },
        { "csp-unsafe-inline",   { "CWE-693", "A05:2021-Security Misconfiguration", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Drop 'unsafe-inline'; use per-response nonces or hashes plus 'strict-dynamic'." } },
        { "csp-unsafe-eval",     { "CWE-693", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Remove 'unsafe-eval' and refactor any eval/new Function usage." } },
        { "csp-wildcard-source", { "CWE-693", "A05:2021-Security Misconfiguration", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Replace * / scheme-wide / data: script sources with an explicit nonce/hash allow-list." } },
        { "csp-bypassable-host", { "CWE-693", "A05:2021-Security Misconfiguration", 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Remove JSONP/gadget-serving CDN hosts from script-src; pin specific files via hash." } },
        { "csp-no-object-src",   { "CWE-693", "A05:2021-Security Misconfiguration", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Add object-src 'none' to block plugin-based script execution." } },
        { "csp-no-base-uri",     { "CWE-693", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Add base-uri 'none' (or 'self') to stop <base>-tag re-rooting of relative scripts." } },
        { "csp-no-script-restriction", { "CWE-693", "A05:2021-Security Misconfiguration", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "The CSP sets neither script-src nor default-src, so script is unrestricted -- add a nonce/hash-based script-src (with 'strict-dynamic')." } },
        { "csp-report-only",     { "CWE-693", "A05:2021-Security Misconfiguration", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Move the policy from Report-Only to an enforcing Content-Security-Policy header." } },
        { "hsts-missing",        { "CWE-319", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Send Strict-Transport-Security with a long max-age and includeSubDomains; preload." } },
        { "hsts-weak",           { "CWE-319", "A02:2021-Cryptographic Failures", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Raise HSTS max-age to at least 180 days (ideally 1 year + preload)." } },
        { "hsts-no-subdomains",  { "CWE-319", "A02:2021-Cryptographic Failures", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Add includeSubDomains to HSTS so subdomains can't be TLS-stripped." } },
        { "hsts-disabled",       { "CWE-319", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "max-age=0 forgets HSTS; set a long max-age (>=180d, ideally 1y) with includeSubDomains + preload." } },
        { "hsts-invalid",        { "CWE-319", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "The HSTS header has no valid max-age and is ignored; send Strict-Transport-Security: max-age=31536000; includeSubDomains." } },
        { "xcto-missing",        { "CWE-693", "A05:2021-Security Misconfiguration", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Send X-Content-Type-Options: nosniff on every response." } },
        { "clickjacking-missing",{ "CWE-1021", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "", "Set CSP frame-ancestors 'none' (or 'self'); X-Frame-Options as a fallback." } },
        { "referrer-policy-missing", { "CWE-200", "A01:2021-Broken Access Control", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "", "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) to stop URL/token leakage." } },
        { "cookie-insecure",     { "CWE-1004", "A05:2021-Security Misconfiguration", 5.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "", "Set Secure + HttpOnly + SameSite on session cookies." } },

        // ---- Open redirect -------------------------------------------
        { "open-redirect", { "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Validate redirect targets against an allow-list of relative paths or exact hosts; never redirect to a raw user-supplied URL." } },

        // ---- Web cache poisoning -------------------------------------
        { "web-cache-poisoning-confirmed", { "CWE-349", "A05:2021-Security Misconfiguration", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L", "", "Add every reflected request input to the cache key, or strip unkeyed headers at the edge before they reach the origin." } },
        { "web-cache-poisoning",           { "CWE-349", "A05:2021-Security Misconfiguration", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "", "Key the cache on the reflected header, or don't reflect untrusted headers into cacheable responses." } },
        { "web-cache-unkeyed-reflected",   { "CWE-349", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "", "An unkeyed header is reflected; confirm no fronting cache stores it, or add it to the cache key." } },

        // ---- Server-side template injection --------------------------
        { "ssti-confirmed",     { "CWE-1336", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Never pass user input into a template as code; render data through context-aware escaping or a logic-less template, and sandbox the engine." } },
        { "ssti-engine-likely", { "CWE-1336", "A03:2021-Injection", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "", "A template engine appears to process this input; confirm whether attacker-controlled syntax is evaluated and lock it down." } },

        // ---- JWT weaknesses (passive analysis + active toolkit) ------
        { "jwt-alg-none",   { "CWE-347", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Reject alg:none; pin the expected algorithm server-side." } },
        { "jwt-no-exp",     { "CWE-613", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Require and enforce an 'exp' claim; keep lifetimes short." } },
        { "jwt-expired",    { "CWE-613", "A07:2021-Identification and Authentication Failures", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Confirm the server actually rejects expired tokens." } },
        { "jwt-long-exp",   { "CWE-613", "A07:2021-Identification and Authentication Failures", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Shorten token lifetime; use refresh tokens for longevity." } },
        { "jwt-kid",        { "CWE-347", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Treat kid as untrusted; never use it to build a file path or SQL." } },
        { "jwt-priv-claim", { "CWE-345", "A04:2021-Insecure Design", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't trust client-presented role/privilege claims without server checks." } },
        { "jwt-signature-not-verified", { "CWE-347", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Verify the JWT signature on every request; reject a token whose signature doesn't match its payload." } },
        { "jwt-weak-secret", { "CWE-347", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Use a long random HMAC secret (or asymmetric keys); rotate any guessable/leaked secret." } },
        { "jwt-alg-confusion", { "CWE-347", "A02:2021-Cryptographic Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "Pin the expected algorithm server-side; never let the token's alg header pick the verification key (RS256->HS256 confusion)." } },

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
        { "graphql-dangerous-mutation",   { "CWE-285", "A01:2021-Broken Access Control", 5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N", "", "Verify per-mutation authorization; don't rely on the mutation being undocumented." } },
        { "graphql-sensitive-field",      { "CWE-213", "A01:2021-Broken Access Control", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Never expose secret/credential fields in the schema; gate them behind field-level auth." } },

        // ---- CVE correlation ----------------------------------------
        { "cve-correlated", { "CWE-1395", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Upgrade the component to the fixed version named in the advisory." } },
        { "tech-detected", { "CWE-200", "A05:2021-Security Misconfiguration", 1.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Suppress version banners (Server, X-Powered-By, generator meta) to slow version-specific attacks." } },

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

        // ---- Disclosure / misc passive findings ----------------------
        { "tech-detected",        { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Technology fingerprint -- recon only; keep components patched and suppress banners." } },
        { "server-version-leak",  { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Suppress the version in the Server header (ServerTokens Prod / server_tokens off)." } },
        { "x-powered-by",         { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Remove the X-Powered-By header." } },
        { "server-timing-leak",   { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Strip Server-Timing in production -- it leaks backend internals." } },
        { "etag-predictable",     { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Use opaque ETags; the inode-based default can leak file metadata." } },
        { "html-comment-leak",    { "CWE-615", "A05:2021-Security Misconfiguration", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Strip developer/debug comments from delivered HTML." } },
        { "internal-ip-leak",     { "CWE-200", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't expose internal IPs in responses/headers." } },
        { "internal-hostname-leak",{ "CWE-200", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Don't expose internal hostnames in responses/headers." } },
        { "robots-discloses-paths",{ "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "robots.txt is public -- don't list sensitive paths; protect them with auth instead." } },
        { "mixed-content",        { "CWE-319", "A02:2021-Cryptographic Failures", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", "PCI-DSS-4.2.1", "Serve all subresources over HTTPS; add upgrade-insecure-requests." } },
        { "sri-missing",          { "CWE-353", "A08:2021-Software and Data Integrity Failures", 4.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", "", "Add an integrity= (SHA-384) and crossorigin attribute to third-party <script>/<link> tags so a compromised CDN or dependency can't inject code; pin dependency versions." } },
        { "secret-in-url",        { "CWE-598", "A01:2021-Broken Access Control", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-6.5.3", "Keep secrets/tokens out of URLs (logs, history, Referer leak); use headers/body." } },
        { "storage-of-secrets",   { "CWE-312", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-3.4", "Don't store secrets in client-accessible storage / delivered source." } },
        { "csv-formula-injection",{ "CWE-1236", "A03:2021-Injection", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", "", "Prefix risky leading chars (= + - @) when exporting user data to CSV." } },
        { "reflected-file-download",{ "CWE-494", "A08:2021-Software and Data Integrity Failures", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Set Content-Disposition + safe filename; don't reflect user input into downloads." } },
        { "host-header-reflected-location",{ "CWE-644", "A03:2021-Injection", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "", "Build absolute URLs from a configured host, not the Host header." } },
        { "options-mutation-methods",{ "CWE-650", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "", "Disable write/mutation HTTP methods you don't serve." } },
        { "debug-method-allowed", { "CWE-489", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Disable TRACE/TRACK and debug methods in production." } },
        { "ws-cross-origin-accepted",{ "CWE-1385", "A05:2021-Security Misconfiguration", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "", "Validate the Origin on the WebSocket handshake (prevent CSWSH)." } },
        { "cache-vary-missing-cookie",{ "CWE-525", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Add Vary: Cookie (or mark private) so per-user responses aren't shared-cached." } },
        { "graphql-introspection",{ "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Disable GraphQL introspection in production." } },
        { "authz-divergence",     { "CWE-285", "A01:2021-Broken Access Control", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "SOC2-CC6.3", "Enforce consistent authorization across identities, roles and HTTP methods." } },
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

// Family fallback: a kind with no exact entry but a known prefix still gets a
// class-appropriate CWE/OWASP/fix (better than empty CWE/OWASP, which degrades
// reports + SARIF + OWASP-coverage grouping) and auto-covers future kinds in
// that family. Exact table entries always win over this.
const Mapping *familyMapping(const QString &kind) {
    struct Fam { const char *prefix; Mapping m; };
    static const QList<Fam> fams = {
        { "cookie-",  { "CWE-1004", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "PCI-DSS-6.5.10", "Harden the cookie: Secure, HttpOnly, SameSite (and the __Host- prefix where applicable)." } },
        { "csp-",     { "CWE-1021", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "PCI-DSS-6.5.7", "Tighten the Content-Security-Policy (avoid wildcards/unsafe-*; set the missing directive)." } },
        { "hsts-",    { "CWE-319", "A02:2021-Cryptographic Failures", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", "PCI-DSS-4.2.1,SOC2-CC6.6", "Strengthen Strict-Transport-Security: long max-age + includeSubDomains + preload." } },
        { "cors-",    { "CWE-942", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-6.5.9", "Restrict CORS: allow-list trusted origins; never reflect Origin with Allow-Credentials." } },
        { "missing-", { "CWE-693", "A05:2021-Security Misconfiguration", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "PCI-DSS-6.5.7", "Add the missing security response header." } },
        { "jwt-",     { "CWE-345", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "OWASP-ASVS-3.5", "Validate the JWT (algorithm, signature, expiry); never expose tokens in URLs or bodies." } },
        { "auth-",    { "CWE-287", "A07:2021-Identification and Authentication Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "SOC2-CC6.1", "Enforce authentication and transport security on this surface." } },
        { "exposed-", { "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "SOC2-CC6.1", "Restrict network/auth access to this exposed resource or service." } },
        { "graphql-", { "CWE-200", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "", "Disable GraphQL introspection in production; add query depth/complexity limits." } },
        { "deser-",   { "CWE-502", "A08:2021-Software and Data Integrity Failures", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "PCI-DSS-6.5.1", "Never deserialize untrusted data; use a safe format / type allow-list." } },
        { "ssti-",    { "CWE-1336", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "", "Don't render user input as a template; sandbox the engine." } },
        { "sqli-",    { "CWE-89", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "PCI-DSS-6.5.1", "Use parameterized queries / prepared statements." } },
        { "tls-",     { "CWE-295", "A02:2021-Cryptographic Failures", 5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", "PCI-DSS-4.2.1", "Fix the TLS configuration (valid cert, modern protocols/ciphers)." } },
        { "leaked-",  { "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "PCI-DSS-6.5.3", "Rotate the exposed secret and remove it from client-delivered content." } },
        { "dom-taint-",{ "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "", "Sanitize/encode untrusted data before it reaches DOM sinks." } },
        { "ssrf-",    { "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "", "Allow-list outbound destinations; block loopback/link-local/RFC1918." } },
        { "oast-",    { "CWE-918", "A10:2021-Server-Side Request Forgery", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "", "Investigate the confirmed out-of-band interaction." } },
        { "fw-",      { "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Technology fingerprint -- keep the framework patched and suppress version banners." } },
        { "cms-",     { "CWE-200", "A06:2021-Vulnerable and Outdated Components", 0.0, "", "", "Technology fingerprint -- keep the platform patched and check it against vendor advisories." } },
        { "protocol-",{ "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "", "Protocol/technology fingerprint (informational)." } },
    };
    for (const auto &fa : fams)
        if (kind.startsWith(QLatin1String(fa.prefix))) return &fa.m;
    return nullptr;
}

// Last-resort mapping so NO finding ever ships with an empty CWE/OWASP
// (which would degrade reports, SARIF, and OWASP-coverage grouping). Used
// only when neither the exact table nor a family prefix matches.
const Mapping &genericMapping() {
    static const Mapping g = {
        "CWE-200", "A05:2021-Security Misconfiguration", 0.0, "", "",
        "Review this finding; no class-specific mapping is available yet."
    };
    return g;
}

} // namespace

bool hasMapping(const QString &kind) {
    return table().contains(kind) || familyMapping(kind) != nullptr;
}

void enrich(Finding &f) {
    const Mapping *m = nullptr;
    auto it = table().constFind(f.kind);
    if (it != table().constEnd())                m = &*it;          // exact wins
    else if (const Mapping *fam = familyMapping(f.kind)) m = fam;   // family prefix
    else                                         m = &genericMapping();  // never empty

    f.cwe   = QString::fromLatin1(m->cwe);
    f.owasp = QString::fromLatin1(m->owasp);
    // A 0.0 table score is a placeholder meaning "score isn't fixed for this
    // kind" -- e.g. cve-correlated carries a per-CVE CVSS, tech tags are
    // informational. Fall back to a severity-derived number rather than
    // forcing 0.0 onto a higher-severity finding.
    if (m->cvssScore > 0.0) {
        f.cvssScore  = m->cvssScore;
        f.cvssVector = QString::fromLatin1(m->cvssVector);
    } else if (f.cvssScore <= 0.0) {
        f.cvssScore  = defaultScoreForSeverity(f.severity);
    }
    f.fixSummary = QString::fromLatin1(m->fix);
    const QString comp = QString::fromLatin1(m->compliance);
    f.compliance.clear();
    if (!comp.isEmpty())
        f.compliance = comp.split(',', Qt::SkipEmptyParts);
}

} // namespace Nullock::Core::FindingEnricher

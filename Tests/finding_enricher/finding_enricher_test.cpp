// Coverage corpus for FindingEnricher.
//
// Invariant: EVERY finding kind the toolkit emits must enrich to a non-empty
// CWE and OWASP category (and a fix line). An unmapped kind otherwise ships
// with empty CWE/OWASP, which silently degrades the HTML/JSON/SARIF reports
// and drops the finding out of the OWASP-coverage grouping. This corpus is
// the authoritative list of emitted kinds (passive_scanner + control_server
// active probes); add new kinds here when shipping new detectors.
//
// Run via:  ctest -R finding_enricher -V
// or:       ./Tests/finding_enricher/finding_enricher_test

#include "finding_enricher.hpp"
#include "passive_scanner.hpp"

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>

using namespace Nullock::Core;

namespace {

// Every finding kind emitted anywhere in the toolkit.
const QStringList &emittedKinds() {
    static const QStringList k = {
        "auth-bypass-verb-tampering", "auth-no-cache-control", "auth-over-http", "authz-divergence",
        "cache-vary-missing-cookie", "cms-woocommerce", "command-injection", "cookie-broad-path-no-samesite",
        "cookie-host-prefix-violation", "cookie-no-httponly", "cookie-no-samesite", "cookie-no-secure",
        "cookie-secure-prefix-violation", "cors-headers-wildcard", "cors-methods-wildcard", "cors-null-origin",
        "cors-origin-reflection", "cors-arbitrary-origin", "cors-reflected-credentialed",
        "cors-scheme-downgrade", "cors-origin-normalization", "cors-wildcard", "cors-wildcard-creds",
        "crlf-injection",
        "csp-no-base-uri", "csp-no-form-action", "csp-no-frame-ancestors", "csp-report-only",
        "csp-unsafe-eval", "csp-unsafe-inline", "csp-wildcard-src", "csv-formula-injection",
        "debug-method-allowed", "etag-predictable", "exposed-dev-file", "fw-angularjs",
        "fw-aspnet", "fw-django", "fw-express", "fw-laravel",
        "fw-nextjs", "fw-nuxt", "fw-rails", "fw-react",
        "fw-spa-state-leak", "fw-symfony", "fw-vue", "graphql-dangerous-mutation",
        "graphql-introspection", "graphql-introspection-active", "graphql-sensitive-field", "host-header-reflected-location",
        "hsts-no-preload", "hsts-no-subdomains", "hsts-short-max-age", "html-comment-leak",
        "idor-horizontal", "internal-hostname-leak", "internal-ip-leak", "jwt-echoed-in-body",
        "jwt-in-url", "mass-assignment", "missing-coep", "missing-coop",
        "missing-corp", "missing-permissions-policy", "mixed-content", "nosql-injection",
        "open-redirect", "options-mutation-methods", "path-traversal", "phpinfo-output",
        "protocol-graphql", "protocol-grpc", "race-condition-suspect", "reflected-file-download",
        "reflected-xss", "request-smuggling", "robots-disallowed-path", "robots-discloses-paths",
        "secret-in-url", "server-timing-leak", "server-version-leak", "source-map-exposed",
        "sql-injection", "ssti-confirmed", "ssti-engine-likely", "storage-of-secrets",
        "subdomain-takeover", "tech-detected", "waf-detected", "web-cache-deception",
        "web-cache-poisoning", "web-cache-poisoning-confirmed", "web-cache-unkeyed-reflected", "ws-cross-origin-accepted",
        "x-powered-by", "xxe-injection", "cve-correlated", "secret-exposed",
        "sensitive-file-exposure",
        // active probes added in the above-Burp climb
        "proto-pollution-reflected", "host-header-injection", "host-header-reflected",
        "http3-advertised", "ldap-injection", "xpath-injection", "content-discovered",
        "sri-missing", "ssrf-cloud-metadata", "ssrf-internal",
        "deser-java", "deser-php", "deser-pickle", "deser-ruby", "deser-dotnet",
        "jwt-alg-none", "jwt-signature-not-verified", "jwt-weak-secret", "jwt-alg-confusion",
    };
    return k;
}

// Spot-checks that the exact + family mappings resolve to the right CWE.
struct Spot { const char *kind; const char *cwe; };
const QList<Spot> &spotChecks() {
    static const QList<Spot> s = {
        { "missing-coep",                "CWE-693" },   // missing- family
        { "cookie-secure-prefix-violation", "CWE-1004" },// cookie- family
        { "cors-origin-reflection",      "CWE-942" },   // cors- family
        { "csp-wildcard-src",            "CWE-1021" },  // csp- family
        { "hsts-short-max-age",          "CWE-319" },   // hsts- family
        { "jwt-in-url",                  "CWE-345" },   // jwt- family
        { "fw-react",                    "CWE-200" },   // fw- family
        { "mixed-content",               "CWE-319" },   // exact
        { "secret-in-url",               "CWE-598" },   // exact
        { "csv-formula-injection",       "CWE-1236" },  // exact
        { "authz-divergence",            "CWE-285" },   // exact
        { "ws-cross-origin-accepted",    "CWE-1385" },  // exact
        { "cookie-no-httponly",          "CWE-1004" },  // pre-existing exact
        { "ldap-injection",              "CWE-90" },    // exact (new)
        { "host-header-injection",       "CWE-20" },    // exact (new)
        { "proto-pollution-reflected",   "CWE-1321" },  // exact (new)
        { "xpath-injection",             "CWE-643" },   // exact (new)
        { "ssrf-cloud-metadata",         "CWE-918" },   // exact (new)
        { "ssrf-internal",               "CWE-918" },   // ssrf- family (new)
        { "deser-java",                  "CWE-502" },   // exact (new)
        { "deser-dotnet",                "CWE-502" },   // exact (new)
        { "jwt-signature-not-verified",  "CWE-347" },   // exact (new)
        { "jwt-weak-secret",             "CWE-347" },   // exact (new)
    };
    return s;
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("Nullock");
    QCoreApplication::setApplicationName("finding-enricher-regression");

    int pass = 0, fail = 0;
    QStringList failures;

    // 1) Coverage invariant: every emitted kind enriches to non-empty CWE+OWASP.
    for (const QString &kind : emittedKinds()) {
        Finding f;
        f.kind = kind;
        f.severity = "medium";
        FindingEnricher::enrich(f);
        const bool ok = !f.cwe.isEmpty() && !f.owasp.isEmpty();
        if (ok) {
            ++pass;
        } else {
            std::fprintf(stderr, "  FAIL  coverage %s  (cwe='%s' owasp='%s')\n",
                         kind.toLocal8Bit().constData(),
                         f.cwe.toLocal8Bit().constData(),
                         f.owasp.toLocal8Bit().constData());
            ++fail;
            failures << ("coverage " + kind);
        }
    }
    std::fprintf(stderr, "  coverage: %d/%d emitted kinds enrich to non-empty CWE+OWASP\n",
                 pass, emittedKinds().size());

    // 2) Spot-check precise CWE resolution (exact + family).
    for (const auto &s : spotChecks()) {
        Finding f;
        f.kind = QString::fromLatin1(s.kind);
        f.severity = "medium";
        FindingEnricher::enrich(f);
        const QString want = QString::fromLatin1(s.cwe);
        if (f.cwe == want) {
            ++pass;
        } else {
            std::fprintf(stderr, "  FAIL  spot %s -> cwe %s (wanted %s)\n",
                         s.kind, f.cwe.toLocal8Bit().constData(), s.cwe);
            ++fail;
            failures << QString("spot %1").arg(s.kind);
        }
    }

    std::fprintf(stderr,
        "\n========================================\n"
        "Finding enricher regression: %d passed, %d failed\n"
        "========================================\n",
        pass, fail);
    if (fail > 0) {
        std::fprintf(stderr, "Failures:\n");
        for (const QString &f : failures)
            std::fprintf(stderr, "  - %s\n", f.toLocal8Bit().constData());
    }
    return fail == 0 ? 0 : 1;
}

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
        "idor-enumerable", "internal-hostname-leak", "internal-ip-leak", "jwt-echoed-in-body",
        "jwt-in-url", "mass-assignment", "missing-coep", "missing-coop",
        "missing-corp", "missing-permissions-policy", "missing-permitted-cross-domain-policies",
        "mixed-content", "nosql-injection",
        "open-redirect", "options-mutation-methods", "path-traversal", "phpinfo-output",
        "protocol-graphql", "protocol-grpc", "race-condition-suspect", "reflected-file-download",
        "reflected-xss", "request-smuggling", "robots-disallowed-path", "robots-discloses-paths",
        "secret-in-url", "server-timing-leak", "server-version-leak", "source-map-exposed",
        "sql-injection", "ssti-confirmed", "ssti-engine-likely", "storage-of-secrets",
        "subdomain-takeover", "tech-detected", "waf-detected", "web-cache-deception",
        "web-cache-poisoning", "web-cache-poisoning-confirmed", "web-cache-unkeyed-reflected", "ws-cross-origin-accepted",
        "ws-origin-not-validated",
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
        { "missing-coep",                "CWE-693" },   // exact (new) -- formerly missing- family
        { "missing-permitted-cross-domain-policies", "CWE-693" }, // exact (new)
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

    // 3) Idempotency / stale-vector contract. enrich() advertises (in the
    //    header) that it is safe to re-call on an already-enriched finding.
    //    A kind whose table CVSS score is 0.0 (info/recon, empty vector) must
    //    NOT leave a previously-stamped cvssVector in place: the 0.0-score path
    //    clears it, so a 0.0 kind never carries a vector. The inverse is also
    //    guarded -- a placeholder-0.0 kind that legitimately carries a
    //    per-finding score+vector (cve-correlated) must keep its vector.
    auto checkIdem = [&](const char *name, bool ok) {
        if (ok) {
            ++pass;
        } else {
            std::fprintf(stderr, "  FAIL  idempotency %s\n", name);
            ++fail;
            failures << QString("idempotency %1").arg(name);
        }
    };

    // 3a) A stale vector pre-seeded on a 0.0-score kind is cleared, and the
    //     score falls through to the severity default.
    {
        Finding f;
        f.kind       = "waf-detected";          // table cvssScore 0.0, empty vector
        f.severity   = "medium";
        f.cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N";  // stale seed
        FindingEnricher::enrich(f);
        checkIdem("0.0-kind clears pre-seeded vector",
                  f.cvssVector.isEmpty()
                  && qFuzzyCompare(f.cvssScore + 1.0, 5.0 + 1.0));   // medium -> 5.0
    }

    // 3b) Full re-enrich cycle: a finding first enriched as a scored kind (which
    //     stamps a vector) and later re-pointed at a 0.0-score kind must come
    //     out clean -- no stale vector, score back to the severity default.
    {
        Finding f;
        f.kind     = "missing-csp";             // table cvssScore 4.3, stamps a vector
        f.severity = "high";
        FindingEnricher::enrich(f);
        const bool stampedFirst = !f.cvssVector.isEmpty()
                                  && qFuzzyCompare(f.cvssScore + 1.0, 4.3 + 1.0);
        // Re-classified as an info/recon kind; upstream recomputes score to 0.
        f.kind      = "robots-disallowed-path"; // table cvssScore 0.0, empty vector
        f.cvssScore = 0.0;
        FindingEnricher::enrich(f);
        checkIdem("re-enrich onto 0.0-kind clears stamped vector",
                  stampedFirst
                  && f.cvssVector.isEmpty()
                  && qFuzzyCompare(f.cvssScore + 1.0, 7.0 + 1.0));   // high -> 7.0
    }

    // 3c) Guard against over-clearing: cve-correlated has a 0.0 *table* score
    //     (placeholder) but carries a real per-CVE score+vector. f.cvssScore is
    //     > 0.0, so neither 0.0-score branch runs and the vector is preserved.
    {
        Finding f;
        f.kind       = "cve-correlated";
        f.severity   = "high";
        f.cvssScore  = 8.8;
        f.cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N";
        const QString keptVector = f.cvssVector;
        FindingEnricher::enrich(f);
        checkIdem("cve-correlated keeps per-CVE vector",
                  f.cvssVector == keptVector
                  && qFuzzyCompare(f.cvssScore + 1.0, 8.8 + 1.0));
    }

    // 5) Confidence taxonomy + preserve-explicit contract.
    {
        auto conf = [&](const char *kind) {
            Finding f; f.kind = kind; f.severity = "medium";
            FindingEnricher::enrich(f);
            return f.confidence;
        };
        auto ck = [&](const char *label, bool ok) {
            if (ok) ++pass; else { ++fail; failures << label;
                std::fprintf(stderr, "  FAIL  %s\n", label); }
        };
        ck("oast kind -> confirmed",        conf("ssrf-oast-callback") == "confirmed");
        ck("time-based kind -> confirmed",  conf("sqli-time-based")    == "confirmed");
        ck("*-confirmed -> confirmed",      conf("rce-blind-confirmed")== "confirmed");
        ck("possible kind -> tentative",    conf("xxe-possible")       == "tentative");
        ck("-lead kind -> tentative",       conf("cors-lead")          == "tentative");
        ck("plain kind -> firm",            conf("missing-csp")        == "firm");
        // A scanner that already proved it keeps its explicit confidence.
        {
            Finding f; f.kind = "missing-csp"; f.severity = "medium";
            f.confidence = "confirmed";
            FindingEnricher::enrich(f);
            ck("explicit confidence preserved", f.confidence == "confirmed");
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

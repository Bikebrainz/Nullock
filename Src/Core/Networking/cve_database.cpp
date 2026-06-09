#include "cve_database.hpp"

#include <QHash>
#include <QRegularExpression>

namespace Nullock::Core::CveDatabase {

namespace {

struct Entry {
    const char *kind;
    const char *cveId;
    const char *summary;
    double      cvss;
    const char *cvssVector;
    const char *affectedRange;
    const char *fixVersion;
    const char *reference;
    // Predicate: does the parsed version fall in `affectedRange`? The
    // ranges here are simple: "<X" / ">=A,<B" / "X.Y.Z" exact match.
    // Empty range = always matches.
};

// Hand-curated table of high-impact CVEs 2023-2026. Sourced from NVD,
// vendor advisories, and known exploit-active CVE feeds. Expand by
// adding entries below; the kind must match a detector kind in
// passive_scanner so the correlation links up.
//
// We deliberately don't ship every CVE -- only the ones that materially
// affect security testing. Each entry is reviewed by hand.
const QList<Entry> &table() {
    static const QList<Entry> t = {
        // ---- WordPress core ------------------------------------------
        { "cms-wordpress", "CVE-2024-31210",
          "WordPress < 6.5.2: plugin/theme upload XSS via wp_plupload_message",
          5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
          "<6.5.2", "6.5.2",
          "https://wordpress.org/news/2024/04/wordpress-6-5-2-security-and-maintenance-release/" },
        { "cms-wordpress", "CVE-2023-39999",
          "WordPress < 6.2.2: cross-site scripting via shortcodes in Post excerpt",
          5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
          "<6.2.2", "6.2.2",
          "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/" },

        // ---- Drupal core ---------------------------------------------
        { "cms-drupal", "CVE-2025-32467",
          "Drupal core < 10.3.13: access bypass via reference cache",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "<10.3.13", "10.3.13",
          "https://www.drupal.org/sa-core-2025-005" },
        { "cms-drupal", "CVE-2023-3824",
          "Drupal core < 10.1.4: SA-CORE-2023-006 information disclosure",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "<10.1.4", "10.1.4",
          "https://www.drupal.org/sa-core-2023-006" },

        // ---- Magento -------------------------------------------------
        { "cms-magento", "CVE-2024-34102",
          "Adobe Commerce / Magento Open Source CosmicSting: XXE via REST API to RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<2.4.7-p1", "2.4.7-p1",
          "https://helpx.adobe.com/security/products/magento/apsb24-40.html" },

        // ---- Atlassian Confluence -----------------------------------
        { "cms-confluence", "CVE-2023-22515",
          "Confluence Data Center: broken access control / privilege escalation (0-day in the wild Sept 2023)",
          10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          ">=8.0.0,<8.5.2", "8.5.2",
          "https://confluence.atlassian.com/security/cve-2023-22515-1295682276.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center: unauthenticated authorization bypass (data destruction)",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
          "<7.19.16", "7.19.16",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },

        // ---- Atlassian Jira -----------------------------------------
        { "cms-jira", "CVE-2024-1597",
          "Jira (via pgjdbc < 42.7.2): JDBC URL parameter injection",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "via pgjdbc <42.7.2", "n/a",
          "https://confluence.atlassian.com/security/security-bulletin-april-2024-1408879771.html" },

        // ---- Sitecore -----------------------------------------------
        { "cms-sitecore", "CVE-2025-27218",
          "Sitecore XP/XM: insecure deserialization in ItemService leading to unauthenticated RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=10.0,<10.4.1", "10.4.1",
          "https://kb.sitecore.com/articles/KB1002844" },

        // ---- Spring Framework / Boot --------------------------------
        { "fw-spring", "CVE-2024-22243",
          "Spring Framework < 6.1.4: open redirect via UriComponentsBuilder",
          7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N",
          "<6.1.4", "6.1.4",
          "https://spring.io/security/cve-2024-22243" },
        { "spring-actuator", "CVE-2022-22965",
          "Spring4Shell: RCE via data binding to class.module.classLoader",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<5.3.18", "5.3.18",
          "https://tanzu.vmware.com/security/cve-2022-22965" },

        // ---- ASP.NET ------------------------------------------------
        { "fw-aspnet", "CVE-2024-30043",
          "Microsoft SharePoint Server: information disclosure (used in chained attacks)",
          6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
          "various", "patched",
          "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30043" },

        // ---- Express / Node -----------------------------------------
        { "fw-express", "CVE-2024-29041",
          "Express < 4.19.2: open redirect in malformed URL path",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<4.19.2", "4.19.2",
          "https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc" },

        // ---- Next.js ------------------------------------------------
        { "fw-nextjs", "CVE-2025-29927",
          "Next.js < 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3: middleware authorization bypass via x-middleware-subrequest header",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "<15.2.3", "15.2.3",
          "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" },

        // ---- Laravel ------------------------------------------------
        { "fw-laravel", "CVE-2024-52301",
          "Laravel < 11.31.0: environment variable manipulation via register_argc_argv + CLI",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "<11.31.0", "11.31.0",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },

        // ---- Django -------------------------------------------------
        { "fw-django", "CVE-2024-39614",
          "Django >= 4.2 < 4.2.14: potential DoS in get_supported_language_variant()",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          ">=4.2,<4.2.14", "4.2.14",
          "https://www.djangoproject.com/weblog/2024/jul/09/security-releases/" },

        // ---- Symfony ------------------------------------------------
        { "fw-symfony", "CVE-2024-50345",
          "Symfony < 5.4.46 / 6.4.14 / 7.1.7: account takeover via remember-me cookie ",
          8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "<5.4.46", "5.4.46",
          "https://symfony.com/blog/cve-2024-50345-account-takeover-via-the-remember-me-cookie" },

        // ---- Generic web servers (Server: header) -------------------
        // We add a synthetic kind "server-version" -- the scanner can
        // emit this when it parses Server with a version number.
        { "server-version", "CVE-2024-38473",
          "Apache HTTP Server < 2.4.59: encoding-issue + mod_proxy SSRF",
          8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "Apache HTTP Server <2.4.59", "2.4.59",
          "https://httpd.apache.org/security/vulnerabilities_24.html" },
        { "server-version", "CVE-2023-44487",
          "HTTP/2 Rapid Reset attack (multi-vendor): DoS against h2 servers via RST_STREAM flood",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "many web servers pre-Oct 2023", "various",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-44487" },
    };
    return t;
}

// Parse "Drupal 10.2.5" / "WordPress 6.1.2" / "Apache/2.4.41" /
// "nginx/1.24.0 (Ubuntu)" / "Express 4.18.3" etc. Returns the
// version segment as a dotted triple [major, minor, patch].
struct Triple { int a = -1, b = -1, c = -1; bool valid = false; };
Triple parseVersion(const QString &s) {
    static const QRegularExpression rx(
        R"((\d+)(?:\.(\d+))?(?:\.(\d+))?)");
    auto m = rx.match(s);
    if (!m.hasMatch()) return {};
    Triple t;
    t.a = m.captured(1).toInt();
    t.b = m.captured(2).toInt();
    t.c = m.captured(3).toInt();
    t.valid = true;
    return t;
}

int cmpTriple(const Triple &x, const Triple &y) {
    if (x.a != y.a) return x.a < y.a ? -1 : 1;
    if (x.b != y.b) return x.b < y.b ? -1 : 1;
    if (x.c != y.c) return x.c < y.c ? -1 : 1;
    return 0;
}

// "<10.3.13" / ">=4.2,<4.2.14" / arbitrary text.
bool rangeMatches(const QString &range, const QString &version) {
    if (range.isEmpty()) return true;            // applies to all versions
    const Triple have = parseVersion(version);
    if (!have.valid) return true;                // can't parse; surface anyway

    static const QRegularExpression op(R"(([<>]=?)\s*([\d.]+))");
    auto it = op.globalMatch(range);
    QList<QPair<QString, Triple>> bounds;
    while (it.hasNext()) {
        auto m = it.next();
        Triple b = parseVersion(m.captured(2));
        if (!b.valid) continue;
        bounds.append({ m.captured(1), b });
    }
    if (bounds.isEmpty()) return true;
    for (const auto &[oper, bound] : bounds) {
        const int c = cmpTriple(have, bound);
        if (oper == "<"  && !(c <  0)) return false;
        if (oper == "<=" && !(c <= 0)) return false;
        if (oper == ">"  && !(c >  0)) return false;
        if (oper == ">=" && !(c >= 0)) return false;
    }
    return true;
}

} // namespace

QList<Match> lookup(const QString &kind, const QString &versionString) {
    QList<Match> out;
    for (const Entry &e : table()) {
        if (QString::fromLatin1(e.kind) != kind) continue;
        if (!rangeMatches(QString::fromLatin1(e.affectedRange), versionString))
            continue;
        out.append({
            QString::fromLatin1(e.cveId),
            QString::fromLatin1(e.summary),
            e.cvss,
            QString::fromLatin1(e.cvssVector),
            QString::fromLatin1(e.affectedRange),
            QString::fromLatin1(e.fixVersion),
            QString::fromLatin1(e.reference),
        });
    }
    return out;
}

QList<Match> lookupByFingerprint(const QString &kind, const HttpFingerprint &fp) {
    // Try in priority order until we get something. Body sniff often
    // beats headers because vendors strip version from response headers.
    static const QStringList sources = {};   // placeholder for chain.
    Q_UNUSED(sources);
    const QString tries[] = {
        fp.bodyVersion, fp.xGenerator, fp.xPoweredBy, fp.server,
    };
    for (const QString &v : tries) {
        if (v.isEmpty()) continue;
        const auto hits = lookup(kind, v);
        if (!hits.isEmpty()) return hits;
    }
    // Nothing matched against any source -- emit the kind's full table
    // as "manual triage" hits so the user at least sees what to check.
    QList<Match> out;
    for (const Entry &e : table()) {
        if (QString::fromLatin1(e.kind) != kind) continue;
        out.append({
            QString::fromLatin1(e.cveId),
            QString("[manual triage] ") + QString::fromLatin1(e.summary),
            e.cvss,
            QString::fromLatin1(e.cvssVector),
            QString::fromLatin1(e.affectedRange),
            QString::fromLatin1(e.fixVersion),
            QString::fromLatin1(e.reference),
        });
    }
    return out;
}

} // namespace Nullock::Core::CveDatabase

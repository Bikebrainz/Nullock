// Regression corpus for the version -> CVE correlation database.
//
// Each case asserts that CveDatabase::lookup(kind, "<name> <version>")
// does (or does NOT) return a given CVE for a given product version, and
// optionally that its CVSS base score matches. This locks in the accuracy
// established by the web-verification audit so future edits to
// cve_database.cpp can't silently reintroduce:
//   * false positives on PATCHED builds (the per-branch range bug),
//   * wrong CVSS scores,
//   * resurrected bogus / removed entries.
//
// Run via:  ctest -R cve_database -V
// or:       ./Tests/cve_database/cve_database_test
//
// Two-sided per CVE: a just-vulnerable version must match; the fix version
// (and out-of-range versions) must NOT.

#include "cve_database.hpp"

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cmath>
#include <cstdio>

using namespace Nullock::Core;

namespace {

struct Case {
    const char *label;
    const char *kind;
    const char *version;      // "<Name> <ver>" as the fingerprinter passes it
    const char *cveId;        // "" => assert the kind returns NO matches at all
    bool        negative;     // true => assert cveId is NOT present
    double      expectCvss;   // >0 => assert the matched CVE's cvss equals this (only when present)
};

bool hasCve(const QList<CveDatabase::Match> &m, const QString &id, double &cvssOut) {
    for (const auto &x : m)
        if (x.cveId == id) { cvssOut = x.cvss; return true; }
    return false;
}

const QList<Case> &corpus() {
    static const QList<Case> c = {
        // ---- Confluence: per-branch FP fix + corrected CVSS -------------
        { "Confluence 8.4.1 -> 22515",                "cms-confluence", "Confluence 8.4.1", "CVE-2023-22515", false, 9.8 },
        { "Confluence 8.4.5 (patched 8.4) -> NOT 22515 (FP fix)", "cms-confluence", "Confluence 8.4.5", "CVE-2023-22515", true, 0 },
        { "Confluence 8.5.1 -> 22518 @ 9.8",          "cms-confluence", "Confluence 8.5.1", "CVE-2023-22518", false, 9.8 },
        { "Confluence 8.5.4 (patched) -> NOT 22527",  "cms-confluence", "Confluence 8.5.4", "CVE-2023-22527", true, 0 },
        { "Confluence 7.13.5 -> 26134",               "cms-confluence", "Confluence 7.13.5", "CVE-2022-26134", false, 9.8 },
        { "Confluence 7.19.16 (patched) -> NOT 26134","cms-confluence", "Confluence 7.19.16", "CVE-2022-26134", true, 0 },

        // ---- Jira: corrected CVSS + ranges ------------------------------
        { "Jira 8.0.1 -> 11581 @ 9.8",                "cms-jira", "Jira 8.0.1", "CVE-2019-11581", false, 9.8 },
        { "Jira 8.22.0 (patched) -> NOT 0540",        "cms-jira", "Jira 8.22.0", "CVE-2022-0540", true, 0 },

        // ---- Jenkins / Grafana ------------------------------------------
        { "Jenkins 2.426.1 -> 23897",                 "app-jenkins", "Jenkins 2.426.1", "CVE-2024-23897", false, 9.8 },
        { "Jenkins 2.426.3 (patched) -> NOT 23897",   "app-jenkins", "Jenkins 2.426.3", "CVE-2024-23897", true, 0 },
        { "Grafana 8.2.0 -> 43798",                   "app-grafana", "Grafana 8.2.0", "CVE-2021-43798", false, 7.5 },
        { "Grafana 8.5.0 -> NOT 43798",               "app-grafana", "Grafana 8.5.0", "CVE-2021-43798", true, 0 },

        // ---- Elasticsearch (1.x banner version) -------------------------
        { "ES 1.1.0 -> 3120 @ 6.8",                   "app-elasticsearch", "Elasticsearch 1.1.0", "CVE-2014-3120", false, 6.8 },
        { "ES 1.2.0 (patched) -> NOT 3120",           "app-elasticsearch", "Elasticsearch 1.2.0", "CVE-2014-3120", true, 0 },
        { "ES 1.3.7 -> 1427 @ 7.5",                   "app-elasticsearch", "Elasticsearch 1.3.7", "CVE-2015-1427", false, 7.5 },
        { "ES 1.4.2 (1.4.x branch) -> 1427",          "app-elasticsearch", "Elasticsearch 1.4.2", "CVE-2015-1427", false, 7.5 },
        { "ES 1.4.3 (patched) -> NOT 1427",           "app-elasticsearch", "Elasticsearch 1.4.3", "CVE-2015-1427", true, 0 },
        { "ES 1.5.0 -> 5531 @ 5.0",                   "app-elasticsearch", "Elasticsearch 1.5.0", "CVE-2015-5531", false, 5.0 },
        { "ES 1.5.0 (>=1.4.3) -> NOT 1427",           "app-elasticsearch", "Elasticsearch 1.5.0", "CVE-2015-1427", true, 0 },
        { "ES 1.6.1 (patched) -> NOT 5531",           "app-elasticsearch", "Elasticsearch 1.6.1", "CVE-2015-5531", true, 0 },
        { "ES 2.4.0 (modern) -> NOT 5531",            "app-elasticsearch", "Elasticsearch 2.4.0", "CVE-2015-5531", true, 0 },

        // ---- Kibana (Timelion prototype-pollution RCE) ------------------
        { "Kibana 5.6.14 -> 7609 @ 10.0",             "app-kibana", "Kibana 5.6.14", "CVE-2019-7609", false, 10.0 },
        { "Kibana 5.6.15 (patched) -> NOT 7609",      "app-kibana", "Kibana 5.6.15", "CVE-2019-7609", true, 0 },
        { "Kibana 6.5.4 (6.x branch) -> 7609",        "app-kibana", "Kibana 6.5.4", "CVE-2019-7609", false, 10.0 },
        { "Kibana 6.6.1 (patched) -> NOT 7609",       "app-kibana", "Kibana 6.6.1", "CVE-2019-7609", true, 0 },
        { "Kibana 7.5.0 (modern) -> NOT 7609",        "app-kibana", "Kibana 7.5.0", "CVE-2019-7609", true, 0 },

        // ---- Apache Tomcat (Ghostcat, default-config AJP) ---------------
        { "Tomcat 9.0.30 -> 1938 @ 9.8",              "app-tomcat", "Apache Tomcat 9.0.30", "CVE-2020-1938", false, 9.8 },
        { "Tomcat 9.0.31 (patched) -> NOT 1938",      "app-tomcat", "Apache Tomcat 9.0.31", "CVE-2020-1938", true, 0 },
        { "Tomcat 8.5.50 -> 1938",                    "app-tomcat", "Apache Tomcat 8.5.50", "CVE-2020-1938", false, 9.8 },
        { "Tomcat 8.0.53 (8.0 line) -> 1938",         "app-tomcat", "Apache Tomcat 8.0.53", "CVE-2020-1938", false, 9.8 },
        { "Tomcat 8.5.51 (patched) -> NOT 1938",      "app-tomcat", "Apache Tomcat 8.5.51", "CVE-2020-1938", true, 0 },
        { "Tomcat 7.0.99 -> 1938",                    "app-tomcat", "Apache Tomcat 7.0.99", "CVE-2020-1938", false, 9.8 },
        { "Tomcat 7.0.100 (patched) -> NOT 1938",     "app-tomcat", "Apache Tomcat 7.0.100", "CVE-2020-1938", true, 0 },
        { "Tomcat 10.0.0 (modern) -> NOT 1938",       "app-tomcat", "Apache Tomcat 10.0.0", "CVE-2020-1938", true, 0 },

        // ---- Adminer (AdminerRead arbitrary file read) ------------------
        { "Adminer 4.6.2 -> 43008 @ 7.5",             "app-adminer", "Adminer 4.6.2", "CVE-2021-43008", false, 7.5 },
        { "Adminer 4.6.3 (patched) -> NOT 43008",     "app-adminer", "Adminer 4.6.3", "CVE-2021-43008", true, 0 },
        { "Adminer 4.2.0 -> 43008",                   "app-adminer", "Adminer 4.2.0", "CVE-2021-43008", false, 7.5 },
        { "Adminer 4.8.1 (modern) -> NOT 43008",      "app-adminer", "Adminer 4.8.1", "CVE-2021-43008", true, 0 },
        { "Adminer 1.11.0 (pre-range) -> NOT 43008",  "app-adminer", "Adminer 1.11.0", "CVE-2021-43008", true, 0 },

        // ---- Apache: the 41773/42013 pair + 38473 fix-version fix -------
        { "Apache 2.4.49 -> 41773",                   "server-apache", "Apache/2.4.49", "CVE-2021-41773", false, 0 },
        { "Apache 2.4.49 -> 42013",                   "server-apache", "Apache/2.4.49", "CVE-2021-42013", false, 9.8 },
        { "Apache 2.4.50 (41773 fixed) -> NOT 41773", "server-apache", "Apache/2.4.50", "CVE-2021-41773", true, 0 },
        { "Apache 2.4.50 -> still 42013",             "server-apache", "Apache/2.4.50", "CVE-2021-42013", false, 0 },
        { "Apache 2.4.59 -> 38473 (still vuln)",      "server-apache", "Apache/2.4.59", "CVE-2024-38473", false, 0 },
        { "Apache 2.4.60 (patched) -> NOT 38473",     "server-apache", "Apache/2.4.60", "CVE-2024-38473", true, 0 },

        // ---- nginx / jQuery / Bootstrap / PHP ---------------------------
        { "nginx 1.18.0 -> 23017",                    "server-nginx", "nginx/1.18.0", "CVE-2021-23017", false, 0 },
        { "nginx 1.20.1 (patched) -> NOT 23017",      "server-nginx", "nginx/1.20.1", "CVE-2021-23017", true, 0 },
        { "jQuery 3.3.1 -> 11358",                    "lib-jquery", "jQuery 3.3.1", "CVE-2019-11358", false, 0 },
        { "jQuery 3.5.1 (patched) -> NOT 11022",      "lib-jquery", "jQuery 3.5.1", "CVE-2020-11022", true, 0 },
        { "Bootstrap 4.2.0 -> 8331",                  "lib-bootstrap", "Bootstrap 4.2.0", "CVE-2019-8331", false, 0 },
        { "Bootstrap 4.3.1 (patched) -> NOT 8331",    "lib-bootstrap", "Bootstrap 4.3.1", "CVE-2019-8331", true, 0 },
        { "jQuery UI 1.12.1 -> 41182",                "lib-jquery-ui", "jQuery UI 1.12.1", "CVE-2021-41182", false, 0 },
        { "jQuery UI 1.13.0 (patched) -> NOT 41182",  "lib-jquery-ui", "jQuery UI 1.13.0", "CVE-2021-41182", true, 0 },
        { "jQuery UI 1.13.1 -> 31160",                "lib-jquery-ui", "jQuery UI 1.13.1", "CVE-2022-31160", false, 0 },
        { "jQuery UI 1.13.2 (patched) -> NOT 31160",  "lib-jquery-ui", "jQuery UI 1.13.2", "CVE-2022-31160", true, 0 },
        { "PHP 8.1.10 -> 4577",                       "lang-php", "PHP 8.1.10", "CVE-2024-4577", false, 0 },
        { "PHP 8.1.29 (patched) -> NOT 4577",         "lang-php", "PHP 8.1.29", "CVE-2024-4577", true, 0 },

        // ---- WordPress: mislabel + CVSS fix -----------------------------
        { "WordPress 6.4.1 -> 31210 @ 8.8 (was XSS/5.4)", "cms-wordpress", "WordPress 6.4.1", "CVE-2024-31210", false, 8.8 },
        { "WordPress 6.4.3 (patched) -> NOT 31210",   "cms-wordpress", "WordPress 6.4.3", "CVE-2024-31210", true, 0 },

        // ---- Spring4Shell re-key (spring-actuator -> fw-spring) ---------
        { "Spring 5.3.10 -> 22965 (re-keyed)",        "fw-spring", "Spring 5.3.10", "CVE-2022-22965", false, 9.8 },
        { "Spring 5.3.20 (patched) -> NOT 22965",     "fw-spring", "Spring 5.3.20", "CVE-2022-22965", true, 0 },
        { "Symfony 5.4.40 -> 50345 (open-redirect)",  "fw-symfony", "Symfony 5.4.40", "CVE-2024-50345", false, 6.1 },

        // ---- Magento CosmicSting: patch-level suffix bound (FN fix) ------
        // "<2.4.7-p1" must FLAG the exact vulnerable build 2.4.7 (the suffix is
        // the FIXED build) -- the old triple dropped "-p1" so 2.4.7 < 2.4.7 was
        // false and the 9.8 RCE was missed for its precise target.
        { "Magento 2.4.7 -> 34102 (suffix FN fix)",   "cms-magento", "Magento 2.4.7", "CVE-2024-34102", false, 9.8 },
        { "Magento 2.4.6 -> 34102 (older, vuln)",     "cms-magento", "Magento 2.4.6", "CVE-2024-34102", false, 9.8 },
        { "Magento 2.4.7-p1 (patched) -> NOT 34102",  "cms-magento", "Magento 2.4.7-p1", "CVE-2024-34102", true, 0 },
        { "Magento 2.4.8 (modern) -> NOT 34102",      "cms-magento", "Magento 2.4.8", "CVE-2024-34102", true, 0 },

        // ---- Removed bogus entries must stay gone -----------------------
        { "cms-drupal entries removed -> none",       "cms-drupal", "Drupal 10.1.0", "", false, 0 },
        { "SharePoint CVE-2024-30043 removed -> NOT on ASP.NET", "fw-aspnet", "ASP.NET 4.0.30319", "CVE-2024-30043", true, 0 },
    };
    return c;
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("Nullock");
    QCoreApplication::setApplicationName("cve-database-regression");

    int pass = 0, fail = 0;
    QStringList failures;

    for (const auto &t : corpus()) {
        const auto matches = CveDatabase::lookup(QString::fromLatin1(t.kind),
                                                 QString::fromLatin1(t.version));
        bool ok = false;
        QString detail;

        if (t.cveId[0] == '\0') {
            // Expect NO matches at all for this kind+version.
            ok = matches.isEmpty();
            detail = QString("got %1 matches").arg(matches.size());
        } else {
            double cvss = -1;
            const bool present = hasCve(matches, QString::fromLatin1(t.cveId), cvss);
            if (t.negative) {
                ok = !present;
                detail = present ? "unexpectedly present" : "absent (ok)";
            } else {
                ok = present;
                detail = present ? "present" : "MISSING";
                if (ok && t.expectCvss > 0.0 && std::fabs(cvss - t.expectCvss) > 0.05) {
                    ok = false;
                    detail = QString("present but CVSS %1 != expected %2")
                                 .arg(cvss).arg(t.expectCvss);
                }
            }
        }

        if (ok) {
            std::fprintf(stderr, "  PASS  %s\n", t.label);
            ++pass;
        } else {
            std::fprintf(stderr, "  FAIL  %s  (%s)\n", t.label, detail.toLocal8Bit().constData());
            ++fail;
            failures << QString::fromLatin1(t.label);
        }
    }

    // ---- precision flag, fingerprint fallback, and table integrity -----
    // (soundness fixes from the adversarial audit, beyond the corpus)
    auto chk = [&](const char *label, bool cond) {
        if (cond) { std::fprintf(stderr, "  PASS  %s\n", label); ++pass; }
        else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; failures << QString::fromLatin1(label); }
    };

    // A version-confirmed in-range match is precise.
    {
        double cv;
        const auto m = CveDatabase::lookup("cms-wordpress", "WordPress 6.4.1");
        chk("WP 6.4.1 -> 31210 is a PRECISE match", hasCve(m, "CVE-2024-31210", cv));
        bool prec = false;
        for (const auto &x : m) if (x.cveId == "CVE-2024-31210") prec = x.precise;
        chk("WP 6.4.1 -> 31210 precise flag is true", prec);
    }
    // An UNPARSEABLE version is surfaced but flagged IMPRECISE (not confirmed) --
    // this is what stops a versionless 'Express'/'Next.js' from reading critical.
    {
        const auto m = CveDatabase::lookup("cms-wordpress", "WordPress");   // no digits
        chk("unparseable version still surfaces entries", !m.isEmpty());
        bool allImprecise = !m.isEmpty();
        for (const auto &x : m) if (x.precise) allImprecise = false;
        chk("unparseable version -> every surfaced entry is imprecise", allImprecise);
    }
    // lookupByFingerprint: a PATCHED host (version parsed, matched nothing) must
    // return EMPTY, NOT the whole table (the headline false positive).
    {
        CveDatabase::HttpFingerprint fp;
        fp.bodyVersion = "WordPress 6.4.3";   // patched
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        chk("fingerprint: patched 6.4.3 -> NO full-table dump (empty)", m.isEmpty());
    }
    // lookupByFingerprint: a VULNERABLE host is still confirmed precisely.
    {
        CveDatabase::HttpFingerprint fp;
        fp.bodyVersion = "WordPress 6.4.1";
        double cv;
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        bool prec = false;
        for (const auto &x : m) if (x.cveId == "CVE-2024-31210") prec = x.precise;
        chk("fingerprint: vulnerable 6.4.1 -> 31210 confirmed precise",
            hasCve(m, "CVE-2024-31210", cv) && prec);
    }
    // lookupByFingerprint: a coarse early source must not shadow a precise one.
    // Coarse "6" -> {6,0,0} does NOT satisfy the 6.1.x branch bound ">=6.1.0";
    // only the precise "6.1.2" reaches CVE-2023-39999, so its presence proves the
    // precise source was selected over the coarse first one.
    {
        CveDatabase::HttpFingerprint fp;
        fp.bodyVersion = "WordPress 6";        // coarse, major-only (misses 6.1.x branch)
        fp.xGenerator  = "WordPress 6.1.2";    // precise -> in the 6.1.x branch CVE
        double cv;
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        chk("fingerprint: precise xGenerator 6.1.2 beats coarse '6' -> 39999",
            hasCve(m, "CVE-2023-39999", cv));
    }
    // audit-7: version PRECISION must outrank vendor-naming. A bare, kind-scoped
    // "6.4.3" (PATCHED, and NOT containing the vendor word) must beat a coarse
    // vendor-named "WordPress 6": ranking vendor-naming first let {6,0,0} shadow the
    // precise 6.4.3 and match a "<6.4.3" CVE, falsely flagging a patched host critical.
    {
        CveDatabase::HttpFingerprint fp;
        fp.bodyVersion = "6.4.3";            // bare, precise, PATCHED (no vendor word)
        fp.xGenerator  = "WordPress 6";      // vendor-named but coarse (major only)
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        chk("fingerprint: precise bare 6.4.3 beats coarse vendor-named 'WordPress 6' -> patched, empty",
            m.isEmpty());
    }
    // lookupByFingerprint: NO parseable version anywhere -> imprecise triage.
    {
        CveDatabase::HttpFingerprint fp;
        fp.server = "wordpress";   // names the vendor but carries no version
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        bool anyImprecise = !m.isEmpty();
        for (const auto &x : m) if (x.precise) anyImprecise = false;
        chk("fingerprint: no version -> manual-triage leads, all imprecise",
            !m.isEmpty() && anyImprecise);
    }
    // audit-6: a FOREIGN generic-infra-header version must NOT confirm a CVE -- a
    // PHP X-Powered-By / nginx Server version can't confirm a CMS/lib CVE. (The
    // selection loop tracked vendor-match but ignored it at the precise gate.)
    {
        CveDatabase::HttpFingerprint fp;
        fp.xGenerator = "WordPress";          // names the vendor but carries no version
        fp.xPoweredBy = "PHP/5.4.49";         // foreign generic header WITH a version
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        bool anyPrecise = false;
        for (const auto &x : m) if (x.precise) anyPrecise = true;
        chk("fingerprint: foreign X-Powered-By PHP version -> no precise CVE (FP fix)", !anyPrecise);
    }
    {
        CveDatabase::HttpFingerprint fp;
        fp.server = "nginx/1.18.0";           // foreign Server version, vendor not named
        const auto m = CveDatabase::lookupByFingerprint("lib-jquery", fp);
        bool anyPrecise = false;
        for (const auto &x : m) if (x.precise) anyPrecise = true;
        chk("fingerprint: foreign Server nginx version -> no precise jQuery CVE (FP fix)", !anyPrecise);
    }
    // ...and a bare, KIND-SCOPED bodyVersion still drives a precise lookup -- the
    // FP fix must not regress into a false negative.
    {
        CveDatabase::HttpFingerprint fp;
        fp.bodyVersion = "6.4.1";             // bare version, sniffed by a kind-specific pattern
        bool prec = false;
        const auto m = CveDatabase::lookupByFingerprint("cms-wordpress", fp);
        for (const auto &x : m) if (x.cveId == "CVE-2024-31210") prec = x.precise;
        chk("fingerprint: bare kind-scoped bodyVersion 6.4.1 -> still precise (no FN regression)", prec);
    }
    // parseVersion must pick the most-dotted run, not a digit inside the product
    // name: "Mag9 2.4.7" -> the version is 2.4.7 (in range), not "9" (out of range).
    {
        double cv;
        const auto m = CveDatabase::lookup("cms-magento", "Mag9 2.4.7");
        chk("digit in product name does not shadow the dotted version (Mag9 2.4.7 -> 34102)",
            hasCve(m, "CVE-2024-34102", cv));
    }
    // audit-7: an over-INT_MAX version component must clamp HIGH, not overflow to 0.
    // nginx/9999999999.20.0 is far NEWER than the 1.20.1 fix; with toInt() overflow
    // the major became 0 -> {0,20,0} < {1,20,1} -> falsely matched CVE-2021-23017.
    {
        double cv;
        const auto m = CveDatabase::lookup("server-nginx", "nginx/9999999999.20.0");
        chk("overflow version component clamps high -> newer host NOT matched to <1.20.1 CVE",
            !hasCve(m, "CVE-2021-23017", cv));
    }
    // Table integrity: no entry has a crossed/unsatisfiable range (dead row).
    chk("table has no crossed/dead >=X,<Y ranges", CveDatabase::auditRanges() == 0);

    // ---- runtime CVE overlay (cve_feed_sync) ---------------------------
    {
        CveDatabase::clearOverlay();
        chk("overlay: starts empty", CveDatabase::overlayCount() == 0);
        QList<CveDatabase::OverlayCve> ov;
        ov.append({ "cms-joomla", "CVE-2099-0001", 9.1, "CVSS:3.1/AV:N/AC:L/...",
                    ">=4.0.0,<4.2.8", "4.2.8", "feed-synced Joomla RCE", "https://example/CVE-2099-0001" });
        chk("overlay: setOverlay returns the stored count", CveDatabase::setOverlay(ov) == 1);
        chk("overlay: overlayCount reflects it", CveDatabase::overlayCount() == 1);

        double cv;
        const auto inRange = CveDatabase::lookup("cms-joomla", "Joomla 4.1.0");
        chk("overlay: a version IN range matches (precise)",
            hasCve(inRange, "CVE-2099-0001", cv) && cv > 9.0);
        bool prec = true;
        for (const auto &m : inRange) if (m.cveId == "CVE-2099-0001") prec = m.precise;
        chk("overlay: in-range overlay match is precise", prec);

        chk("overlay: a PATCHED version (>= fix) does NOT match",
            !hasCve(CveDatabase::lookup("cms-joomla", "Joomla 4.2.8"), "CVE-2099-0001", cv));
        chk("overlay: a different kind does NOT match",
            CveDatabase::lookup("cms-wordpress", "WordPress 4.1.0").isEmpty()
            || !hasCve(CveDatabase::lookup("cms-wordpress", "WordPress 4.1.0"), "CVE-2099-0001", cv));
        chk("overlay: an unparseable version surfaces the entry as IMPRECISE",
            [&]{ const auto m = CveDatabase::lookup("cms-joomla", "Joomla");
                 for (const auto &x : m) if (x.cveId == "CVE-2099-0001") return !x.precise;
                 return false; }());

        // Dedup: an overlay row re-publishing a static CVE id must not double it
        // (the static table wins).
        QList<CveDatabase::OverlayCve> dup;
        dup.append({ "cms-wordpress", "CVE-2024-31210", 1.0, "", ">=0,<99", "99",
                     "overlay dup", "https://x" });
        CveDatabase::setOverlay(dup);
        const auto m = CveDatabase::lookup("cms-wordpress", "WordPress 6.4.1");
        int n = 0; for (const auto &x : m) if (x.cveId == "CVE-2024-31210") ++n;
        chk("overlay: a dup of a static CVE id is not double-counted (static wins)", n == 1);

        CveDatabase::clearOverlay();
        chk("overlay: clearOverlay empties it", CveDatabase::overlayCount() == 0);
        chk("overlay: after clear, the overlay CVE no longer matches",
            !hasCve(CveDatabase::lookup("cms-joomla", "Joomla 4.1.0"), "CVE-2099-0001", cv));
    }

    std::fprintf(stderr,
        "\n========================================\n"
        "CVE database regression: %d passed, %d failed\n"
        "========================================\n",
        pass, fail);
    if (fail > 0) {
        std::fprintf(stderr, "Failures:\n");
        for (const QString &f : failures)
            std::fprintf(stderr, "  - %s\n", f.toLocal8Bit().constData());
    }
    return fail == 0 ? 0 : 1;
}

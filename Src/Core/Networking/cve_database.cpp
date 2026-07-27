#include "cve_database.hpp"

#include <QHash>
#include <QMutex>
#include <QRegularExpression>
#include <QSet>

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
          "WordPress < 6.4.3: unrestricted upload of file with dangerous type (plugin/theme upload) -> RCE",
          8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          ">=4.1.0,<6.4.3", "6.4.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-31210" },
        // CVE-2023-39999: contributor-only information disclosure (read comments
        // on private/password-protected posts), NOT XSS. Per-branch fixes.
        { "cms-wordpress", "CVE-2023-39999",
          "WordPress 6.3.x < 6.3.2: information disclosure -- contributors can read comments on private/password-protected posts",
          4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
          ">=6.3.0,<6.3.2", "6.3.2",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-39999" },
        { "cms-wordpress", "CVE-2023-39999",
          "WordPress 6.2.x < 6.2.3: information disclosure -- contributors can read comments on private/password-protected posts",
          4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
          ">=6.2.0,<6.2.3", "6.2.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-39999" },
        { "cms-wordpress", "CVE-2023-39999",
          "WordPress 6.1.x < 6.1.4: information disclosure -- contributors can read comments on private/password-protected posts",
          4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
          ">=6.1.0,<6.1.4", "6.1.4",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-39999" },
        { "cms-wordpress", "CVE-2023-39999",
          "WordPress 6.0.x < 6.0.6: information disclosure -- contributors can read comments on private/password-protected posts",
          4.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
          ">=6.0.0,<6.0.6", "6.0.6",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-39999" },

        // ---- Drupal core ---------------------------------------------
        // (No version-keyed Drupal CVEs: Drupal exposes only its MAJOR version
        // in the generator string, so patch-level ranges would false-positive
        // every install. The prior two entries also had MISASSIGNED CVE IDs --
        // CVE-2025-32467 is an Intel TDX CVE and CVE-2023-3824 is a PHP CVE.)

        // ---- Magento -------------------------------------------------
        { "cms-magento", "CVE-2024-34102",
          "Adobe Commerce / Magento Open Source CosmicSting: XXE via REST API to RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<2.4.7-p1", "2.4.7-p1",
          "https://helpx.adobe.com/security/products/magento/apsb24-40.html" },

        // ---- Atlassian Confluence -----------------------------------
        { "cms-confluence", "CVE-2023-22515",
          "Confluence Data Center/Server 8.0-8.3.2: broken access control -> unauthorized admin account creation (0-day, Sept 2023)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.0.0,<8.3.3", "8.3.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-22515" },
        { "cms-confluence", "CVE-2023-22515",
          "Confluence Data Center/Server 8.4.0-8.4.2: broken access control -> unauthorized admin account creation (0-day, Sept 2023)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.4.0,<8.4.3", "8.4.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-22515" },
        { "cms-confluence", "CVE-2023-22515",
          "Confluence Data Center/Server 8.5.0-8.5.1: broken access control -> unauthorized admin account creation (0-day, Sept 2023)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.5.0,<8.5.2", "8.5.2",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-22515" },
        // CVE-2023-22527: OGNL template injection -> unauthenticated RCE
        // (10.0, mass-exploited early 2024). Affected 8.0.0-8.5.3, fixed 8.5.4
        // (and all 8.6+); a single clean range -- no per-branch backports.
        { "cms-confluence", "CVE-2023-22527",
          "Confluence Data Center/Server: OGNL template injection -> unauthenticated remote code execution",
          10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          ">=8.0.0,<8.5.4", "8.5.4",
          "https://confluence.atlassian.com/security/cve-2023-22527-1333990257.html" },
        // CVE-2023-22518 affected ALL Confluence DC/Server before the
        // per-branch fixes (7.19.16, 8.3.4, 8.4.4, 8.5.3, 8.6.1) -- the lone
        // <7.19.16 range missed the entire 8.x line (the common DC line in
        // late 2023). Modeled as mutually-exclusive branch ranges (same shape
        // as CVE-2022-0540) so patched 8.x builds aren't false-positived.
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<7.19.16", "7.19.16",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.0.0,<8.3.4", "8.3.4",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.4.0,<8.4.4", "8.4.4",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.5.0,<8.5.3", "8.5.3",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.6.0,<8.6.1", "8.6.1",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },

        // CVE-2022-26134: OGNL injection -> unauthenticated RCE, exploited as a
        // 0-day (June 2022). Per the Atlassian advisory / NVD, affected by
        // maintenance branch: <7.4.17, 7.13.x<7.13.7, 7.14.x<7.14.3,
        // 7.15.x<7.15.2, 7.16.x<7.16.4, 7.17.x<7.17.4, 7.18.x<7.18.1. (8.x
        // postdates the fix and is unaffected.) Web-verified pins.
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<7.4.17", "7.4.17",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.13.0,<7.13.7", "7.13.7",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.14.0,<7.14.3", "7.14.3",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.15.0,<7.15.2", "7.15.2",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.16.0,<7.16.4", "7.16.4",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.17.0,<7.17.4", "7.17.4",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },
        { "cms-confluence", "CVE-2022-26134",
          "Confluence Data Center/Server: OGNL injection -> unauthenticated remote code execution (0-day, June 2022)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.18.0,<7.18.1", "7.18.1",
          "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html" },

        // ---- Atlassian Jira -----------------------------------------
        // NB: CVE-2024-1597 (bundled pgjdbc <42.7.2) was removed -- it is a
        // dependency CVE not keyed to Jira's own version, and its "<42.7.2"
        // text matches every real Jira version, so it false-positives once
        // Jira version fingerprinting is enabled. Replaced with CVEs whose
        // affected range IS Jira's own version. CVE-2022-0540 spans three
        // mutually-exclusive maintenance branches (same pattern as PHP
        // CVE-2024-4577) so a patched build on any branch isn't flagged.
        { "cms-jira", "CVE-2022-0540",
          "Jira / Jira Service Management: authentication bypass in Seraph -- affected web actions reachable unauthenticated",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<8.13.18", "8.13.18",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2022-04-20-1115127899.html" },
        { "cms-jira", "CVE-2022-0540",
          "Jira / Jira Service Management: authentication bypass in Seraph -- affected web actions reachable unauthenticated",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.14.0,<8.20.6", "8.20.6",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2022-04-20-1115127899.html" },
        { "cms-jira", "CVE-2022-0540",
          "Jira / Jira Service Management: authentication bypass in Seraph -- affected web actions reachable unauthenticated",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.21.0,<8.22.0", "8.22.0",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2022-04-20-1115127899.html" },
        { "cms-jira", "CVE-2019-8449",
          "Jira < 8.4.0: user/group enumeration via /rest/api/latest/groupuserpicker (information disclosure)",
          5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "<8.4.0", "8.4.0",
          "https://jira.atlassian.com/browse/JRASERVER-69242" },
        // CVE-2019-11581: server-side template injection in ContactAdministrators
        // / SendBulkMail -> RCE (unauthenticated when the Contact Administrators
        // form is enabled). Web-verified per-branch ranges (fixes 7.6.14 /
        // 7.13.5 / 8.0.3 / 8.1.2 / 8.2.3).
        { "cms-jira", "CVE-2019-11581",
          "Jira 4.4-7.6.x < 7.6.14: server-side template injection -> RCE (unauth via Contact Administrators form)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=4.4.0,<7.6.14", "7.6.14",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2019-07-10-973486595.html" },
        { "cms-jira", "CVE-2019-11581",
          "Jira 7.7-7.13.x < 7.13.5: server-side template injection -> RCE (unauth via Contact Administrators form)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.7.0,<7.13.5", "7.13.5",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2019-07-10-973486595.html" },
        { "cms-jira", "CVE-2019-11581",
          "Jira 8.0.x < 8.0.3: server-side template injection -> RCE (unauth via Contact Administrators form)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.0.0,<8.0.3", "8.0.3",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2019-07-10-973486595.html" },
        { "cms-jira", "CVE-2019-11581",
          "Jira 8.1.x < 8.1.2: server-side template injection -> RCE (unauth via Contact Administrators form)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.1.0,<8.1.2", "8.1.2",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2019-07-10-973486595.html" },
        { "cms-jira", "CVE-2019-11581",
          "Jira 8.2.x < 8.2.3: server-side template injection -> RCE (unauth via Contact Administrators form)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.2.0,<8.2.3", "8.2.3",
          "https://confluence.atlassian.com/jira/jira-security-advisory-2019-07-10-973486595.html" },

        // ---- Jenkins (X-Jenkins header version) ---------------------
        // CVE-2024-23897: unauthenticated arbitrary file read via the CLI
        // args4j '@' expansion (readable->RCE; mass-exploited Jan 2024). Fixed
        // in weekly 2.442 and LTS 2.426.3. Two fix points => three
        // mutually-exclusive branches so a patched 2.426.3 / 2.442 isn't FP'd
        // (the LTS 2.426 line is 3-part, weeklies 2-part -- both compare under
        // the dotted-triple matcher).
        { "app-jenkins", "CVE-2024-23897",
          "Jenkins < 2.442 (weekly): unauthenticated arbitrary file read via CLI args4j '@' expansion (-> RCE)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<2.426", "2.426.3 / 2.442",
          "https://www.jenkins.io/security/advisory/2024-01-24/" },
        { "app-jenkins", "CVE-2024-23897",
          "Jenkins LTS 2.426.x < 2.426.3: unauthenticated arbitrary file read via CLI args4j '@' expansion (-> RCE)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=2.426,<2.426.3", "2.426.3",
          "https://www.jenkins.io/security/advisory/2024-01-24/" },
        { "app-jenkins", "CVE-2024-23897",
          "Jenkins weekly 2.427-2.441 < 2.442: unauthenticated arbitrary file read via CLI args4j '@' expansion (-> RCE)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=2.427,<2.442", "2.442",
          "https://www.jenkins.io/security/advisory/2024-01-24/" },

        // ---- Grafana (grafanaBootData buildInfo version) ------------
        // CVE-2021-43798: unauthenticated directory traversal -> arbitrary file
        // read via /public/plugins/<id>/../../  -- affected 8.0.0-8.3.0, fixed
        // 8.3.1 with backports 8.0.7 / 8.1.8 / 8.2.7. Branch-modeled so a
        // patched build on any line isn't false-positived; 7.x and >=8.3.1 are
        // unaffected (no range matches them).
        { "app-grafana", "CVE-2021-43798",
          "Grafana 8.0.x < 8.0.7: unauthenticated path traversal -> arbitrary file read via plugin assets",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=8.0.0,<8.0.7", "8.0.7",
          "https://grafana.com/security/security-advisories/cve-2021-43798/" },
        { "app-grafana", "CVE-2021-43798",
          "Grafana 8.1.x < 8.1.8: unauthenticated path traversal -> arbitrary file read via plugin assets",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=8.1.0,<8.1.8", "8.1.8",
          "https://grafana.com/security/security-advisories/cve-2021-43798/" },
        { "app-grafana", "CVE-2021-43798",
          "Grafana 8.2.x < 8.2.7: unauthenticated path traversal -> arbitrary file read via plugin assets",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=8.2.0,<8.2.7", "8.2.7",
          "https://grafana.com/security/security-advisories/cve-2021-43798/" },
        { "app-grafana", "CVE-2021-43798",
          "Grafana 8.3.0 < 8.3.1: unauthenticated path traversal -> arbitrary file read via plugin assets",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=8.3.0,<8.3.1", "8.3.1",
          "https://grafana.com/security/security-advisories/cve-2021-43798/" },

        // ---- Elasticsearch (version from GET / JSON banner number) ---
        // All three are 1.x-era flaws (only fire on ancient, internet-exposed
        // clusters), but they're version-keyed and web-verified, and an
        // exposed Elasticsearch is itself worth surfacing. Scores are the NVD
        // CVSS v2 base values (these predate v3) kept verbatim. Patched 1.x
        // and every 2.x+ build fall outside the ranges -> no false positives.
        { "app-elasticsearch", "CVE-2014-3120",
          "Elasticsearch < 1.2.0: remote code execution via the dynamic-scripting 'source' parameter of /_search (default config)",
          6.8, "CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:P",
          "<1.2.0", "1.2.0",
          "https://nvd.nist.gov/vuln/detail/CVE-2014-3120" },
        { "app-elasticsearch", "CVE-2015-1427",
          "Elasticsearch < 1.3.8: Groovy scripting-engine sandbox bypass -> arbitrary shell command execution",
          7.5, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
          "<1.3.8", "1.3.8 / 1.4.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-1427" },
        { "app-elasticsearch", "CVE-2015-1427",
          "Elasticsearch 1.4.x < 1.4.3: Groovy scripting-engine sandbox bypass -> arbitrary shell command execution",
          7.5, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
          ">=1.4.0,<1.4.3", "1.4.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-1427" },
        { "app-elasticsearch", "CVE-2015-5531",
          "Elasticsearch 1.0.0-1.6.0: directory traversal -> read files readable by the Elasticsearch JVM via the snapshot API",
          5.0, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N",
          ">=1.0.0,<1.6.1", "1.6.1 / 1.7.0",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-5531" },

        // ---- Kibana (kbn-name header; version from /api/status banner) --
        // CVE-2019-7609: Timelion prototype-pollution -> arbitrary code
        // execution, unauthenticated against a default-open Kibana. NVD-
        // verified: before 5.6.15, and the 6.0.0-6.6.0 line fixed in 6.6.1.
        // Branch-modeled so a patched 5.6.15/6.6.1 and all 7.x are clean.
        { "app-kibana", "CVE-2019-7609",
          "Kibana < 5.6.15: Timelion prototype-pollution -> arbitrary code execution (RCE)",
          10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          "<5.6.15", "5.6.15",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-7609" },
        { "app-kibana", "CVE-2019-7609",
          "Kibana 6.0.0-6.6.0 < 6.6.1: Timelion prototype-pollution -> arbitrary code execution (RCE)",
          10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          ">=6.0.0,<6.6.1", "6.6.1",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-7609" },

        // ---- Apache Tomcat (version from default/error page banner) -----
        // CVE-2020-1938 (Ghostcat): the AJP connector -- enabled by DEFAULT in
        // 6/7/8/9 -- allows reading/including arbitrary webapp files, escalating
        // to RCE when an upload dir is reachable. Web-verified fix points
        // 7.0.100 / 8.5.51 / 9.0.31; branch-modeled (the 8.0.x line has no
        // separate fix, so upgrade target is 8.5.51). NOTE: Tomcat's other RCEs
        // (CVE-2017-12617 PUT-JSP, CVE-2020-9484 FileStore deser, CVE-2019-0232
        // CGI) are config-gated rather than default-config, so they are
        // deliberately NOT version-correlated here -- doing so would false-
        // positive on the common default install.
        { "app-tomcat", "CVE-2020-1938",
          "Apache Tomcat 7.0.x < 7.0.100 (Ghostcat): AJP connector arbitrary file read/include -> RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=7.0.0,<7.0.100", "7.0.100",
          "https://tomcat.apache.org/security-7.html" },
        { "app-tomcat", "CVE-2020-1938",
          "Apache Tomcat 8.x < 8.5.51 (Ghostcat): AJP connector arbitrary file read/include -> RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.0.0,<8.5.51", "8.5.51",
          "https://tomcat.apache.org/security-8.html" },
        { "app-tomcat", "CVE-2020-1938",
          "Apache Tomcat 9.0.x < 9.0.31 (Ghostcat): AJP connector arbitrary file read/include -> RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=9.0.0,<9.0.31", "9.0.31",
          "https://tomcat.apache.org/security-9.html" },

        // ---- Adminer (footer "Adminer X.Y.Z" + adminer.org link) -------
        // CVE-2021-43008 (AdminerRead): an attacker who can make Adminer connect
        // to a MySQL server they control reads arbitrary files on the Adminer
        // host. NVD-verified: 1.12.0-4.6.2, fixed 4.6.3. Adminer is a single PHP
        // file often dropped on a server and forgotten, so exposure is common.
        { "app-adminer", "CVE-2021-43008",
          "Adminer 1.12.0-4.6.2: arbitrary file read via a malicious MySQL server (AdminerRead)",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=1.12.0,<4.6.3", "4.6.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-43008" },

        // ---- jQuery (version from script-src filename) --------------
        // jQuery's full version is reliably exposed in the asset path
        // (jquery-X.Y.Z.min.js), so these correlate cleanly. All three are
        // single clean ranges fixed in a known release.
        { "lib-jquery", "CVE-2019-11358",
          "jQuery < 3.4.0: prototype pollution via jQuery.extend(true, {}, ...)",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<3.4.0", "3.4.0",
          "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/" },
        { "lib-jquery", "CVE-2020-11022",
          "jQuery >=1.2 <3.5.0: XSS -- untrusted HTML passed to .html()/.append() etc. can execute",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=1.2.0,<3.5.0", "3.5.0",
          "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/" },
        { "lib-jquery", "CVE-2020-11023",
          "jQuery >=1.0.3 <3.5.0: XSS -- HTML containing <option> elements passed to DOM methods can execute",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=1.0.3,<3.5.0", "3.5.0",
          "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/" },

        // ---- Bootstrap (version from asset filename) ----------------
        // CVE-2019-8331: XSS in tooltip/popover data-template -- the canonical
        // outdated-Bootstrap finding. Fixed in 3.4.1 (3.x line) and 4.3.1 (4.x
        // line); two clean branches so a patched build on either line and 5.x
        // aren't false-positived.
        { "lib-bootstrap", "CVE-2019-8331",
          "Bootstrap < 3.4.1: XSS in tooltip/popover via the data-template attribute",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<3.4.1", "3.4.1",
          "https://github.com/twbs/bootstrap/releases/tag/v3.4.1" },
        { "lib-bootstrap", "CVE-2019-8331",
          "Bootstrap 4.x < 4.3.1: XSS in tooltip/popover via the data-template attribute",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=4.0.0,<4.3.1", "4.3.1",
          "https://github.com/twbs/bootstrap/releases/tag/v4.3.1" },

        // ---- jQuery UI (version from the jquery-ui-X.Y.Z asset path) -
        // The three 2021 XSS CVEs are one clean range fixed in 1.13.0:
        // 41182 (datepicker altField), 41183 (datepicker text options),
        // 41184 (.position() `of`). A later checkboxradio XSS (CVE-2022-31160)
        // is a separate range fixed in 1.13.2.
        { "lib-jquery-ui", "CVE-2021-41182",
          "jQuery UI < 1.13.0: XSS via the datepicker altField / text options and the .position() 'of' option",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<1.13.0", "1.13.0",
          "https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc" },
        { "lib-jquery-ui", "CVE-2022-31160",
          "jQuery UI >=1.13.0 <1.13.2: XSS in the checkboxradio widget via a non-string label",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=1.13.0,<1.13.2", "1.13.2",
          "https://github.com/jquery/jquery-ui/security/advisories/GHSA-h6gj-6jjq-h8g9" },

        // ---- Sitecore -----------------------------------------------
        { "cms-sitecore", "CVE-2025-27218",
          "Sitecore XP/XM: insecure deserialization in ItemService leading to unauthenticated RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=10.0,<10.4.1", "10.4.1",
          "https://kb.sitecore.com/articles/KB1002844" },

        // ---- Spring Framework / Boot --------------------------------
        { "fw-spring", "CVE-2024-22243",
          "Spring Framework 5.3.x < 5.3.32: open redirect / SSRF via UriComponentsBuilder",
          8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
          ">=5.3.0,<5.3.32", "5.3.32",
          "https://spring.io/security/cve-2024-22243" },
        { "fw-spring", "CVE-2024-22243",
          "Spring Framework 6.0.x < 6.0.17: open redirect / SSRF via UriComponentsBuilder",
          8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
          ">=6.0.0,<6.0.17", "6.0.17",
          "https://spring.io/security/cve-2024-22243" },
        { "fw-spring", "CVE-2024-22243",
          "Spring Framework 6.1.x < 6.1.4: open redirect / SSRF via UriComponentsBuilder",
          8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
          ">=6.1.0,<6.1.4", "6.1.4",
          "https://spring.io/security/cve-2024-22243" },
        // Spring4Shell -- re-keyed from the bogus "spring-actuator" kind to
        // fw-spring; modeled per-branch (5.2.x and 5.3.x) so patched builds
        // aren't flagged.
        { "fw-spring", "CVE-2022-22965",
          "Spring4Shell (Spring 5.2.x < 5.2.20): RCE via data binding to class.module.classLoader",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=5.2.0,<5.2.20", "5.2.20",
          "https://spring.io/security/cve-2022-22965" },
        { "fw-spring", "CVE-2022-22965",
          "Spring4Shell (Spring 5.3.x < 5.3.18): RCE via data binding to class.module.classLoader",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=5.3.0,<5.3.18", "5.3.18",
          "https://spring.io/security/cve-2022-22965" },

        // ---- ASP.NET ------------------------------------------------
        // (CVE-2024-30043 removed: a SharePoint CVE mis-filed under fw-aspnet
        // with a non-numeric "various" range that matched EVERY ASP.NET app --
        // an active false positive. SharePoint isn't fingerprinted, so there's
        // no correct home for it here yet.)

        // ---- Express / Node -----------------------------------------
        { "fw-express", "CVE-2024-29041",
          "Express < 4.19.2: open redirect in malformed URL path",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<4.19.2", "4.19.2",
          "https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc" },

        // ---- Next.js ------------------------------------------------
        { "fw-nextjs", "CVE-2025-29927",
          "Next.js 11.1.4-12.3.x < 12.3.5: middleware authorization bypass via x-middleware-subrequest header",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          ">=11.1.4,<12.3.5", "12.3.5",
          "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" },
        { "fw-nextjs", "CVE-2025-29927",
          "Next.js 13.x < 13.5.9: middleware authorization bypass via x-middleware-subrequest header",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          ">=13.0.0,<13.5.9", "13.5.9",
          "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" },
        { "fw-nextjs", "CVE-2025-29927",
          "Next.js 14.x < 14.2.25: middleware authorization bypass via x-middleware-subrequest header",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          ">=14.0.0,<14.2.25", "14.2.25",
          "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" },
        { "fw-nextjs", "CVE-2025-29927",
          "Next.js 15.x < 15.2.3: middleware authorization bypass via x-middleware-subrequest header",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          ">=15.0.0,<15.2.3", "15.2.3",
          "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" },

        // ---- Laravel ------------------------------------------------
        // CVE-2024-52301: per-branch fixes across all maintained Laravel lines.
        { "fw-laravel", "CVE-2024-52301",
          "Laravel < 6.20.45: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "<6.20.45", "6.20.45",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },
        { "fw-laravel", "CVE-2024-52301",
          "Laravel 7.x < 7.30.7: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=7.0.0,<7.30.7", "7.30.7",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },
        { "fw-laravel", "CVE-2024-52301",
          "Laravel 8.x < 8.83.28: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=8.0.0,<8.83.28", "8.83.28",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },
        { "fw-laravel", "CVE-2024-52301",
          "Laravel 9.x < 9.52.17: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=9.0.0,<9.52.17", "9.52.17",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },
        { "fw-laravel", "CVE-2024-52301",
          "Laravel 10.x < 10.48.23: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=10.0.0,<10.48.23", "10.48.23",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },
        { "fw-laravel", "CVE-2024-52301",
          "Laravel 11.x < 11.31.0: HTTP request can alter the application environment via register_argc_argv",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=11.0.0,<11.31.0", "11.31.0",
          "https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h" },

        // ---- Django -------------------------------------------------
        { "fw-django", "CVE-2024-39614",
          "Django >= 4.2 < 4.2.14: potential DoS in get_supported_language_variant()",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          ">=4.2,<4.2.14", "4.2.14",
          "https://www.djangoproject.com/weblog/2024/jul/09/security-releases/" },

        // ---- Symfony ------------------------------------------------
        // CVE-2024-50345 is an OPEN REDIRECT (the prior summary mislabeled it
        // as remember-me account takeover -- that is a different CVE). Per-branch.
        { "fw-symfony", "CVE-2024-50345",
          "Symfony < 5.4.46: open redirect via Request URI parsing of browser-sanitized URLs",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          "<5.4.46", "5.4.46",
          "https://symfony.com/blog/cve-2024-50345-open-redirect-via-browser-sanitized-urls" },
        { "fw-symfony", "CVE-2024-50345",
          "Symfony 6.4.x < 6.4.14: open redirect via Request URI parsing of browser-sanitized URLs",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=6.4.0,<6.4.14", "6.4.14",
          "https://symfony.com/blog/cve-2024-50345-open-redirect-via-browser-sanitized-urls" },
        { "fw-symfony", "CVE-2024-50345",
          "Symfony 7.1.x < 7.1.7: open redirect via Request URI parsing of browser-sanitized URLs",
          6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
          ">=7.1.0,<7.1.7", "7.1.7",
          "https://symfony.com/blog/cve-2024-50345-open-redirect-via-browser-sanitized-urls" },

        // ---- Joomla --------------------------------------------------
        { "cms-joomla", "CVE-2023-23752",
          "Joomla! 4.0.0-4.2.7: improper access check on webservice endpoints -- unauthenticated disclosure of config incl. DB credentials",
          5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          ">=4.0.0,<4.2.8", "4.2.8",
          "https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html" },
        { "cms-joomla", "CVE-2015-8562",
          "Joomla! 1.5-3.4.5: PHP object injection via crafted User-Agent / X-Forwarded-For -> unauthenticated RCE",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<3.4.6", "3.4.6",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-8562" },

        // ---- PHP (language runtime) ---------------------------------
        // CVE-2024-4577 is multi-branch -- one mutually-exclusive range per
        // maintained branch so a given version matches exactly one (no FP on
        // a patched older-branch build). Config-dependent (PHP-CGI on Windows).
        { "lang-php", "CVE-2024-4577",
          "PHP-CGI argument injection -> unauthenticated RCE (Windows / certain locales+configs); 8.3.x before 8.3.8",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.3.0,<8.3.8", "8.3.8",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-4577" },
        { "lang-php", "CVE-2024-4577",
          "PHP-CGI argument injection -> unauthenticated RCE (Windows / certain locales+configs); 8.2.x before 8.2.20",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.2.0,<8.2.20", "8.2.20",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-4577" },
        { "lang-php", "CVE-2024-4577",
          "PHP-CGI argument injection -> unauthenticated RCE (Windows / certain locales+configs); 8.1.x before 8.1.29",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=8.1.0,<8.1.29", "8.1.29",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-4577" },

        // ---- Web servers (Server: header) ---------------------------
        // Keyed to the kinds http_fingerprint actually emits (server-apache /
        // server-nginx) with clean version pins, so a fingerprinted Server
        // version correlates. (These were previously filed under a synthetic
        // "server-version" kind that nothing looks up -- i.e. dead entries.)
        { "server-apache", "CVE-2024-38473",
          "Apache httpd 2.4.0-2.4.59: mod_proxy encoding flaw -> SSRF / auth bypass (fixed 2.4.60)",
          8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
          ">=2.4.0,<2.4.60", "2.4.60",
          "https://httpd.apache.org/security/vulnerabilities_24.html" },
        { "server-apache", "CVE-2023-44487",
          "HTTP/2 Rapid Reset DoS via RST_STREAM flood (Apache added mitigations in 2.4.58)",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "<2.4.58", "2.4.58",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-44487" },
        // Oct-2021 path-traversal pair (mass-exploited). 41773 affects 2.4.49
        // ONLY (fixed 2.4.50); 42013 -- the incomplete-fix follow-up -- affects
        // 2.4.49 AND 2.4.50 (fixed 2.4.51). Modeled as half-open ranges, not a
        // bare "2.4.49" exact (rangeMatches only honors </> bounds; a bare
        // version has no bound and would match every version).
        { "server-apache", "CVE-2021-41773",
          "Apache httpd 2.4.49: path traversal -> file disclosure / RCE (when mod_cgi enabled on aliased paths)",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          ">=2.4.49,<2.4.50", "2.4.50",
          "https://httpd.apache.org/security/vulnerabilities_24.html" },
        { "server-apache", "CVE-2021-42013",
          "Apache httpd 2.4.49-2.4.50: path traversal -> unauthenticated RCE (incomplete fix for CVE-2021-41773)",
          9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          ">=2.4.49,<2.4.51", "2.4.51",
          "https://httpd.apache.org/security/vulnerabilities_24.html" },
        { "server-nginx", "CVE-2023-44487",
          "HTTP/2 Rapid Reset DoS via RST_STREAM flood (nginx added mitigations in 1.25.3)",
          7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "<1.25.3", "1.25.3",
          "https://nvd.nist.gov/vuln/detail/CVE-2023-44487" },
        { "server-nginx", "CVE-2021-23017",
          "nginx resolver off-by-one heap write (0.6.18-1.20.0) -> worker crash / potential RCE",
          7.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H",
          "<1.20.1", "1.20.1",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" },
    };
    return t;
}

// Parse "Drupal 10.2.5" / "WordPress 6.1.2" / "Apache/2.4.41" /
// "nginx/1.24.0 (Ubuntu)" / "Magento 2.4.7-p1" etc. into up to four dotted
// numeric components PLUS a patch-level/pre-release suffix RANK, so a vendor
// patch build sorts ABOVE its base release ("2.4.7" < "2.4.7-p1") and a
// pre-release sorts BELOW it ("1.2.3rc1" < "1.2.3"). The old dotted-triple
// dropped the suffix at the '-', collapsing "2.4.7-p1" to "2.4.7" and missing
// the exact vulnerable build a "<X-pN" bound targets.

// Rank a trailing suffix: patch-level (-pN/patchN/plN) -> well above release;
// pre-release (rc/beta/alpha/dev/...) -> below release; release/unknown -> 0.
int suffixRank(const QString &sufIn) {
    QString t = sufIn.toLower();
    while (!t.isEmpty() && (t.front() == '-' || t.front() == '_' || t.front() == '.' || t.front() == ' '))
        t.remove(0, 1);
    if (t.isEmpty()) return 0;
    static const QRegularExpression patch(R"(^(?:p|patch|pl)(\d+))");
    if (auto mp = patch.match(t); mp.hasMatch()) return 1000 + mp.captured(1).toInt();
    static const QRegularExpression pre(R"(^(rc|beta|alpha|dev|snapshot|preview|pre)(\d*))");
    if (auto mr = pre.match(t); mr.hasMatch())
        return -1000 + (mr.captured(2).isEmpty() ? 0 : mr.captured(2).toInt());
    return 0;   // unknown trailing text -> treat as a plain release
}

struct Ver { int p[4] = { 0, 0, 0, 0 }; int ncomp = 0; int suffix = 0; bool valid = false; };
Ver parseVersion(const QString &s) {
    static const QRegularExpression rx(
        R"((\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?([A-Za-z0-9._\-]*))");
    // Pick the MOST-dotted digit run, not the first: a product name that itself
    // carries a digit ("log4j 2.14.1", "ASP.NET 4.x") must not let the bare "4"
    // shadow the real dotted version.
    auto it = rx.globalMatch(s);
    Ver best;
    while (it.hasNext()) {
        auto m = it.next();
        Ver v;
        v.p[0] = m.captured(1).toInt();
        v.ncomp = 1;
        for (int i = 2; i <= 4; ++i) {
            const QString c = m.captured(i);
            if (c.isEmpty()) break;
            v.p[i - 1] = c.toInt();
            v.ncomp = i;
        }
        v.suffix = suffixRank(m.captured(5));
        v.valid = true;
        if (!best.valid || v.ncomp > best.ncomp) best = v;   // most components wins (ties -> first)
    }
    return best;   // valid=false if no digit run at all
}

int cmpVer(const Ver &x, const Ver &y) {
    for (int i = 0; i < 4; ++i)
        if (x.p[i] != y.p[i]) return x.p[i] < y.p[i] ? -1 : 1;
    if (x.suffix != y.suffix) return x.suffix < y.suffix ? -1 : 1;
    return 0;
}

// "<10.3.13" / ">=4.2,<4.2.14" / "<2.4.7-p1" / "2.4.49" (exact) / arbitrary text.
// Sets `precise`: true for a version-confirmed in-range/exact match; false when
// the version or the range couldn't be parsed and the entry was SURFACED anyway.
bool rangeMatches(const QString &range, const Ver &have, bool &precise) {
    precise = true;
    if (range.isEmpty()) { precise = false; return true; }   // applies to all -> not confirmed
    if (!have.valid)      { precise = false; return true; }   // unparseable version -> surface, not confirmed

    // The bound token keeps any -pN / pre-release suffix (the char class spans
    // letters/'-'), so parseVersion can rank it -- the old [\d.]+ stopped at '-'.
    static const QRegularExpression op(R"(([<>]=?)\s*([0-9][0-9A-Za-z._\-]*))");
    auto it = op.globalMatch(range);
    QList<QPair<QString, Ver>> bounds;
    while (it.hasNext()) {
        auto m = it.next();
        Ver b = parseVersion(m.captured(2));
        if (!b.valid) continue;
        bounds.append({ m.captured(1), b });
    }
    if (bounds.isEmpty()) {
        // No </> bound. A bare dotted version ("2.4.49") is an EXACT match.
        // Anything else (free text / "n/a") is surfaced, but NOT as confirmed.
        static const QRegularExpression bare(R"(^\s*\d+(?:\.\d+){0,3}\s*$)");
        if (bare.match(range).hasMatch()) {
            const Ver want = parseVersion(range);
            return want.valid && cmpVer(have, want) == 0;     // exact -> precise
        }
        precise = false; return true;                          // free-text -> surfaced
    }
    for (const auto &[oper, bound] : bounds) {
        const int c = cmpVer(have, bound);
        if (oper == "<"  && !(c <  0)) return false;
        if (oper == "<=" && !(c <= 0)) return false;
        if (oper == ">"  && !(c >  0)) return false;
        if (oper == ">=" && !(c >= 0)) return false;
    }
    return true;                                                // bounded match -> precise
}

Match makeMatch(const Entry &e, bool precise) {
    return {
        QString::fromLatin1(e.cveId),
        QString::fromLatin1(e.summary),
        e.cvss,
        QString::fromLatin1(e.cvssVector),
        QString::fromLatin1(e.affectedRange),
        QString::fromLatin1(e.fixVersion),
        QString::fromLatin1(e.reference),
        precise,
    };
}

// Runtime CVE overlay (cve_feed_sync) -- file-scoped, mutex-guarded.
QMutex            g_overlayMutex;
QList<OverlayCve> g_overlay;

} // namespace

QList<Match> lookup(const QString &kind, const QString &versionString) {
    QList<Match> out;
    const Ver have = parseVersion(versionString);
    for (const Entry &e : table()) {
        if (QString::fromLatin1(e.kind) != kind) continue;
        bool precise = true;
        if (!rangeMatches(QString::fromLatin1(e.affectedRange), have, precise))
            continue;
        out.append(makeMatch(e, precise));
    }
    // Runtime overlay: same range/precise semantics. Dedup by cveId (the static
    // table wins) so a feed re-publishing a curated CVE doesn't double-count.
    QSet<QString> seen;
    for (const Match &m : out) seen.insert(m.cveId.toLower());
    QMutexLocker lk(&g_overlayMutex);
    for (const OverlayCve &c : g_overlay) {
        if (c.kind != kind) continue;
        if (seen.contains(c.cveId.toLower())) continue;
        bool precise = true;
        if (!rangeMatches(c.affectedRange, have, precise)) continue;
        seen.insert(c.cveId.toLower());
        out.append({ c.cveId, c.summary, c.cvss, c.cvssVector, c.affectedRange,
                     c.fixVersion, c.reference, precise });
    }
    return out;
}

int setOverlay(const QList<OverlayCve> &entries) {
    QMutexLocker lk(&g_overlayMutex);
    g_overlay = entries;
    return g_overlay.size();
}

void clearOverlay() {
    QMutexLocker lk(&g_overlayMutex);
    g_overlay.clear();
}

int overlayCount() {
    QMutexLocker lk(&g_overlayMutex);
    return g_overlay.size();
}

QList<Match> lookupByFingerprint(const QString &kind, const HttpFingerprint &fp) {
    // Pick the MOST PRECISE parseable version across the fingerprint sources --
    // preferring a source that actually names this kind's vendor -- so a coarse
    // early source (e.g. a major-only "6") doesn't shadow a precise later one
    // (e.g. an "6.1.3" generator) and a foreign source's version (a Server
    // header's Apache version for a CMS kind) doesn't drive the lookup.
    const QString vendor = kind.section('-', 1, 1).toLower();
    const QString sources[] = { fp.bodyVersion, fp.xGenerator, fp.xPoweredBy, fp.server };
    // bodyVersion / xGenerator are already KIND-SCOPED by the fingerprinter (a
    // version sniffed via a kind-specific pattern, or the generator meta), so a
    // bare number there is trusted. server / X-Powered-By are GENERIC shared-infra
    // headers -- a version there only counts if it actually NAMES this kind's
    // vendor; otherwise a foreign version (a PHP X-Powered-By on a WordPress kind)
    // would drive a precise, CVSS-escalated CVE match it has no business confirming.
    const bool vendorScoped[] = { true, true, false, false };
    QString best; int bestComp = -1; bool bestVendor = false; bool anyUsable = false;
    for (int i = 0; i < 4; ++i) {
        const QString &v = sources[i];
        if (v.isEmpty()) continue;
        const Ver pv = parseVersion(v);
        if (!pv.valid) continue;
        const bool vendorMatch = !vendor.isEmpty() && v.toLower().contains(vendor);
        if (!(vendorScoped[i] || vendorMatch)) continue;   // generic header must name the vendor
        anyUsable = true;
        if ((vendorMatch && !bestVendor) ||
            (vendorMatch == bestVendor && pv.ncomp > bestComp)) {
            best = v; bestComp = pv.ncomp; bestVendor = vendorMatch;
        }
    }

    if (anyUsable) {
        // We HAVE a trustworthy version -> a clean, version-confirmed lookup. If it
        // matches nothing, the host is patched / out of range -> return EMPTY.
        // Dumping the whole table here flagged a patched host with every
        // historical CVE (escalated to critical by the CVSS-based severity).
        return lookup(kind, best);
    }

    // No source produced a parseable version at all -> a genuine unknown. Surface
    // the kind's table as IMPRECISE manual-triage leads (never confirmed, so a
    // consumer won't escalate them by CVSS).
    QList<Match> out;
    for (const Entry &e : table()) {
        if (QString::fromLatin1(e.kind) != kind) continue;
        Match m = makeMatch(e, /*precise=*/false);
        m.summary = QStringLiteral("[manual triage] ") + m.summary;
        out.append(m);
    }
    return out;
}

int auditRanges() {
    static const QRegularExpression op(R"(([<>]=?)\s*([0-9][0-9A-Za-z._\-]*))");
    int dead = 0;
    for (const Entry &e : table()) {
        Ver lower, upper; bool hasLower = false, hasUpper = false;
        auto it = op.globalMatch(QString::fromLatin1(e.affectedRange));
        while (it.hasNext()) {
            auto m = it.next();
            const Ver b = parseVersion(m.captured(2));
            if (!b.valid) continue;
            const QString o = m.captured(1);
            if (o == ">" || o == ">=") { lower = b; hasLower = true; }
            else                       { upper = b; hasUpper = true; }
        }
        // Crossed bounds (lower >= upper) -> the conjunction matches no version.
        if (hasLower && hasUpper && cmpVer(lower, upper) >= 0) ++dead;
    }
    return dead;
}

} // namespace Nullock::Core::CveDatabase

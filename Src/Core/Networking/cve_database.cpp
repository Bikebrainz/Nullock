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
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
          "<7.19.16", "7.19.16",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
          ">=8.0.0,<8.3.4", "8.3.4",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
          ">=8.4.0,<8.4.4", "8.4.4",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
          ">=8.5.0,<8.5.3", "8.5.3",
          "https://confluence.atlassian.com/security/cve-2023-22518-1311473907.html" },
        { "cms-confluence", "CVE-2023-22518",
          "Confluence Data Center/Server: unauthenticated authorization bypass (data destruction)",
          9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
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
          "Apache httpd < 2.4.59: mod_proxy encoding issue -> SSRF / auth bypass",
          8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "<2.4.59", "2.4.59",
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
    if (bounds.isEmpty()) {
        // No </> bound parsed. A bare dotted version ("2.4.49") means an
        // EXACT-version match (as the struct doc promises) -- compare for
        // equality rather than silently matching every version. Anything else
        // (free-text / "n/a") we surface rather than drop.
        static const QRegularExpression bare(R"(^\s*\d+(?:\.\d+){0,3}\s*$)");
        if (bare.match(range).hasMatch()) {
            const Triple want = parseVersion(range);
            return want.valid && cmpTriple(have, want) == 0;
        }
        return true;
    }
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

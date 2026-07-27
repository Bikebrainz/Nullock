// Regression corpus for the service-version CVE matcher's pure logic (no
// network): the per-product banner parser, and the version-range matching
// (min inclusive / max EXCLUSIVE / exact) including the boundary conditions
// where an off-by-one silently flips a finding. Plus the runtime overlay and
// its dedup-by-cveId (static table wins).
//
// Run via:  ctest -R service_vulns -V

#include "service_vulns.hpp"

#include <QCoreApplication>
#include <QSet>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::ServiceVulns;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// product/version parsed from a banner.
QString prod(const char *banner) { QString p, v; parseBanner(QString::fromLatin1(banner), 0, p, v); return p; }
QString ver(const char *banner)  { QString p, v; parseBanner(QString::fromLatin1(banner), 0, p, v); return v; }
// the set of CVE ids matched for a product+version.
QSet<QString> cves(const char *product, const char *version) {
    QSet<QString> s;
    for (const auto &h : matchVersion(product, version)) s.insert(h.cveId);
    return s;
}
bool has(const QSet<QString> &s, const char *id) { return s.contains(id); }
// precision of one CVE match: 1 = confirmed/precise, 0 = lead/imprecise, -1 = not matched.
int matchPrec(const char *product, const char *version, const char *id) {
    for (const auto &h : matchVersion(product, version))
        if (h.cveId == id) return h.precise ? 1 : 0;
    return -1;
}
// productOnly() canonical product for a banner (port hint).
QString pOnly(const char *banner, int port = 0) { return productOnly(QString::fromLatin1(banner), port); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    clearOverlay();   // tests run against the static table unless told otherwise

    // ===== parseBanner ===================================================
    chk("parse OpenSSH", prod("SSH-2.0-OpenSSH_9.7p1 Ubuntu") == "openssh" && ver("SSH-2.0-OpenSSH_9.7p1") == "9.7p1");
    chk("parse vsftpd",  prod("220 (vsFTPd 2.3.4)") == "vsftpd" && ver("220 (vsFTPd 2.3.4)") == "2.3.4");
    chk("parse Apache",  prod("Apache/2.4.49 (Debian)") == "apache" && ver("Apache/2.4.49 (Debian)") == "2.4.49");
    chk("parse nginx",   prod("nginx/1.20.1") == "nginx" && ver("nginx/1.20.1") == "1.20.1");
    chk("parse IIS",     prod("Microsoft-IIS/6.0") == "iis" && ver("Microsoft-IIS/6.0") == "6.0");
    chk("empty banner -> no product", prod("") == "");
    chk("unrecognized banner -> no product", prod("Caddy/2.6.4") == "");

    // ===== regreSSHion CVE-2024-6387 range (min 8.5 incl, max 9.8 excl) ==
    chk("openssh 9.7p1 -> regreSSHion (in range)", has(cves("openssh", "9.7p1"), "CVE-2024-6387"));
    chk("openssh 8.5p1 -> regreSSHion (at min boundary)", has(cves("openssh", "8.5p1"), "CVE-2024-6387"));
    chk("openssh 9.8p1 -> NOT regreSSHion (the fix, >= max)", !has(cves("openssh", "9.8p1"), "CVE-2024-6387"));
    chk("openssh 8.4p1 -> NOT regreSSHion (below min)", !has(cves("openssh", "8.4p1"), "CVE-2024-6387"));
    chk("openssh 8.4p1 -> still ssh-agent CVE-2023-38408 (5.5-9.3p1)", has(cves("openssh", "8.4p1"), "CVE-2023-38408"));
    chk("openssh 9.3p2 -> NOT CVE-2023-38408 (the fix, max 9.3.2 excl)", !has(cves("openssh", "9.3p2"), "CVE-2023-38408"));
    chk("openssh 7.6 -> username-enum CVE-2018-15473 (< 7.7)", has(cves("openssh", "7.6"), "CVE-2018-15473"));
    chk("openssh 7.7 -> NOT CVE-2018-15473 (the fix)", !has(cves("openssh", "7.7"), "CVE-2018-15473"));

    // ===== Apache exact + range boundaries ==============================
    chk("apache 2.4.49 -> exact CVE-2021-41773", has(cves("apache", "2.4.49"), "CVE-2021-41773"));
    chk("apache 2.4.49 -> NOT the 2.4.50-exact CVE-2021-42013", !has(cves("apache", "2.4.49"), "CVE-2021-42013"));
    chk("apache 2.4.50 -> exact CVE-2021-42013, not 41773",
        has(cves("apache", "2.4.50"), "CVE-2021-42013") && !has(cves("apache", "2.4.50"), "CVE-2021-41773"));
    chk("apache 2.4.55 -> mod_proxy CVE-2023-25690 (max 2.4.56 excl)", has(cves("apache", "2.4.55"), "CVE-2023-25690"));
    chk("apache 2.4.58 -> NO apache CVEs (patched, past all maxes)", cves("apache", "2.4.58").isEmpty());

    // ===== vsftpd / proftpd exact-ish ====================================
    chk("vsftpd 2.3.4 -> backdoor CVE-2011-2523", has(cves("vsftpd", "2.3.4"), "CVE-2011-2523"));
    chk("vsftpd 3.0.3 -> clean", cves("vsftpd", "3.0.3").isEmpty());

    // ===== empty / unknown ==============================================
    chk("empty product -> no hits", cves("", "9.7p1").isEmpty());
    chk("empty version -> no hits", cves("openssh", "").isEmpty());
    chk("unknown product -> no hits", cves("caddy", "2.6.4").isEmpty());

    // ===== precision-aware grading (#1 FP fix) ==========================
    // A truncated "Apache/2.4" (ServerTokens Minor) still MATCHES the 2.4.x
    // range CVEs (could be vulnerable) but must be flagged imprecise -- a lead,
    // not a confirmed critical -- because the hidden patch level might be fixed.
    {
        bool imprecise = false;
        for (const auto &h : matchVersion("apache", "2.4"))
            if (h.cveId == "CVE-2023-25690" && !h.precise) imprecise = true;
        chk("apache 2.4 (truncated) -> range CVE matched but FLAGGED IMPRECISE (lead)", imprecise);

        bool precise55 = false;
        for (const auto &h : matchVersion("apache", "2.4.55"))
            if (h.cveId == "CVE-2023-25690") precise55 = h.precise;
        chk("apache 2.4.55 (precise) -> CVE-2023-25690 confirmed (precise=true)", precise55);

        bool exactPrecise = false;
        for (const auto &h : matchVersion("apache", "2.4.49"))
            if (h.cveId == "CVE-2021-41773") exactPrecise = h.precise;
        chk("apache 2.4.49 -> exact CVE-2021-41773 is precise", exactPrecise);

        // "2.3" has a DIFFERING prefix from the 2.4.x range -> certain (no match).
        chk("apache 2.3 (differing prefix) -> no 2.4.x range hit", !has(cves("apache", "2.3"), "CVE-2023-25690"));

        // F1: the same truncation logic must apply to EXACT-match CVEs. A scanned
        // "2.4" is LESS precise than the exact CVE-2021-41773 version (2.4.49); the
        // hidden patch level could BE .49, so it is an affected LEAD (imprecise),
        // not a silent drop. A differing prefix ("2.5") is still certainly-not.
        chk("apache 2.4 (truncated) -> EXACT CVE-2021-41773 matched as a LEAD (F1)",
            has(cves("apache", "2.4"), "CVE-2021-41773"));
        chk("apache 2.4 -> that exact-CVE match is flagged imprecise (lead)",
            matchPrec("apache", "2.4", "CVE-2021-41773") == 0);
        chk("apache 2.5 (differing prefix) -> NOT the 2.4.49-exact CVE-2021-41773 (certain)",
            !has(cves("apache", "2.5"), "CVE-2021-41773"));

        // The all-zero-tail certainty branch (truncatedAgainst line 213): a truncated
        // version sitting exactly at an EXCLUSIVE-max fix ending in .0 must be CERTAIN
        // (NOT affected), never a false-positive lead. nginx CVE-2021-23017 has maxVer
        // "1.21.0"; a 'nginx/1.21' banner is exactly the fix. Every other truncated
        // case above hits a NON-zero tail, so this branch was behavior-untested -- a
        // regression treating an all-zero tail as truncated would flip nginx 1.21 (the
        // patched release) into a spurious CVE hit while the suite stayed green.
        chk("nginx 1.21 (truncated, == exclusive-max fix 1.21.0) -> NOT CVE-2021-23017",
            !has(cves("nginx", "1.21"), "CVE-2021-23017"));
        chk("nginx 1.20.0 (precise, in range) -> IS CVE-2021-23017 (positive control)",
            has(cves("nginx", "1.20.0"), "CVE-2021-23017"));
    }

    // ===== lettered patch/build ordering (#2) ============================
    // proftpd CVE-2015-3306 affects ONLY 1.3.5; the fix is the lettered build
    // 1.3.5a, which sorts ABOVE 1.3.5 -> the fixed build must NOT match.
    chk("proftpd 1.3.5 -> mod_copy CVE-2015-3306 (vulnerable release)", has(cves("proftpd", "1.3.5"), "CVE-2015-3306"));
    chk("proftpd 1.3.5 hit is CONFIRMED (precise, not a lead)", matchPrec("proftpd", "1.3.5", "CVE-2015-3306") == 1);
    chk("proftpd 1.3.5a -> NOT CVE-2015-3306 (lettered FIX sorts above 1.3.5)", !has(cves("proftpd", "1.3.5a"), "CVE-2015-3306"));
    chk("proftpd 1.3.5b -> NOT CVE-2015-3306 (later fix build)", !has(cves("proftpd", "1.3.5b"), "CVE-2015-3306"));
    chk("proftpd 1.3.4 -> NOT CVE-2015-3306 (below the affected release)", !has(cves("proftpd", "1.3.4"), "CVE-2015-3306"));

    // ===== pre-release ordering (#2) =====================================
    // A pre-release ("1.2.3rc1") must sort BELOW its final release ("1.2.3"),
    // not above it. Exercised through the overlay's range + exact semantics.
    {
        OverlayCve rng; rng.product = "acme"; rng.cveId = "CVE-3000-0001"; rng.cvss = 7.5;
        rng.minVer = ""; rng.maxVer = "1.2.3"; rng.exact = false;     // affected: < 1.2.3
        setOverlay({rng});
        chk("pre-release 1.2.3rc1 sorts BELOW 1.2.3 -> inside (,1.2.3)", has(cves("acme", "1.2.3rc1"), "CVE-3000-0001"));
        chk("pre-release 1.2.3beta2 also below 1.2.3 -> inside range", has(cves("acme", "1.2.3beta2"), "CVE-3000-0001"));
        chk("final 1.2.3 is the fix boundary -> NOT inside (,1.2.3)", !has(cves("acme", "1.2.3"), "CVE-3000-0001"));
        chk("patch build 1.2.3a sorts ABOVE 1.2.3 -> NOT inside (,1.2.3)", !has(cves("acme", "1.2.3a"), "CVE-3000-0001"));
        OverlayCve ex; ex.product = "acme"; ex.cveId = "CVE-3000-0002"; ex.cvss = 5.0;
        ex.minVer = "1.2.3"; ex.exact = true;                          // affected: == 1.2.3 only
        setOverlay({ex});
        chk("exact 1.2.3 does NOT match the pre-release 1.2.3rc1", !has(cves("acme", "1.2.3rc1"), "CVE-3000-0002"));
        chk("exact 1.2.3 matches the final release", has(cves("acme", "1.2.3"), "CVE-3000-0002"));
        clearOverlay();
    }

    // ===== min-boundary truncation -> lead (#3) ==========================
    // A version truncated BELOW the min ("8" vs a [8.5, 9.8) range) used to be
    // dropped as not-affected; the hidden minor decides, so it must surface as
    // an affected LEAD (matched, imprecise), symmetric to the max-side fix.
    chk("openssh 8 (truncated at/under min 8.5) -> regreSSHion matched as a LEAD", has(cves("openssh", "8"), "CVE-2024-6387"));
    chk("openssh 8 -> that regreSSHion match is flagged imprecise (lead)", matchPrec("openssh", "8", "CVE-2024-6387") == 0);
    chk("openssh 7 (whole 7.x is below 8.5) -> NOT regreSSHion (certain, dropped)", !has(cves("openssh", "7"), "CVE-2024-6387"));
    // a band that fully contains 8.x is still a CONFIRMED hit (truncation doesn't decide).
    chk("openssh 8 -> ssh-agent CVE-2023-38408 stays CONFIRMED (all 8.x in 5.5-9.3p1)", matchPrec("openssh", "8", "CVE-2023-38408") == 1);

    // ===== product-only -> INFO (#1) + new product coverage (#4) =========
    // ServerTokens Prod / server_tokens off: a bare "Apache"/"nginx" has no
    // version, so parseBanner yields nothing -- but productOnly still names the
    // service so the caller can emit an INFO "version not disclosed" finding
    // instead of a silent (looks-patched) drop.
    chk("bare 'Apache' -> parseBanner gives NO product/version", prod("Apache") == "" && ver("Apache") == "");
    chk("bare 'Apache' -> productOnly recognizes apache", pOnly("Apache") == "apache");
    chk("bare 'nginx' -> productOnly recognizes nginx", pOnly("nginx") == "nginx");
    chk("full banner -> productOnly still returns the product", pOnly("Apache/2.4.49 (Debian)") == "apache");
    chk("genuinely unknown server -> productOnly empty", pOnly("Caddy/2.6.4") == "");
    chk("empty banner -> productOnly empty", pOnly("") == "");
    // newly-recognized products (parse where the version is disclosed; name-only otherwise).
    chk("parse lighttpd version", prod("lighttpd/1.4.59") == "lighttpd" && ver("lighttpd/1.4.59") == "1.4.59");
    chk("productOnly lighttpd (no version)", pOnly("lighttpd") == "lighttpd");
    chk("parse MariaDB handshake version", prod("5.5.5-10.3.27-MariaDB-1") == "mariadb" && ver("5.5.5-10.3.27-MariaDB-1") == "10.3.27");
    chk("productOnly Postfix SMTP greeting (no version)", pOnly("220 mail.example.com ESMTP Postfix (Ubuntu)", 25) == "postfix");
    chk("productOnly Dovecot IMAP greeting (no version)", pOnly("* OK [CAPABILITY IMAP4rev1] Dovecot ready.", 143) == "dovecot");
    chk("productOnly Redis INFO line", pOnly("redis_version:7.0.5") == "redis");
    chk("productOnly MySQL handshake marker", pOnly("5.7.33-log mysql_native_password caching_sha2_password", 3306) == "mysql");

    // ===== Samba range (curated CVE, reachable via matchVersion/overlay) ==
    chk("samba 4.5.0 -> SambaCry CVE-2017-7494 (3.5.0-4.6.3)", has(cves("samba", "4.5.0"), "CVE-2017-7494"));
    chk("samba 4.6.4 -> NOT CVE-2017-7494 (the fix, max excl)", !has(cves("samba", "4.6.4"), "CVE-2017-7494"));

    // ===== SMB/445 removed from the default probe set (#4) ===============
    chk("445 is NOT in the default probe set (raw grab is blind to SMB)", !serviceProbePorts().contains(445));

    // ===== runtime overlay + dedup ======================================
    {
        OverlayCve o;
        o.product = "nginx"; o.cveId = "CVE-2099-0001"; o.cvss = 7.5;
        o.minVer = "1.18.0"; o.maxVer = "1.25.0"; o.exact = false;
        setOverlay({o});
        chk("overlay: nginx 1.20.1 -> the overlay CVE matches", has(cves("nginx", "1.20.1"), "CVE-2099-0001"));
        chk("overlay: nginx 1.26.0 -> out of overlay range, no hit", !has(cves("nginx", "1.26.0"), "CVE-2099-0001"));
        // dedup: an overlay re-publishing a static CVE id must NOT double-count.
        OverlayCve dup;
        dup.product = "vsftpd"; dup.cveId = "CVE-2011-2523"; dup.cvss = 1.0;
        dup.minVer = "2.3.4"; dup.exact = true;
        setOverlay({dup});
        int n = 0; for (const auto &h : matchVersion("vsftpd", "2.3.4")) if (h.cveId == "CVE-2011-2523") ++n;
        chk("overlay: a re-published static CVE id is deduped (static wins, counted once)", n == 1);
        clearOverlay();
        chk("clearOverlay: overlay CVE gone", !has(cves("nginx", "1.20.1"), "CVE-2099-0001"));
    }

    std::fprintf(stderr, "service_vulns_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

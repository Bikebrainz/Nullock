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
    chk("unrecognized banner -> no product", prod("lighttpd/1.4.59") == "");

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
    chk("unknown product -> no hits", cves("lighttpd", "1.4.59").isEmpty());

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
    }

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

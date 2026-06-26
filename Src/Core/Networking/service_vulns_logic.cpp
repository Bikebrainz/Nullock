// Pure service-version CVE matching, split out of service_vulns.cpp so a unit
// test can link it against Qt6::Core alone -- grabBanner()/scan() and their
// QTcpSocket (Qt Network) stay in service_vulns.cpp. Mirrors the established
// sibling pattern. Everything here is I/O-free: the curated CVE table, the
// version parser/comparator, the banner parser, the version matcher, and the
// thread-safe runtime overlay.

#include "service_vulns.hpp"

#include <QMutex>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

namespace Nullock::Core::ServiceVulns {

namespace {

// A version-pinned service CVE. `minVer`/`maxVer` bound the affected range
// (min inclusive, max EXCLUSIVE); `exact` means the version must equal minVer.
// Versions are compared component-wise; an OpenSSH "9.3p1" parses as 9.3.1.
struct ServiceCve {
    const char *product;
    const char *cveId;
    double      cvss;
    const char *cvssVector;
    const char *minVer;     // "" = no lower bound
    const char *maxVer;     // "" = no upper bound (exclusive)
    bool        exact;
    const char *affected;
    const char *summary;
    const char *fix;
    const char *reference;
};

const QList<ServiceCve> &table() {
    static const QList<ServiceCve> t = {
        { "vsftpd", "CVE-2011-2523", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.3.4", "", true, "2.3.4",
          "vsftpd 2.3.4 ships a backdoor: a ':)' in the username opens a root shell on 6200.",
          "upgrade to a clean 3.x build", "https://nvd.nist.gov/vuln/detail/CVE-2011-2523" },
        { "openssh", "CVE-2024-6387", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "8.5", "9.8", false, "8.5p1 - 9.7p1",
          "regreSSHion: signal-handler race in sshd allows unauthenticated RCE as root (glibc Linux).",
          "9.8p1", "https://nvd.nist.gov/vuln/detail/CVE-2024-6387" },
        { "openssh", "CVE-2018-15473", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "", "7.7", false, "< 7.7",
          "Username enumeration via differing auth responses for valid vs invalid users.",
          "7.7", "https://nvd.nist.gov/vuln/detail/CVE-2018-15473" },
        { "proftpd", "CVE-2015-3306", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "1.3.5", "1.3.5.1", false, "1.3.5 (mod_copy)",
          "mod_copy SITE CPFR/CPTO lets an unauthenticated attacker copy files -> RCE.",
          "1.3.5a", "https://nvd.nist.gov/vuln/detail/CVE-2015-3306" },
        { "exim", "CVE-2019-10149", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "4.87", "4.92", false, "4.87 - 4.91",
          "Improper validation of the recipient address allows remote command execution as root.",
          "4.92", "https://nvd.nist.gov/vuln/detail/CVE-2019-10149" },
        { "apache", "CVE-2021-41773", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.49", "2.4.50", true, "2.4.49",
          "Path traversal + RCE via %2e encoding when mod_cgi is enabled and Require all denied missing.",
          "2.4.51", "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" },
        { "apache", "CVE-2021-42013", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.50", "2.4.51", true, "2.4.50",
          "Incomplete fix for CVE-2021-41773; double-encoded path traversal -> RCE.",
          "2.4.51", "https://nvd.nist.gov/vuln/detail/CVE-2021-42013" },
        { "nginx", "CVE-2021-23017", 7.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L",
          "0.6.18", "1.21.0", false, "0.6.18 - 1.20.x (resolver)",
          "Off-by-one in the DNS resolver can corrupt memory; RCE-class when resolver is configured.",
          "1.21.0", "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" },
        { "iis", "CVE-2017-7269", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "6.0", "6.1", true, "6.0 (WebDAV)",
          "Buffer overflow in the WebDAV ScStoragePathFromUrl handler -> unauthenticated RCE.",
          "no vendor fix (EOL); disable WebDAV", "https://nvd.nist.gov/vuln/detail/CVE-2017-7269" },
        { "samba", "CVE-2017-7494", 9.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
          "3.5.0", "4.6.4", false, "3.5.0 - 4.6.3 (SambaCry)",
          "A writable share + this version lets a client load and run a shared library as root.",
          "4.6.4", "https://nvd.nist.gov/vuln/detail/CVE-2017-7494" },
        { "openssh", "CVE-2023-38408", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "5.5", "9.3.2", false, "5.5 - 9.3p1 (ssh-agent PKCS#11)",
          "Remote code execution in ssh-agent's PKCS#11 provider loading; exploitable when an agent is forwarded to an attacker-controlled host.",
          "9.3p2", "https://nvd.nist.gov/vuln/detail/CVE-2023-38408" },
        { "apache", "CVE-2023-25690", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.0", "2.4.56", false, "2.4.0 - 2.4.55 (mod_proxy)",
          "HTTP request smuggling via mod_proxy with certain RewriteRule/ProxyPassMatch patterns (config-dependent).",
          "2.4.56", "https://nvd.nist.gov/vuln/detail/CVE-2023-25690" },
        { "apache", "CVE-2021-44790", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.0", "2.4.52", false, "2.4.0 - 2.4.51 (mod_lua)",
          "Buffer overflow in mod_lua multipart parsing -> possible RCE (requires a mod_lua script calling r:parsebody).",
          "2.4.52", "https://nvd.nist.gov/vuln/detail/CVE-2021-44790" },
    };
    return t;
}

// Compare dotted versions component-wise. "9.3p1" -> [9,3,1]; "2.4.49" -> [2,4,49].
QList<int> verParts(const QString &v) {
    QList<int> out;
    const QString norm = QString(v).replace(QRegularExpression("[A-Za-z]+"), ".");
    for (const QString &p : norm.split('.', Qt::SkipEmptyParts)) {
        bool ok = false; const int n = p.toInt(&ok);
        if (ok) out << n;
    }
    return out;
}
int verCmp(const QString &a, const QString &b) {
    const QList<int> pa = verParts(a), pb = verParts(b);
    for (int i = 0; i < qMax(pa.size(), pb.size()); ++i) {
        const int x = i < pa.size() ? pa[i] : 0;
        const int y = i < pb.size() ? pb[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

// Is `version` too imprecise to confirm a range CVE's UPPER bound? verCmp pads
// missing components with 0, so a less-precise version ("2.4") compares EQUAL on
// the shared prefix of an exclusive max ("2.4.56") and is judged below-max --
// even though the real (hidden) patch level could be at or past the fix. Only
// the missing trailing component(s) decide affected-vs-patched, so the match is
// a LEAD, not a confirmation. (When the known prefix already differs from max --
// e.g. "2.3" vs "2.4.56" -- the comparison is certain, so this returns false.)
bool maxUncertain(const QString &version, const QString &maxVer) {
    if (maxVer.isEmpty()) return false;
    const QList<int> pv = verParts(version), pm = verParts(maxVer);
    if (pv.size() >= pm.size()) return false;   // precise enough to compare max
    for (int i = 0; i < pv.size(); ++i)
        if (pv[i] != pm[i]) return false;       // prefix differs -> comparison is certain
    return true;                                // equal prefix + fewer components
}

// Runtime overlay store (cve_feed_sync). Guarded by a mutex because
// matchVersion runs on scan worker threads.
QMutex            g_overlayMutex;
QList<OverlayCve> g_overlay;

} // namespace

QList<int> serviceProbePorts() {
    return { 21, 22, 25, 80, 110, 143, 443, 445, 587, 3306, 5432, 8080 };
}

void parseBanner(const QString &banner, int port, QString &product, QString &version) {
    product.clear(); version.clear();
    if (banner.isEmpty()) return;
    struct Pat { const char *product; QRegularExpression re; };
    static const QList<Pat> pats = {
        { "openssh", QRegularExpression("OpenSSH[_/]([0-9][0-9.p]*)", QRegularExpression::CaseInsensitiveOption) },
        { "vsftpd",  QRegularExpression("vsftpd\\s+([0-9][0-9.]*)",   QRegularExpression::CaseInsensitiveOption) },
        { "proftpd", QRegularExpression("ProFTPD\\s+([0-9][0-9.]*)",  QRegularExpression::CaseInsensitiveOption) },
        { "exim",    QRegularExpression("Exim\\s+([0-9][0-9.]*)",     QRegularExpression::CaseInsensitiveOption) },
        { "apache",  QRegularExpression("Apache/([0-9][0-9.]*)",      QRegularExpression::CaseInsensitiveOption) },
        { "nginx",   QRegularExpression("nginx/([0-9][0-9.]*)",       QRegularExpression::CaseInsensitiveOption) },
        { "iis",     QRegularExpression("Microsoft-IIS/([0-9][0-9.]*)", QRegularExpression::CaseInsensitiveOption) },
        { "samba",   QRegularExpression("Samba\\s+([0-9][0-9.]*)",    QRegularExpression::CaseInsensitiveOption) },
    };
    Q_UNUSED(port);
    for (const Pat &p : pats) {
        const auto m = p.re.match(banner);
        if (m.hasMatch()) { product = p.product; version = m.captured(1); return; }
    }
}

QList<CveHit> matchVersion(const QString &product, const QString &version) {
    QList<CveHit> out;
    if (product.isEmpty() || version.isEmpty()) return out;
    for (const ServiceCve &c : table()) {
        if (product.compare(QString::fromUtf8(c.product), Qt::CaseInsensitive) != 0) continue;
        bool affected;
        if (c.exact) {
            affected = verCmp(version, QString::fromUtf8(c.minVer)) == 0;
        } else {
            const bool aboveMin = !*c.minVer || verCmp(version, QString::fromUtf8(c.minVer)) >= 0;
            const bool belowMax = !*c.maxVer || verCmp(version, QString::fromUtf8(c.maxVer)) < 0;
            affected = aboveMin && belowMax;
        }
        if (!affected) continue;
        CveHit h;
        h.product = product; h.version = version;
        h.cveId = c.cveId; h.cvss = c.cvss; h.cvssVector = c.cvssVector;
        h.summary = c.summary; h.affected = c.affected; h.fix = c.fix; h.reference = c.reference;
        h.precise = c.exact || !maxUncertain(version, QString::fromUtf8(c.maxVer));
        out.append(h);
    }
    // Also consult the runtime overlay (same range semantics, reusing verCmp).
    // Dedup by cveId (static table wins) so a feed re-publishing a curated CVE,
    // or listing one twice, doesn't double-count downstream.
    QSet<QString> seenCve;
    for (const CveHit &h : out) seenCve.insert(h.cveId.toLower());
    {
        QMutexLocker lk(&g_overlayMutex);
        for (const OverlayCve &c : g_overlay) {
            if (product.compare(c.product, Qt::CaseInsensitive) != 0) continue;
            if (seenCve.contains(c.cveId.toLower())) continue;
            bool affected;
            if (c.exact) {
                affected = verCmp(version, c.minVer) == 0;
            } else {
                const bool aboveMin = c.minVer.isEmpty() || verCmp(version, c.minVer) >= 0;
                const bool belowMax = c.maxVer.isEmpty() || verCmp(version, c.maxVer) < 0;
                affected = aboveMin && belowMax;
            }
            if (!affected) continue;
            seenCve.insert(c.cveId.toLower());
            CveHit h;
            h.product = product; h.version = version;
            h.cveId = c.cveId; h.cvss = c.cvss; h.cvssVector = c.cvssVector;
            h.summary = c.summary; h.affected = c.affected; h.fix = c.fix; h.reference = c.reference;
            h.precise = c.exact || !maxUncertain(version, c.maxVer);
            out.append(h);
        }
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

} // namespace Nullock::Core::ServiceVulns

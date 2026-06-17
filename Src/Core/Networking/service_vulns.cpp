#include "service_vulns.hpp"

#include <QMutex>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QTcpSocket>

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

bool isHttpPort(int port) {
    return port == 80 || port == 8080 || port == 8000 || port == 8443
        || port == 443 || port == 8888 || port == 9200;
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

namespace {
QString grabBanner(const QString &host, int port, int timeoutMs) {
    QTcpSocket s;
    s.connectToHost(host, static_cast<quint16>(port));
    if (!s.waitForConnected(timeoutMs)) return QString();
    QString banner;
    // SSH/FTP/SMTP push a banner unprompted.
    if (s.waitForReadyRead(timeoutMs))
        banner = QString::fromLatin1(s.readAll().left(1024));
    // HTTP-ish ports answer a HEAD with a Server: header.
    if (banner.isEmpty() && isHttpPort(port)) {
        s.write("HEAD / HTTP/1.0\r\nHost: " + host.toUtf8() + "\r\n\r\n");
        s.flush();
        if (s.waitForReadyRead(timeoutMs)) {
            const QString resp = QString::fromLatin1(s.readAll().left(2048));
            for (const QString &line : resp.split("\r\n"))
                if (line.startsWith("Server:", Qt::CaseInsensitive)) { banner = line.mid(7).trimmed(); break; }
        }
    }
    s.disconnectFromHost();
    return banner.trimmed();
}
} // namespace

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    result.host = req.host;
    const QList<int> ports = req.ports.isEmpty() ? serviceProbePorts() : req.ports;

    for (int port : ports) {
        ++result.portsProbed;
        const QString banner = grabBanner(req.host, port, req.timeoutMs);
        if (banner.isEmpty()) continue;
        ++result.banners;
        QString product, version;
        parseBanner(banner, port, product, version);
        if (product.isEmpty()) continue;
        for (CveHit h : matchVersion(product, version)) {
            h.port = port;
            h.banner = banner.left(200);
            result.hits.append(h);
        }
    }
    return result;
}

} // namespace Nullock::Core::ServiceVulns

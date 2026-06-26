#pragma once

// Service-version vulnerability matching (the nmap `vulners` / metasploit-aux
// capability). The port scanner grabs banners; cve_database correlates *web*
// frameworks. Neither turns a NETWORK service banner -- "SSH-2.0-OpenSSH_7.4",
// "220 (vsFTPd 2.3.4)", "Server: Apache/2.4.49" -- into a CVE. This does:
// connect, grab the banner, parse product+version, and match a curated table of
// high-signal, version-pinned service CVEs (vsftpd backdoor, regreSSHion,
// Apache path traversal, ProFTPd mod_copy, Exim RCE, IIS WebDAV, ...). Each
// match is a finding tagged with the CVE id, CVSS, and fix version. Read-only
// banner grab -- it identifies vulnerable versions, it does not exploit them.

#include <QList>
#include <QString>

namespace Nullock::Core::ServiceVulns {

struct CveHit {
    int     port = 0;
    QString product;     // "openssh", "vsftpd", "apache", ...
    QString version;     // parsed version
    QString cveId;
    double  cvss = 0.0;
    QString cvssVector;
    QString summary;
    QString affected;    // human-readable affected range
    QString fix;
    QString reference;
    QString banner;      // the banner the match came from
    bool    precise = true;  // false => the scanned version is LESS precise than
                             // the CVE's range boundary (e.g. "Apache/2.4" vs a
                             // 2.4.x range) so affected-vs-patched can't be
                             // confirmed -- grade it a lead, not a confirmed CVE.
};

struct Request {
    QString host;
    QList<int> ports;        // empty => curated service-port set
    int     timeoutMs = 1200;
};

struct Result {
    QString host;
    QList<CveHit> hits;
    int     portsProbed = 0;
    int     banners = 0;     // how many ports yielded a banner
    QString error;
};

// Connect to each port, grab its banner, parse product+version, and return CVE
// matches. Only ports that answer with a parseable banner can match.
Result scan(const Request &req);

QList<int> serviceProbePorts();

// Exposed for tests: parse "product"/"version" out of a banner (port hints the
// protocol). Returns empty product when nothing recognizable is found.
void parseBanner(const QString &banner, int port, QString &product, QString &version);

// Exposed for tests: CVE matches for an already-parsed product+version.
// Consults the curated static table AND the runtime overlay (see below).
QList<CveHit> matchVersion(const QString &product, const QString &version);

// ---- Runtime CVE overlay (cve_feed_sync) -------------------------------
// The static table ships a curated set of high-signal service CVEs. The
// overlay lets an operator extend detection coverage at runtime by syncing an
// external CVE feed (or pushing entries directly) -- matchVersion checks both,
// reusing the same product/version-range semantics. Thread-safe.
struct OverlayCve {
    QString product;      // matched case-insensitively
    QString cveId;
    double  cvss = 0.0;
    QString cvssVector;
    QString minVer;       // "" = no lower bound (inclusive)
    QString maxVer;       // "" = no upper bound (exclusive)
    bool    exact = false; // true => match only version == minVer
    QString affected;
    QString summary;
    QString fix;
    QString reference;
};

// Replace the overlay with `entries`; returns how many were stored.
int  setOverlay(const QList<OverlayCve> &entries);
void clearOverlay();
int  overlayCount();

} // namespace Nullock::Core::ServiceVulns

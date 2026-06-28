// Regression corpus for scan_bridge's pure port-scan -> findings logic (no
// network). This module is entirely pure; the test locks:
//   - classify(): the curated port -> (kind, severity) map. Crucially the severity
//     string MUST stay in the kind's fixed enricher CVSS band (database 7.5/high,
//     remote-admin 8.1/high, mgmt 8.6/high, file-share 6.5/medium, cleartext
//     5.9/medium) or the report's severity and cvssScore diverge -- these
//     assertions enforce that consistency against silent future regressions;
//   - the service-label fallback (non-standard ports), incl. the sftp/tftp guard
//     and the CouchDB/Cassandra/Oracle/SQL-Server parity additions;
//   - port 25 / unknown ports are NOT flagged;
//   - fromPortResults(): only "open" ports are processed, includeOpenPorts gates
//     the generic info finding, and a classified port doesn't also info-double.
//
// Run via:  ctest -R scan_bridge -V

#include "scan_bridge.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core;
using namespace Nullock::Core::ScanBridge;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// classify a (port, service) and assert the resulting kind+severity.
bool is(quint16 port, const QString &service, const char *kind, const char *sev) {
    QString k, s, l;
    classify(port, service, QString(), k, s, l);
    return k == QLatin1String(kind) && s == QLatin1String(sev);
}
bool unclassified(quint16 port, const QString &service) {
    QString k, s, l;
    classify(port, service, QString(), k, s, l);
    return k.isEmpty();
}
PortResult open(quint16 port, const QString &service = QString(), const QString &banner = QString()) {
    PortResult r; r.host = "h"; r.port = port; r.status = "open"; r.service = service; r.banner = banner; return r;
}
int countKind(const QList<BridgeFinding> &fs, const char *kind) {
    int n = 0; for (const auto &f : fs) if (f.kind == QLatin1String(kind)) ++n; return n;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== classify: port -> kind + severity (band consistency) =========
    chk("3306 MySQL -> exposed-database high", is(3306, "", "exposed-database", "high"));
    chk("6379 Redis -> exposed-database high", is(6379, "", "exposed-database", "high"));
    chk("9200 Elasticsearch -> exposed-database high", is(9200, "", "exposed-database", "high"));
    chk("3389 RDP -> exposed-remote-admin high", is(3389, "", "exposed-remote-admin", "high"));
    chk("23 Telnet -> exposed-remote-admin high", is(23, "", "exposed-remote-admin", "high"));
    chk("2375 Docker API -> exposed-management-interface high", is(2375, "", "exposed-management-interface", "high"));
    chk("6443 Kubernetes -> exposed-management-interface high", is(6443, "", "exposed-management-interface", "high"));
    chk("445 SMB -> exposed-file-share MEDIUM (band 6.5)", is(445, "", "exposed-file-share", "medium"));
    chk("2049 NFS -> exposed-file-share medium", is(2049, "", "exposed-file-share", "medium"));
    chk("21 FTP -> exposed-cleartext-service MEDIUM (band 5.9)", is(21, "", "exposed-cleartext-service", "medium"));
    chk("110 POP3 -> exposed-cleartext-service medium", is(110, "", "exposed-cleartext-service", "medium"));
    chk("389 LDAP -> exposed-cleartext-service medium", is(389, "", "exposed-cleartext-service", "medium"));
    // Band-divergence guards: a file-share/cleartext kind must NEVER be "high".
    chk("file-share is not mislabeled high", !is(445, "", "exposed-file-share", "high"));
    chk("cleartext is not mislabeled high", !is(21, "", "exposed-cleartext-service", "high"));

    // ===== classify: service-label fallback (non-standard ports) ========
    chk("redis on :7777 (label fallback) -> exposed-database high",
        is(7777, "redis", "exposed-database", "high"));
    chk("telnet on a non-standard port -> exposed-remote-admin high",
        is(9999, "telnet", "exposed-remote-admin", "high"));
    chk("ftp label -> exposed-cleartext-service medium", is(9998, "ftp", "exposed-cleartext-service", "medium"));
    chk("sftp is NOT flagged as cleartext FTP (SSH-based, encrypted)", unclassified(9997, "sftp"));
    chk("tftp is NOT flagged as cleartext FTP", unclassified(9996, "tftp"));
    // Parity additions (were port-covered but missing from the fallback):
    chk("couchdb label -> exposed-database high", is(9995, "couchdb", "exposed-database", "high"));
    chk("cassandra label -> exposed-database high", is(9994, "cassandra", "exposed-database", "high"));
    chk("mssql label -> exposed-database high", is(9993, "mssql", "exposed-database", "high"));
    chk("oracle label -> exposed-database high", is(9992, "oracle", "exposed-database", "high"));

    // ===== classify: deliberate non-findings ============================
    chk("port 25 SMTP is NOT flagged (MX is expected; STARTTLS invisible to a TCP scan)",
        unclassified(25, "smtp"));
    chk("an unknown port with no recognizable service is not classified", unclassified(8080, "http"));

    // ===== fromPortResults: open-only, info gating ======================
    {
        // Only "open" ports are processed; a closed one is skipped.
        const auto out = fromPortResults({ open(3306), [] { PortResult c; c.port = 5432; c.status = "closed"; return c; }() },
                                         Options{});
        chk("only OPEN ports are classified (closed 5432 skipped)", countKind(out, "exposed-database") == 1);
    }
    {
        Options o; o.includeOpenPorts = true; o.correlateCves = false;
        const auto out = fromPortResults({ open(8080, "http") }, o);
        chk("an unknown OPEN port emits a generic open-port info finding", countKind(out, "open-port") == 1);
    }
    {
        Options o; o.includeOpenPorts = false; o.correlateCves = false;
        const auto out = fromPortResults({ open(8080, "http") }, o);
        chk("includeOpenPorts=false suppresses the generic info finding", out.isEmpty());
    }
    {
        // A classified port does NOT also emit the generic open-port info finding.
        Options o; o.includeOpenPorts = true; o.correlateCves = false;
        const auto out = fromPortResults({ open(3306) }, o);
        chk("a classified port does not double as an open-port info finding",
            countKind(out, "exposed-database") == 1 && countKind(out, "open-port") == 0);
    }

    std::fprintf(stderr, "scan_bridge_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

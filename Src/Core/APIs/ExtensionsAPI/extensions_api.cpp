#include "extensions_api.hpp"

#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJSValueIterator>
#include <QStandardPaths>

namespace Nullock::Core {

namespace {
constexpr int kMaxLogLines = 500;
}

ExtensionsApiBridge::ExtensionsApiBridge(ExtensionsApi *parent)
    : QObject(parent), m_owner(parent) {}

void ExtensionsApiBridge::log(const QString &message) {
    m_owner->appendLog(message);
}

void ExtensionsApiBridge::onResponse(const QJSValue &callback) {
    if (!callback.isCallable()) {
        m_owner->appendLog("[ext] onResponse: argument is not a function");
        return;
    }
    m_owner->m_onResponseHandlers.append(callback);
}

ExtensionsApi::ExtensionsApi(QObject *parent) : QObject(parent) {
    m_bridge = new ExtensionsApiBridge(this);
    QJSValue nullockObj = m_engine.newQObject(m_bridge);
    m_engine.globalObject().setProperty("nullock", nullockObj);
    loadAll();
}

ExtensionsApi::~ExtensionsApi() = default;

QString ExtensionsApi::extensionsDir() const {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + "/extensions";
}

QStringList ExtensionsApi::recentLog(int max) const {
    if (max <= 0 || max >= m_logLines.size()) return m_logLines;
    return m_logLines.mid(m_logLines.size() - max);
}

bool ExtensionsApi::reload() {
    m_onResponseHandlers.clear();
    m_loadedScripts.clear();
    // Reset the engine by clearing the global except our nullock object.
    // Easier: recreate the engine altogether.
    m_engine.collectGarbage();
    // Re-init globals.
    QJSValue nullockObj = m_engine.newQObject(m_bridge);
    m_engine.globalObject().setProperty("nullock", nullockObj);
    loadAll();
    emit loadedChanged();
    return true;
}

void ExtensionsApi::loadAll() {
    const QString dir = extensionsDir();
    QDir().mkpath(dir);
    const QFileInfoList files = QDir(dir).entryInfoList({ "*.js" }, QDir::Files);
    for (const QFileInfo &fi : files) {
        QFile f(fi.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QString source = QString::fromUtf8(f.readAll());
        const QJSValue result = m_engine.evaluate(source, fi.fileName());
        if (result.isError()) {
            appendLog(QString("[ext] %1: %2 at line %3")
                          .arg(fi.fileName())
                          .arg(result.toString())
                          .arg(result.property("lineNumber").toInt()));
            continue;
        }
        m_loadedScripts.append(fi.fileName());
        appendLog(QString("[ext] loaded %1").arg(fi.fileName()));
    }
    emit loadedChanged();
}

void ExtensionsApi::appendLog(const QString &message) {
    const QString stamped = QString("[%1] %2")
                                .arg(QDateTime::currentDateTime().toString("HH:mm:ss.zzz"))
                                .arg(message);
    m_logLines.append(stamped);
    if (m_logLines.size() > kMaxLogLines)
        m_logLines.remove(0, m_logLines.size() - kMaxLogLines);
    emit logChanged();
}

void ExtensionsApi::onResponseReceived(const Nullock::Proxy::HttpRequest &request,
                                       const Nullock::Proxy::HttpResponse &response) {
    if (m_onResponseHandlers.isEmpty()) return;

    QJSValue entry = m_engine.newObject();
    entry.setProperty("method", request.method);
    entry.setProperty("host",   request.host);
    entry.setProperty("port",   request.port);
    entry.setProperty("path",   request.path);
    entry.setProperty("scheme", response.wasTls ? QStringLiteral("https") : QStringLiteral("http"));
    entry.setProperty("url",
        (response.wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
        + request.host
        + ((request.port == 80 || request.port == 443)
           ? QString() : QString(":%1").arg(request.port))
        + request.path);
    entry.setProperty("status", response.statusCode);
    entry.setProperty("reasonPhrase", response.reasonPhrase);
    entry.setProperty("responseSize", static_cast<int>(response.body.size()));
    entry.setProperty("bodyPreview",
        QString::fromUtf8(response.body.left(4096)));

    QJSValue headers = m_engine.newArray(response.headers.size());
    for (qsizetype i = 0; i < response.headers.size(); ++i) {
        QJSValue pair = m_engine.newArray(2);
        pair.setProperty(0, response.headers[i].first);
        pair.setProperty(1, response.headers[i].second);
        headers.setProperty(static_cast<quint32>(i), pair);
    }
    entry.setProperty("headers", headers);

    QJSValueList args = { entry };
    for (QJSValue &handler : m_onResponseHandlers) {
        const QJSValue r = handler.call(args);
        if (r.isError()) {
            appendLog(QString("[ext] handler threw: %1 at line %2")
                          .arg(r.toString())
                          .arg(r.property("lineNumber").toInt()));
        }
    }
}

} // namespace Nullock::Core

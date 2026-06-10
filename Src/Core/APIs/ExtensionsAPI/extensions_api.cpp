#include "extensions_api.hpp"
#include "passive_scanner.hpp"

#include <QDateTime>
#include <QUrl>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJSValueIterator>
#include <QMetaType>
#include <QStandardPaths>
#include <QThread>

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

void ExtensionsApiBridge::onRequest(const QJSValue &callback) {
    if (!callback.isCallable()) {
        m_owner->appendLog("[ext] onRequest: argument is not a function");
        return;
    }
    m_owner->m_onRequestHandlers.append(callback);
}

void ExtensionsApiBridge::reportFinding(const QString &severity,
                                        const QString &kind,
                                        const QString &summary,
                                        const QString &evidence,
                                        const QString &url) {
    PassiveScanner *scanner = m_owner->scanner();
    if (!scanner) {
        // No scanner wired -- don't silently drop the signal; surface it
        // in the extension log so the author still sees their finding.
        m_owner->appendLog(QString("[ext][finding] %1/%2: %3 (%4)")
                               .arg(severity, kind, summary, url));
        return;
    }
    const QString host = QUrl(url).host();
    // rowId 0 = extension-originated; the panel still renders it, the URL
    // makes it actionable. reportFinding runs the enrichment pass for us.
    scanner->reportFinding(0, severity, kind, summary, evidence, host, url);
}

ExtensionsApi::ExtensionsApi(QObject *parent) : QObject(parent) {
    // Both types travel across thread boundaries when worker threads call
    // applyRequestMutation / applyResponseMutation via BlockingQueuedConnection.
    qRegisterMetaType<Nullock::Proxy::HttpRequest>("Nullock::Proxy::HttpRequest");
    qRegisterMetaType<Nullock::Proxy::HttpResponse>("Nullock::Proxy::HttpResponse");

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
    m_onRequestHandlers.clear();
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
    // 64 KiB preview. Static analysis extensions (DOM taint, secret
    // scanning) need enough of the body to see inline scripts and bundle
    // headers; 4 KiB truncated mid-<script>. responseSize still reports
    // the true length so handlers can tell when they're seeing a prefix.
    entry.setProperty("bodyPreview",
        QString::fromUtf8(response.body.left(64 * 1024)));

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

namespace {

// Anything a JS handler returns ends up serialised onto the wire. A
// header name or value carrying CR / LF would split the request and
// hand an attacker a request-smuggling primitive against the upstream.
// Validate aggressively at the boundary so handlers can't get this
// wrong by accident or design.
static bool isValidHeaderName(const QString &name) {
    if (name.isEmpty() || name.size() > 256) return false;
    // RFC 7230 token chars only.
    for (QChar c : name) {
        const ushort u = c.unicode();
        if (u < 0x21 || u > 0x7E) return false;
        // Reject separators that aren't valid in a token.
        static const QString seps = "\"(),/:;<=>?@[\\]{}";
        if (seps.contains(c)) return false;
    }
    return true;
}
static bool isValidHeaderValue(const QString &value) {
    if (value.size() > 8192) return false;
    for (QChar c : value) {
        const ushort u = c.unicode();
        // VCHAR + SP + HT; absolutely no CR / LF / NUL.
        if (u == '\r' || u == '\n' || u == '\0') return false;
        if (u < 0x20 && u != '\t') return false;
    }
    return true;
}

QList<QPair<QString, QString>> headersFromJs(const QJSValue &arr) {
    QList<QPair<QString, QString>> out;
    if (!arr.isArray()) return out;
    const int n = arr.property("length").toInt();
    // Cap total header count to avoid a runaway handler blowing memory.
    constexpr int kMaxHeaders = 256;
    for (int i = 0; i < n && out.size() < kMaxHeaders; ++i) {
        const QJSValue pair = arr.property(i);
        if (!pair.isArray() || pair.property("length").toInt() < 2) continue;
        const QString k = pair.property(0).toString();
        const QString v = pair.property(1).toString();
        if (!isValidHeaderName(k) || !isValidHeaderValue(v)) continue;
        out.append({ k, v });
    }
    return out;
}

QJSValue headersToJs(QJSEngine *engine,
                     const QList<QPair<QString, QString>> &headers) {
    QJSValue arr = engine->newArray(static_cast<quint32>(headers.size()));
    for (qsizetype i = 0; i < headers.size(); ++i) {
        QJSValue pair = engine->newArray(2);
        pair.setProperty(0, headers[i].first);
        pair.setProperty(1, headers[i].second);
        arr.setProperty(static_cast<quint32>(i), pair);
    }
    return arr;
}

} // namespace

Nullock::Proxy::HttpRequest ExtensionsApi::applyRequestMutation(
    const Nullock::Proxy::HttpRequest &req) {
    if (m_onRequestHandlers.isEmpty()) return req;
    if (thread() == QThread::currentThread()) return doMutateRequest(req);

    Nullock::Proxy::HttpRequest out;
    QMetaObject::invokeMethod(this, "doMutateRequest", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(Nullock::Proxy::HttpRequest, out),
                              Q_ARG(Nullock::Proxy::HttpRequest, req));
    return out;
}

Nullock::Proxy::HttpResponse ExtensionsApi::applyResponseMutation(
    const Nullock::Proxy::HttpRequest &req,
    const Nullock::Proxy::HttpResponse &resp) {
    if (m_onResponseHandlers.isEmpty()) return resp;
    if (thread() == QThread::currentThread()) return doMutateResponse(req, resp);

    Nullock::Proxy::HttpResponse out;
    QMetaObject::invokeMethod(this, "doMutateResponse", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(Nullock::Proxy::HttpResponse, out),
                              Q_ARG(Nullock::Proxy::HttpRequest, req),
                              Q_ARG(Nullock::Proxy::HttpResponse, resp));
    return out;
}

Nullock::Proxy::HttpRequest ExtensionsApi::doMutateRequest(Nullock::Proxy::HttpRequest req) {
    if (m_onRequestHandlers.isEmpty()) return req;

    QJSValue entry = m_engine.newObject();
    entry.setProperty("method", req.method);
    entry.setProperty("host", req.host);
    entry.setProperty("port", req.port);
    entry.setProperty("path", req.path);
    entry.setProperty("headers", headersToJs(&m_engine, req.headers));
    entry.setProperty("bodyText", QString::fromUtf8(req.body));

    for (QJSValue &handler : m_onRequestHandlers) {
        const QJSValue r = handler.call({ entry });
        if (r.isError()) {
            appendLog(QString("[ext] onRequest threw: %1 at line %2")
                          .arg(r.toString()).arg(r.property("lineNumber").toInt()));
            continue;
        }
        // If the handler returned an object, treat its properties as the
        // new state. Returning undefined/null = no change.
        if (r.isObject()) entry = r;
    }

    // Read final mutated values back into the C++ struct. Host/port stay
    // immutable on purpose -- changing them mid-flight would require
    // reconnecting to a different upstream, which is a bigger design.
    // Validate everything from JS before letting it touch the wire:
    // method must look like an HTTP method, path must not contain CR/LF.
    {
        const QString m = entry.property("method").toString();
        bool methodOk = !m.isEmpty() && m.size() <= 32;
        for (QChar c : m) {
            const ushort u = c.unicode();
            if (u < 'A' || u > 'Z') { methodOk = false; break; }
        }
        if (methodOk) req.method = m;
    }
    {
        const QString p = entry.property("path").toString();
        bool pathOk = !p.isEmpty() && p.size() <= 8192;
        for (QChar c : p) {
            const ushort u = c.unicode();
            if (u == '\r' || u == '\n' || u == '\0' || u == ' ' || u < 0x20) {
                pathOk = false; break;
            }
        }
        if (pathOk) req.path = p;
    }
    req.headers = headersFromJs(entry.property("headers"));
    req.body   = entry.property("bodyText").toString().toUtf8();
    return req;
}

Nullock::Proxy::HttpResponse ExtensionsApi::doMutateResponse(
    Nullock::Proxy::HttpRequest req, Nullock::Proxy::HttpResponse resp) {
    if (m_onResponseHandlers.isEmpty()) return resp;

    QJSValue entry = m_engine.newObject();
    entry.setProperty("method", req.method);
    entry.setProperty("url",
        (resp.wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
        + req.host
        + ((req.port == 80 || req.port == 443)
           ? QString() : QString(":%1").arg(req.port))
        + req.path);
    entry.setProperty("status", resp.statusCode);
    entry.setProperty("reasonPhrase", resp.reasonPhrase);
    entry.setProperty("headers", headersToJs(&m_engine, resp.headers));
    entry.setProperty("bodyText", QString::fromUtf8(resp.body));
    entry.setProperty("responseSize", static_cast<int>(resp.body.size()));

    for (QJSValue &handler : m_onResponseHandlers) {
        const QJSValue r = handler.call({ entry });
        if (r.isError()) {
            appendLog(QString("[ext] onResponse threw: %1 at line %2")
                          .arg(r.toString()).arg(r.property("lineNumber").toInt()));
            continue;
        }
        if (r.isObject()) entry = r;
    }

    // Clamp the JS-returned status to a valid HTTP code; reject CR/LF
    // in the reason phrase (would split the status line going to the
    // client).
    const int sc = entry.property("status").toInt();
    if (sc >= 100 && sc < 600) resp.statusCode = sc;
    {
        const QString rp = entry.property("reasonPhrase").toString();
        bool rpOk = rp.size() <= 128;
        for (QChar c : rp) {
            const ushort u = c.unicode();
            if (u == '\r' || u == '\n' || u == '\0' || u < 0x20) {
                rpOk = false; break;
            }
        }
        if (rpOk) resp.reasonPhrase = rp;
    }
    resp.headers      = headersFromJs(entry.property("headers"));
    resp.body         = entry.property("bodyText").toString().toUtf8();
    return resp;
}

} // namespace Nullock::Core

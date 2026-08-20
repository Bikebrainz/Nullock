#include "extensions_api.hpp"
#include "extension_perms_logic.hpp"
#include "extensions_utils_logic.hpp"
#include "oast_server.hpp"   // OastServer + OastHit (same APIs lib)
#include "dns_sink.hpp"      // DnsSink

#include <QDateTime>
#include <QUrl>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
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
    // Observation always registers; whether a returned mutation is applied
    // depends on the extension's "modify-responses" grant (enforced in
    // doMutateResponse). Registering is safe -- the read-only path always runs.
    const bool mayMutate = Nullock::Core::ExtensionPerms::isAllowed(
        m_owner->m_currentGrants, Nullock::Core::ExtensionPerms::kModifyResponses);
    m_owner->m_onResponseHandlers.append({ callback, mayMutate });
    m_owner->refreshHandlerFlags();
}

void ExtensionsApiBridge::onRequest(const QJSValue &callback) {
    if (!callback.isCallable()) {
        m_owner->appendLog("[ext] onRequest: argument is not a function");
        return;
    }
    // onRequest ALWAYS mutates the upstream request -- deny it unless the
    // extension declared "modify-requests" (default-deny). The handler is not
    // registered, so a non-permitted extension simply can't touch requests.
    if (!Nullock::Core::ExtensionPerms::isAllowed(
            m_owner->m_currentGrants, Nullock::Core::ExtensionPerms::kModifyRequests)) {
        m_owner->appendLog(
            "[ext] onRequest DENIED: extension lacks the 'modify-requests' "
            "permission (add `// nullock:permissions modify-requests`)");
        return;
    }
    m_owner->m_onRequestHandlers.append(callback);
    m_owner->refreshHandlerFlags();
}

void ExtensionsApiBridge::onUnload(const QJSValue &callback) {
    if (!callback.isCallable()) {
        m_owner->appendLog("[ext] onUnload: argument is not a function");
        return;
    }
    // Ungated: a teardown callback cleans up the SCRIPT's own state and can't
    // touch the wire, so -- like onResponse observation -- it always registers.
    m_owner->m_onUnloadHandlers.append(callback);
}

void ExtensionsApiBridge::registerUnloadingHandler(const QJSValue &callback) {
    onUnload(callback);   // Burp-name alias
}

QVariantList ExtensionsApiBridge::history(int max) const {
    const QList<ExtensionsApi::HistoryEntry> &hist = m_owner->m_history;
    // max<=0 -> all; otherwise the last `max` (most recent). Clamp to size.
    const int n = (max <= 0) ? hist.size() : qMin(max, hist.size());
    const int start = hist.size() - n;
    QVariantList out;
    out.reserve(n);
    for (int i = start; i < hist.size(); ++i) {
        const ExtensionsApi::HistoryEntry &h = hist[i];
        QVariantMap m;
        m["atMs"]         = h.atMs;
        m["method"]       = h.method;
        m["host"]         = h.host;
        m["port"]         = h.port;
        m["path"]         = h.path;
        m["url"]          = h.url;
        m["tls"]          = h.tls;
        m["status"]       = h.status;
        m["responseSize"] = h.responseSize;
        out.append(m);
    }
    return out;   // Qt auto-converts QVariantList -> JS array of objects
}

void ExtensionsApiBridge::reportFinding(const QString &severity,
                                        const QString &kind,
                                        const QString &summary,
                                        const QString &evidence,
                                        const QString &url) {
    IFindingSink *scanner = m_owner->scanner();
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

// nullock.utils.* -- thin wrappers over the pure, unit-tested ExtUtils codecs.
QString ExtensionsUtilsBridge::base64Encode(const QString &s) const { return ExtUtils::base64Encode(s); }
QString ExtensionsUtilsBridge::base64Decode(const QString &s) const { return ExtUtils::base64Decode(s); }
QString ExtensionsUtilsBridge::urlEncode(const QString &s)    const { return ExtUtils::urlEncode(s); }
QString ExtensionsUtilsBridge::urlDecode(const QString &s)    const { return ExtUtils::urlDecode(s); }
QString ExtensionsUtilsBridge::hexEncode(const QString &s)    const { return ExtUtils::hexEncode(s); }
QString ExtensionsUtilsBridge::hexDecode(const QString &s)    const { return ExtUtils::hexDecode(s); }
QString ExtensionsUtilsBridge::htmlEncode(const QString &s)   const { return ExtUtils::htmlEncode(s); }
QString ExtensionsUtilsBridge::htmlDecode(const QString &s)   const { return ExtUtils::htmlDecode(s); }
QString ExtensionsUtilsBridge::sha256(const QString &s)       const { return ExtUtils::sha256Hex(s); }
QString ExtensionsUtilsBridge::sha1(const QString &s)         const { return ExtUtils::sha1Hex(s); }
QString ExtensionsUtilsBridge::md5(const QString &s)          const { return ExtUtils::md5Hex(s); }

// nullock.collaborator.* -- mint OOB payloads + read the interactions they trigger.
ExtensionsCollaboratorBridge::ExtensionsCollaboratorBridge(ExtensionsApi *owner)
    : QObject(owner), m_owner(owner) {}

QVariantMap ExtensionsCollaboratorBridge::generate() const {
    OastServer *oast = m_owner->oast();
    if (!oast) return {};
    const QJsonObject minted = oast->mintToken();
    const QString tok = minted.value("token").toString();
    if (!tok.isEmpty()) m_tokens.insert(tok);
    return minted.toVariantMap();
}

QVariantList ExtensionsCollaboratorBridge::interactions() const {
    QVariantList out;
    if (m_tokens.isEmpty()) return out;
    auto append = [&](const OastHit &h, const char *type) {
        if (!m_tokens.contains(h.token)) return;   // scope to THIS extension's tokens
        QVariantMap m;
        m["id"]       = static_cast<qlonglong>(h.id);
        m["token"]    = h.token;
        m["type"]     = QString::fromLatin1(type);
        m["sourceIp"] = h.sourceIp;
        m["atMs"]     = static_cast<qlonglong>(h.atMs);
        m["host"]     = h.hostHeader;   // Host header (HTTP) / queried name (DNS)
        m["method"]   = h.method;       // HTTP verb / "DNS"
        m["path"]     = h.path;         // request path (HTTP) / record type (DNS)
        out.append(m);
    };
    if (OastServer *oast = m_owner->oast())
        for (const OastHit &h : oast->hitsSince(0)) append(h, "http");
    if (DnsSink *dns = m_owner->dnsSink())
        for (const OastHit &h : dns->hitsSince(0)) append(h, "dns");
    return out;
}

ExtensionsApi::ExtensionsApi(QObject *parent) : QObject(parent) {
    // Both types travel across thread boundaries when worker threads call
    // applyRequestMutation / applyResponseMutation via BlockingQueuedConnection.
    qRegisterMetaType<Nullock::Proxy::HttpRequest>("Nullock::Proxy::HttpRequest");
    qRegisterMetaType<Nullock::Proxy::HttpResponse>("Nullock::Proxy::HttpResponse");

    // Parented to this, which is what gives it CppOwnership when handed to
    // newQObject() -- so the bridge outlives any engine that reload() destroys.
    m_bridge = new ExtensionsApiBridge(this);
    // Parented to this (CppOwnership) for the same reason as m_bridge: it must
    // survive every engine reload() destroys, and is re-published each rebuild.
    m_utils  = new ExtensionsUtilsBridge(this);
    m_collab = new ExtensionsCollaboratorBridge(this);
    rebuildEngine();
    loadAll();
}

void ExtensionsApi::rebuildEngine() {
    // Order is load-bearing. Every QJSValue this object holds belongs to the
    // OLD engine, and a QJSValue that outlives its engine is undefined
    // behaviour -- so they must all be gone before the reset below runs.
    // Callers clear the handler lists first; this assert-by-construction keeps
    // that true even if a new QJSValue member is added later and the caller
    // forgets, because dropping them here is idempotent.
    m_onResponseHandlers.clear();
    m_onRequestHandlers.clear();
    m_onUnloadHandlers.clear();   // same QJSValue-lifetime rule as the two above
    refreshHandlerFlags();

    m_engine = std::make_unique<QJSEngine>();
    QJSValue nullockObj = m_engine->newQObject(m_bridge);
    // Group the codec/hash helpers under nullock.utils (Burp's api.utilities()).
    // m_utils is CppOwned (parented to this), so re-wrapping it on the fresh
    // engine each rebuild is safe -- the object itself is never recreated.
    nullockObj.setProperty("utils", m_engine->newQObject(m_utils));
    nullockObj.setProperty("collaborator", m_engine->newQObject(m_collab));
    m_engine->globalObject().setProperty("nullock", nullockObj);
}

ExtensionsApi::~ExtensionsApi() {
    // App exit is an unload too: fire teardown callbacks while the engine and
    // the parented bridge are still alive (both outlive this body -- m_engine is
    // a member destroyed after ~body runs, m_bridge is a child QObject cleaned up
    // in ~QObject). A well-behaved onUnload handler flushes JS-side state / logs.
    runUnloadHandlers();
}

void ExtensionsApi::runUnloadHandlers() {
    // Owner thread only. Fire each teardown callback in turn; one throwing must
    // not stop the others (a half-run teardown is worse than a logged error), so
    // each is isolated and its error surfaced to the extension log. The list is
    // NOT cleared here -- rebuildEngine() owns clearing it (the QJSValues belong
    // to the engine it is about to destroy).
    for (QJSValue &fn : m_onUnloadHandlers) {
        if (!fn.isCallable()) continue;
        const QJSValue r = fn.call();
        if (r.isError())
            appendLog(QString("[ext] onUnload handler error: %1 at line %2")
                          .arg(r.toString())
                          .arg(r.property("lineNumber").toInt()));
    }
}

QString ExtensionsApi::extensionsDir() const {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + "/extensions";
}

QStringList ExtensionsApi::recentLog(int max) const {
    if (max <= 0 || max >= m_logLines.size()) return m_logLines;
    return m_logLines.mid(m_logLines.size() - max);
}

bool ExtensionsApi::reload() {
    // Every currently-loaded script is about to be torn down (rebuildEngine
    // destroys the engine, then loadAll re-reads from disk -- an uninstalled
    // script is simply gone afterward). Give each its onUnload callback FIRST,
    // while its engine is still alive, before anything is cleared.
    runUnloadHandlers();

    m_loadedScripts.clear();
    m_scriptGrants.clear();
    m_currentGrants.clear();

    // Destroy the engine and build a fresh one, rather than collecting garbage
    // in the old one. QJSEngine has no way to clear its global scope, and
    // collectGarbage() only frees what is ALREADY unreachable -- so every
    // global an extension assigned, and every prototype it patched, used to
    // survive a reload.
    //
    // That is what made "uninstall" a lie. Extensions share one engine, so a
    // script the user had just deleted from disk left its globals in place and
    // still reachable by the extensions that remained -- and an observe-only
    // script could poison state a mutation-granted one depended on, or clobber
    // the `nullock` object itself. Nothing short of restarting the process
    // cleared it.
    //
    // Safe because m_bridge is parented to this (CppOwnership), so the dying
    // engine does not take it with it.
    rebuildEngine();

    loadAll();
    emit loadedChanged();
    return true;
}

void ExtensionsApi::loadAll() {
    const QString dir = extensionsDir();
    QDir().mkpath(dir);
    m_allScripts.clear();
    loadDisabledSet();   // refresh the user's per-extension enable/disable choices
    const QFileInfoList files = QDir(dir).entryInfoList({ "*.js" }, QDir::Files, QDir::Name);
    for (const QFileInfo &fi : files) {
        m_allScripts.append(fi.fileName());
        // A user-disabled extension stays on disk + in the list, but is never
        // evaluated (no globals, no handlers) -- the same "unchecked Loaded" state
        // Burp gives it. Skipping BEFORE reading the file also avoids running a
        // script the user turned off.
        if (m_disabled.contains(fi.fileName())) {
            appendLog(QString("[ext] %1 (disabled)").arg(fi.fileName()));
            continue;
        }
        QFile f(fi.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QString source = QString::fromUtf8(f.readAll());
        // Parse the extension's declared permissions and make them the active
        // grant set for its evaluate() -- the bridge reads m_currentGrants when
        // the script registers onRequest / onResponse handlers.
        m_currentGrants = Nullock::Core::ExtensionPerms::parsePermissions(source);
        m_scriptGrants.insert(fi.fileName(), QStringList(m_currentGrants.begin(), m_currentGrants.end()));
        const QJSValue result = m_engine->evaluate(source, fi.fileName());
        if (result.isError()) {
            appendLog(QString("[ext] %1: %2 at line %3")
                          .arg(fi.fileName())
                          .arg(result.toString())
                          .arg(result.property("lineNumber").toInt()));
            continue;
        }
        m_loadedScripts.append(fi.fileName());
        const QStringList g = m_scriptGrants.value(fi.fileName());
        appendLog(g.isEmpty()
            ? QString("[ext] loaded %1 (observe-only)").arg(fi.fileName())
            : QString("[ext] loaded %1 (granted: %2)").arg(fi.fileName(), g.join(", ")));
    }
    m_currentGrants.clear();   // not evaluating any extension now
    emit loadedChanged();
}

void ExtensionsApi::setExtensionEnabled(const QString &name, bool enabled) {
    if (name.isEmpty()) return;
    const bool wasDisabled = m_disabled.contains(name);
    if (enabled == !wasDisabled) return;   // no change
    if (enabled) m_disabled.remove(name);
    else         m_disabled.insert(name);
    saveDisabledSet();
    reload();   // re-evaluate everything under the new enable/disable set
}

void ExtensionsApi::loadDisabledSet() {
    m_disabled.clear();
    QFile f(extensionsDir() + "/.nullock-disabled.json");
    if (!f.open(QIODevice::ReadOnly)) return;   // absent == nothing disabled
    const QJsonArray arr = QJsonDocument::fromJson(f.readAll()).array();
    for (const QJsonValue &v : arr) {
        const QString s = v.toString();
        if (!s.isEmpty()) m_disabled.insert(s);
    }
}

void ExtensionsApi::saveDisabledSet() {
    const QString path = extensionsDir() + "/.nullock-disabled.json";
    if (m_disabled.isEmpty()) { QFile::remove(path); return; }   // clean slate = no file
    QJsonArray arr;
    QStringList names(m_disabled.constBegin(), m_disabled.constEnd());
    names.sort();   // stable on-disk order
    for (const QString &s : names) arr.append(s);
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
}

void ExtensionsApi::refreshHandlerFlags() {
    // Owner thread only. Release-store so a worker that observes true has also
    // observed the appends that made it true.
    m_hasRequestHandlers.store(!m_onRequestHandlers.isEmpty(), std::memory_order_release);
    m_hasResponseHandlers.store(!m_onResponseHandlers.isEmpty(), std::memory_order_release);
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
    // Record the exchange in the history ring FIRST -- before the no-handlers
    // early-return -- so nullock.history() is complete even for an extension that
    // registered no onResponse handler. Owner-thread only, same as the read side.
    {
        HistoryEntry h;
        h.atMs         = QDateTime::currentMSecsSinceEpoch();
        h.method       = request.method;
        h.host         = request.host;
        h.port         = request.port;
        h.path         = request.path;
        h.tls          = response.wasTls;
        h.url          = (response.wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
                         + request.host
                         + ((request.port == 80 || request.port == 443)
                            ? QString() : QString(":%1").arg(request.port))
                         + request.path;
        h.status       = response.statusCode;
        h.responseSize = static_cast<int>(response.body.size());
        m_history.append(h);
        while (m_history.size() > kMaxHistory) m_history.removeFirst();
    }

    if (m_onResponseHandlers.isEmpty()) return;

    QJSValue entry = m_engine->newObject();
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

    QJSValue headers = m_engine->newArray(response.headers.size());
    for (qsizetype i = 0; i < response.headers.size(); ++i) {
        QJSValue pair = m_engine->newArray(2);
        pair.setProperty(0, response.headers[i].first);
        pair.setProperty(1, response.headers[i].second);
        headers.setProperty(static_cast<quint32>(i), pair);
    }
    entry.setProperty("headers", headers);

    QJSValueList args = { entry };
    for (ResponseHandler &h : m_onResponseHandlers) {
        const QJSValue r = h.fn.call(args);
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
    // Read the ATOMIC, never the QList: this runs on the CALLER's thread and a
    // concurrent reload() may be clearing/re-appending the list right now.
    // A stale "false" only skips extensions for this one message; a stale
    // "true" is harmless because doMutateRequest re-checks on the owner thread.
    if (!m_hasRequestHandlers.load(std::memory_order_acquire)) return req;
    if (thread() == QThread::currentThread()) return doMutateRequest(req);

    // Seeded with the ORIGINAL, not default-constructed: Q_RETURN_ARG only
    // writes `out` when the invocation succeeds, and a blank HttpRequest is a
    // request with an empty method, host and path. Forwarding that upstream is
    // strictly worse than forwarding the untouched original, so the failure
    // direction has to be "extensions did not run", never "send garbage".
    //
    // The SEEDING is what covers teardown, NOT the bool below. For a blocking-
    // queued call invokeMethod returns TRUE once the QMetaCallEvent is posted;
    // it then waits on a semaphore that ~QObject releases when the receiver is
    // destroyed, and still returns true with `out` never written. The bool only
    // catches signature-resolution failure (bad method name / unregistered
    // metatype) -- unreachable while both slots stay `public slots:` with their
    // metatypes registered in the ctor, so treat it as belt-and-braces.
    Nullock::Proxy::HttpRequest out = req;
    if (!QMetaObject::invokeMethod(this, "doMutateRequest", Qt::BlockingQueuedConnection,
                                   Q_RETURN_ARG(Nullock::Proxy::HttpRequest, out),
                                   Q_ARG(Nullock::Proxy::HttpRequest, req))) {
        qWarning("ExtensionsApi: onRequest dispatch failed; forwarding the request unmodified");
        return req;
    }
    return out;
}

Nullock::Proxy::HttpResponse ExtensionsApi::applyResponseMutation(
    const Nullock::Proxy::HttpRequest &req,
    const Nullock::Proxy::HttpResponse &resp) {
    // See applyRequestMutation: atomic, not the QList -- the caller is a proxy
    // worker thread and reload() mutates the list on the owner thread.
    if (!m_hasResponseHandlers.load(std::memory_order_acquire)) return resp;
    if (thread() == QThread::currentThread()) return doMutateResponse(req, resp);

    // See applyRequestMutation: the seeding, not the bool, is what stops a
    // cancelled teardown dispatch handing the client a 0-status empty body.
    Nullock::Proxy::HttpResponse out = resp;
    if (!QMetaObject::invokeMethod(this, "doMutateResponse", Qt::BlockingQueuedConnection,
                                   Q_RETURN_ARG(Nullock::Proxy::HttpResponse, out),
                                   Q_ARG(Nullock::Proxy::HttpRequest, req),
                                   Q_ARG(Nullock::Proxy::HttpResponse, resp))) {
        qWarning("ExtensionsApi: onResponse dispatch failed; passing the response through unmodified");
        return resp;
    }
    return out;
}

Nullock::Proxy::HttpRequest ExtensionsApi::doMutateRequest(Nullock::Proxy::HttpRequest req) {
    if (m_onRequestHandlers.isEmpty()) return req;

    QJSValue entry = m_engine->newObject();
    entry.setProperty("method", req.method);
    entry.setProperty("host", req.host);
    entry.setProperty("port", req.port);
    entry.setProperty("path", req.path);
    entry.setProperty("headers", headersToJs(m_engine.get(), req.headers));
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

    // Each handler gets its OWN entry object, rebuilt from the authoritative
    // `resp` -- they are NOT handed one shared object.
    //
    // A QJSValue object is a REFERENCE. Passing one shared `entry` to every
    // handler meant an UNGRANTED extension could simply assign to its argument
    //     nullock.onResponse(function (e) { e.bodyText = "injected"; });
    // and never return anything. The gate below only guarded REPLACING entry
    // with the RETURN value, so it never saw that write -- and the read-back
    // after the loop then pushed the mutation onto the wire. Every extension
    // that registered an onResponse handler could rewrite responses without the
    // "modify-responses" grant, defeating the default-deny model outright.
    //
    // Registration cannot simply be refused the way onRequest does (see the
    // binding, which drops an ungranted onRequest handler entirely): an
    // ungranted onResponse handler is deliberately still allowed to OBSERVE.
    // So the enforcement has to be here, and it has to discard whatever an
    // ungranted handler did to its copy.
    auto buildEntry = [&]() {
        QJSValue e = m_engine->newObject();
        e.setProperty("method", req.method);
        e.setProperty("url",
            (resp.wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
            + req.host
            + ((req.port == 80 || req.port == 443)
               ? QString() : QString(":%1").arg(req.port))
            + req.path);
        e.setProperty("status", resp.statusCode);
        e.setProperty("reasonPhrase", resp.reasonPhrase);
        e.setProperty("headers", headersToJs(m_engine.get(), resp.headers));
        e.setProperty("bodyText", QString::fromUtf8(resp.body));
        e.setProperty("responseSize", static_cast<int>(resp.body.size()));
        return e;
    };

    // Fold a GRANTED handler's result back into resp. Clamps the JS status to a
    // valid HTTP code and rejects CR/LF in the reason phrase (which would split
    // the status line going to the client). Runs per granted handler now, so
    // each one's output is validated rather than only the last.
    auto applyBack = [&](const QJSValue &e) {
        const int sc = e.property("status").toInt();
        if (sc >= 100 && sc < 600) resp.statusCode = sc;
        const QString rp = e.property("reasonPhrase").toString();
        bool rpOk = rp.size() <= 128;
        for (QChar c : rp) {
            const ushort u = c.unicode();
            if (u == '\r' || u == '\n' || u == '\0' || u < 0x20) { rpOk = false; break; }
        }
        if (rpOk) resp.reasonPhrase = rp;
        resp.headers = headersFromJs(e.property("headers"));
        // Write the body back ONLY if the handler actually changed it.
        // `bodyText` is a QString, so a binary body (PNG, woff2, gzip) becomes
        // U+FFFD replacement characters on the way in and DIFFERENT bytes on the
        // way out. An unconditional write-back therefore corrupted every binary
        // response that passed a granted extension -- even one that only READ the
        // body and never assigned to it. Comparing against exactly what
        // buildEntry() handed in keeps the original bytes byte-for-byte untouched.
        //
        // This does NOT make binary bodies editable: an extension that genuinely
        // wants to rewrite one still round-trips through a lossy QString. Doing
        // that losslessly needs a separate bytes-oriented API, which is a bigger
        // change than this fix and deliberately out of scope here.
        const QString handedIn = QString::fromUtf8(resp.body);
        const QString returned = e.property("bodyText").toString();
        if (returned != handedIn) resp.body = returned.toUtf8();
    };

    for (ResponseHandler &h : m_onResponseHandlers) {
        QJSValue arg = buildEntry();
        const QJSValue r = h.fn.call({ arg });
        if (r.isError()) {
            appendLog(QString("[ext] onResponse threw: %1 at line %2")
                          .arg(r.toString()).arg(r.property("lineNumber").toInt()));
            continue;
        }
        // Observe-only: throw away the whole copy, whether the handler returned
        // a new object OR edited the one it was given.
        if (!h.mayMutate) continue;
        // Granted: honour a returned object, else the in-place edits to `arg`.
        applyBack(r.isObject() ? r : arg);
    }
    return resp;
}

} // namespace Nullock::Core

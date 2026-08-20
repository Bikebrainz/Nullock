#pragma once

#include "finding_sink.hpp"
#include "proxy_server.hpp"

#include <QJSEngine>
#include <QJSValue>
#include <QList>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

#include <atomic>
#include <memory>

class QFileSystemWatcher;   // forward — auto-reload watcher (pointer member)
class QTimer;               // forward — reload debounce (pointer member)

namespace Nullock::Core {

// Findings from nullock.reportFinding() go to an IFindingSink, which
// PassiveScanner implements and app.cpp wires in. Depending on the header-only
// interface rather than the concrete class is what lets APIs stop LINKING
// Networking -- see finding_sink.hpp for why that mattered.
class ExtensionsApiBridge;    // forward — internal
class ExtensionsUtilsBridge;  // forward — internal (published as nullock.utils)
class ExtensionsCollaboratorBridge;  // forward — internal (nullock.collaborator)
class ExtensionsStorageBridge;       // forward — internal (nullock.storage)
class OastServer;             // forward — Src/Core/APIs/Oast (same lib)
class DnsSink;                // forward — Src/Core/APIs/Oast (same lib)

// Loads JavaScript extensions from <appdata>/Nullock/Nullock/extensions/
// at startup and dispatches proxy events to them.
//
// Each .js file is evaluated once in a shared QJSEngine. Extensions
// interact via a global `nullock` object:
//
//   nullock.log("hello from my extension");
//   nullock.onResponse(function(entry) {
//       if (entry.status >= 500) nullock.log("server error: " + entry.url);
//   });
//
// Handlers CAN change what goes on the wire, but only with an explicit grant.
// An extension declares one in a line comment,
// `// nullock:permissions modify-responses`, on ANY LINE of the first 64 KiB.
// The directive must START its line (only whitespace before the `//`): the
// parser regex is line-anchored (^[ \t]*//), so a directive tacked onto the END
// of a code line does NOT grant. It is a text regex, not a JS lexer, so a `//`
// line inside a block comment or a multi-line string literal still counts --
// which is the conservative direction (it can grant a capability the author put
// in a comment, never silently miss one they declared).
//
// The two directions enforce the grant differently:
//
//   onRequest   gated at REGISTRATION -- an ungranted handler is never added
//               to m_onRequestHandlers, so it never runs and never sees
//               request headers or bodies. (It can still observe the method
//               and URL of completed exchanges through onResponse.)
//   onResponse  always registered, and RUNS regardless of grant -- observation
//               is ungated. Only the mutated result is gated.
//
// Checking a handler's return value is NOT sufficient: the argument is a
// QJSValue reference into the engine, so a handler can edit it in place and
// return nothing. Note the two directions differ here too -- doMutateResponse
// rebuilds a fresh entry per handler, while onResponseReceived and
// doMutateRequest reuse one entry across all of them.
class ExtensionsApi : public QObject {
    Q_OBJECT
    Q_PROPERTY(int      loadedCount      READ loadedCount      NOTIFY loadedChanged)
    Q_PROPERTY(QStringList loadedScripts READ loadedScripts    NOTIFY loadedChanged)
    Q_PROPERTY(QString   extensionsDir   READ extensionsDir    CONSTANT)
    Q_PROPERTY(int      logLineCount     READ logLineCount     NOTIFY logChanged)
public:
    explicit ExtensionsApi(QObject *parent = nullptr);
    ~ExtensionsApi() override;

    int loadedCount() const { return m_loadedScripts.size(); }
    QStringList loadedScripts() const { return m_loadedScripts; }
    // Per-script DECLARED capability set, canonicalised -- the whole thing, not
    // just the dangerous ones. It also carries observe-level tokens (observe,
    // log, report-findings) and any unknown/future token, which ExtensionPerms
    // keeps verbatim for forward-compatibility. So presence here, or a
    // non-empty list, does NOT imply a mutation grant: only kModifyRequests /
    // kModifyResponses appearing IN the list does. (A script that declares only
    // "observe" is present with a non-empty list and holds no mutation grant.)
    const QMap<QString, QStringList> &scriptGrants() const { return m_scriptGrants; }
    QString extensionsDir() const;
    int logLineCount() const { return m_logLines.size(); }

    // Every .js file present in the extensions dir (loaded or disabled), so the
    // UI can render the full "Installed" list with a per-extension Loaded
    // checkbox, not just the ones that evaluated.
    QStringList allScripts() const { return m_allScripts; }
    // False iff `name` is in the persisted disabled set. An extension the user
    // unchecked is present on disk + listed, but never evaluated.
    bool isExtensionEnabled(const QString &name) const { return !m_disabled.contains(name); }
    // Enable/disable a single extension by file name. Persists the choice and
    // reloads (an enable evaluates it, a disable tears it down via the normal
    // reload path) so the change takes effect immediately, the way Burp's
    // per-extension Loaded checkbox does.
    void setExtensionEnabled(const QString &name, bool enabled);

    Q_INVOKABLE QStringList recentLog(int max = 50) const;
    Q_INVOKABLE bool reload();

    // Auto-reload during development: when enabled, a filesystem watcher on the
    // extensions dir reloads (debounced) whenever a .js is added, edited, or
    // removed -- no manual Reload needed. Opt-in (Burp's per-extension model) so a
    // stateful extension isn't torn down on every unrelated file save. Default off.
    void setAutoReload(bool on);
    bool autoReload() const { return m_autoReload; }

    // Wire the passive scanner so extensions can call
    // nullock.reportFinding(severity, kind, summary, evidence, url).
    // Optional -- if unset, reportFinding() falls back to logging.
    void setScanner(IFindingSink *scanner) { m_scanner = scanner; }
    IFindingSink *scanner() const { return m_scanner; }

    // Wire the OAST sinks so extensions can mint OOB payloads + read the
    // interactions they trigger (nullock.collaborator). Optional -- unset means
    // generate() returns {} and interactions() returns []. Both live in the same
    // APIs lib, so no cross-lib callback interface is needed.
    void setOast(OastServer *oast, DnsSink *dns) { m_oast = oast; m_dns = dns; }
    OastServer *oast() const { return m_oast; }
    DnsSink    *dnsSink() const { return m_dns; }

    // Apply onRequest mutation handlers and return the (possibly modified)
    // request. Thread-safe: if called from a non-main thread it routes via
    // BlockingQueuedConnection so the JS engine still runs on its owner
    // thread.
    Nullock::Proxy::HttpRequest applyRequestMutation(
        const Nullock::Proxy::HttpRequest &req);

    Nullock::Proxy::HttpResponse applyResponseMutation(
        const Nullock::Proxy::HttpRequest &req,
        const Nullock::Proxy::HttpResponse &resp);

public slots:
    // Wire to ProxyServer::responseReceived.
    void onResponseReceived(const Nullock::Proxy::HttpRequest &request,
                            const Nullock::Proxy::HttpResponse &response);

    // Internal: called via BlockingQueuedConnection by applyRequestMutation /
    // applyResponseMutation. Must execute on the engine's own thread.
    Nullock::Proxy::HttpRequest doMutateRequest(Nullock::Proxy::HttpRequest req);
    Nullock::Proxy::HttpResponse doMutateResponse(
        Nullock::Proxy::HttpRequest req,
        Nullock::Proxy::HttpResponse resp);

signals:
    void loadedChanged();
    void logChanged();

private:
    friend class ExtensionsApiBridge;

    void loadAll();
    // Drop every QJSValue we hold, then replace the engine with a fresh one and
    // re-publish the `nullock` bridge on its global object. Owner thread only,
    // and NEVER while JS is executing -- destroying an engine from inside a
    // handler it is running would pull the stack out from under itself.
    void rebuildEngine();
    // Invoke every registered nullock.onUnload handler once, on the owner thread,
    // while the engine is still alive -- called at the START of reload() (before
    // rebuildEngine tears the engine down) and from the destructor (app exit), so
    // a script always gets its teardown callback before its world disappears.
    // Does not clear the list; rebuildEngine() clears it (QJSValue-lifetime).
    void runUnloadHandlers();
    void appendLog(const QString &message);
    // Re-publish the worker-visible handler flags. MUST be called on this
    // object's own thread after ANY change to the two handler lists.
    void refreshHandlerFlags();

    // An onResponse handler carries whether its extension was granted the
    // "modify-responses" capability -- observation always runs, but a mutated
    // return value is only applied when mayMutate is true.
    struct ResponseHandler {
        QJSValue fn;
        bool     mayMutate = false;
    };

    // A recorded proxy exchange, kept so an extension can read RECENT history
    // (nullock.history()) rather than only the single live entry it sees per
    // response. Plain C++ (not a QJSValue) so it survives an engine rebuild and
    // needs no engine to store. Bounded ring; oldest dropped.
    struct HistoryEntry {
        qint64  atMs = 0;
        QString method;
        QString host;
        int     port = 0;
        QString path;
        QString url;
        bool    tls = false;
        int     status = 0;
        int     responseSize = 0;
    };

    // Held by pointer so reload() can DESTROY and rebuild it. A QJSEngine has
    // no "clear the global scope" operation, and collectGarbage() only frees
    // what is already unreachable -- everything an extension assigned to a
    // global, and every prototype it patched, survives it. Since the engine is
    // shared by all extensions, that meant an UNINSTALLED script's side effects
    // stayed live and reachable until the process restarted. Rebuilding is the
    // only way to make "remove" mean removed.
    //
    // Safe to swap because m_bridge is parented to this ExtensionsApi, so
    // newQObject() gives it CppOwnership and the old engine's destructor does
    // not take it. Every QJSValue this class stores must be cleared BEFORE the
    // reset -- a QJSValue outliving its engine is undefined behaviour.
    std::unique_ptr<QJSEngine> m_engine;
    ExtensionsApiBridge *m_bridge = nullptr;
    ExtensionsUtilsBridge *m_utils = nullptr;   // published as nullock.utils each rebuild
    ExtensionsCollaboratorBridge *m_collab = nullptr;  // published as nullock.collaborator
    ExtensionsStorageBridge *m_storage = nullptr;      // published as nullock.storage
    OastServer *m_oast = nullptr;   // OOB HTTP sink (optional)
    DnsSink    *m_dns  = nullptr;   // OOB DNS sink (optional)
    IFindingSink        *m_scanner = nullptr;
    // Touched ONLY on this object's own thread: registered during script
    // evaluation, cleared by reload(), read by doMutateRequest/doMutateResponse
    // (which the proxy worker threads reach through a BlockingQueuedConnection).
    QList<ResponseHandler> m_onResponseHandlers;
    QList<QJSValue>      m_onRequestHandlers;   // only permitted extensions get in
    // Teardown callbacks (nullock.onUnload). Owner-thread only, like the lists
    // above: registered during evaluate(), fired by runUnloadHandlers() before an
    // engine rebuild/app-exit, cleared by rebuildEngine(). Ungated -- a teardown
    // callback is observe-level (it can't reach the wire). Not mirrored to a
    // worker atomic: unlike onRequest/onResponse, no proxy worker ever consults
    // it -- it fires only on the owner thread at reload/exit.
    QList<QJSValue>      m_onUnloadHandlers;

    // Recent proxy exchanges for nullock.history(). Recorded in onResponseReceived
    // on this object's own thread and read by the bridge's history() during JS
    // execution on the SAME thread -- so, like the handler lists, no mutex. NOT
    // cleared on an engine rebuild: history is proxy traffic, independent of the
    // extension lifetime, so a reloaded script still sees what came before.
    QList<HistoryEntry>  m_history;
    static constexpr int kMaxHistory = 500;

    // Worker-readable mirrors of "is that list non-empty".
    //
    // applyRequestMutation/applyResponseMutation run on the CALLING thread -- a
    // proxy per-client thread or a QtConcurrent worker -- and used to answer
    // their early-out by reading the QLists directly, BEFORE the thread hop that
    // exists to make those lists safe to touch. A concurrent reload() clears and
    // re-appends them on the owner thread, so the fast path was an unsynchronised
    // read of a container being reallocated: undefined behaviour, and in the
    // benign direction a false "empty" that silently skips every extension for
    // that message. Workers now read these atomics and never touch the lists.
    std::atomic<bool>    m_hasRequestHandlers { false };
    std::atomic<bool>    m_hasResponseHandlers { false };
    QStringList          m_loadedScripts;
    QStringList          m_logLines;
    // Capabilities granted to the extension currently being evaluated (set
    // before each evaluate() in loadAll); the bridge reads it at registration.
    QSet<QString>        m_currentGrants;
    // Per-script granted capabilities, for display / the API.
    QMap<QString, QStringList> m_scriptGrants;

    // Every .js in the extensions dir at the last loadAll() (loaded OR disabled),
    // sorted; and the persisted set of file names the user disabled. m_disabled is
    // read from <extensionsDir>/.nullock-disabled.json at loadAll() and rewritten
    // by setExtensionEnabled(). Owner-thread only, like the other lists.
    QStringList          m_allScripts;
    QSet<QString>        m_disabled;
    void loadDisabledSet();   // read .nullock-disabled.json into m_disabled
    void saveDisabledSet();   // write m_disabled back out

    // Auto-reload plumbing. m_watcher watches the extensions dir + each .js;
    // m_reloadDebounce coalesces the burst of events an editor's save produces
    // into a single reload(). refreshWatch() re-syncs the watched paths after a
    // reload (files are commonly deleted+recreated on save, dropping the watch).
    bool                 m_autoReload = false;
    QFileSystemWatcher  *m_watcher = nullptr;
    QTimer              *m_reloadDebounce = nullptr;
    void refreshWatch();
};

// The C++ object the JS side calls into. Lives inside ExtensionsApi.
class ExtensionsApiBridge : public QObject {
    Q_OBJECT
public:
    explicit ExtensionsApiBridge(ExtensionsApi *parent);

    // Exposed to JS as nullock.log("…")
    Q_INVOKABLE void log(const QString &message);

    // Exposed to JS as nullock.onResponse(function(entry) { ... })
    Q_INVOKABLE void onResponse(const QJSValue &callback);

    // Exposed to JS as nullock.onRequest(function(entry) { return modified; })
    // Returning a modified entry (with new headers/body/method/path) actually
    // changes what gets forwarded upstream.
    Q_INVOKABLE void onRequest(const QJSValue &callback);

    // Exposed to JS as nullock.onUnload(function() { ... }). The callback runs
    // once, on the owner thread, just BEFORE this extension is torn down -- on a
    // reload/uninstall (reload() rebuilds the engine) and on app exit. It's the
    // hook for a script to flush its own state, close a resource, or log that it
    // stopped; the JS engine is still alive when it fires. No grant is required
    // (a teardown callback cleans up the script's OWN state -- it can't touch the
    // wire), so it registers like onResponse observation. Burp calls this
    // registerUnloadingHandler; that name is provided below as an alias.
    Q_INVOKABLE void onUnload(const QJSValue &callback);

    // Burp-API-parity alias for onUnload (Burp: registerUnloadingHandler).
    Q_INVOKABLE void registerUnloadingHandler(const QJSValue &callback);

    // Exposed to JS as nullock.history(max) -- the most recent proxy exchanges
    // (newest last), each an object { atMs, method, host, port, path, url, tls,
    // status, responseSize }. max<=0 (or omitted) returns all retained (capped at
    // kMaxHistory). Read-only and ungated: it is the same traffic an onResponse
    // handler already observes, just retained so a scan/recon extension can look
    // back over what was captured instead of accumulating it by hand. Burp's
    // api.proxy().history() equivalent.
    Q_INVOKABLE QVariantList history(int max = 0) const;

    // Exposed to JS as
    //   nullock.reportFinding(severity, kind, summary, evidence, url)
    // Emits a finding into the same panel the passive scanner uses, so an
    // extension's findings get the same CWE/OWASP/CVSS enrichment and show
    // up in reports / exports. If no scanner is wired it falls back to log.
    // host is derived from the url. rowId is 0 (extension-originated, no
    // single history row).
    Q_INVOKABLE void reportFinding(const QString &severity,
                                   const QString &kind,
                                   const QString &summary,
                                   const QString &evidence,
                                   const QString &url);

private:
    ExtensionsApi *m_owner;
};

// Published as nullock.utils -- Burp's api.utilities() equivalent. A grouped set
// of pure codec/hash primitives so extensions stop hand-rolling base64/hex/hashing
// in ES5. Ungated (pure text transforms, no I/O, no wire access). Parented to
// ExtensionsApi so it outlives any engine reload() destroys; re-published on the
// fresh engine by rebuildEngine(). Every method is a thin wrapper over the pure,
// unit-tested Nullock::Core::ExtUtils functions.
class ExtensionsUtilsBridge : public QObject {
    Q_OBJECT
public:
    explicit ExtensionsUtilsBridge(QObject *parent = nullptr) : QObject(parent) {}

    Q_INVOKABLE QString base64Encode(const QString &s) const;
    Q_INVOKABLE QString base64Decode(const QString &s) const;
    Q_INVOKABLE QString urlEncode(const QString &s) const;
    Q_INVOKABLE QString urlDecode(const QString &s) const;
    Q_INVOKABLE QString hexEncode(const QString &s) const;
    Q_INVOKABLE QString hexDecode(const QString &s) const;
    Q_INVOKABLE QString htmlEncode(const QString &s) const;
    Q_INVOKABLE QString htmlDecode(const QString &s) const;
    Q_INVOKABLE QString sha256(const QString &s) const;
    Q_INVOKABLE QString sha1(const QString &s) const;
    Q_INVOKABLE QString md5(const QString &s) const;
};

// Published as nullock.collaborator -- Burp's api.collaborator() equivalent. Lets
// an extension mint an out-of-band payload and later read the interactions that
// payload triggered (SSRF/blind-injection/XXE proofs). Parented to ExtensionsApi
// (CppOwnership) so it survives an engine reload() and keeps the set of tokens it
// generated; re-published on the fresh engine by rebuildEngine().
class ExtensionsCollaboratorBridge : public QObject {
    Q_OBJECT
public:
    explicit ExtensionsCollaboratorBridge(ExtensionsApi *owner);

    // Mint an OOB payload. Returns the minted object { token, hostUrl, pathUrl,
    // port, baseHost } (embed hostUrl/pathUrl, or build "<token>.<baseHost>"
    // yourself). Records the token so interactions() can scope to it. {} if no
    // OAST sink is wired.
    Q_INVOKABLE QVariantMap generate() const;

    // Every OOB interaction (HTTP + DNS) seen so far for a token THIS object
    // minted, newest last: { id, token, type ("http"|"dns"), sourceIp, atMs,
    // host, method, path }. The extension dedups by id / filters by its own
    // token. [] if no sink is wired.
    Q_INVOKABLE QVariantList interactions() const;

private:
    ExtensionsApi *m_owner;
    mutable QSet<QString> m_tokens;   // tokens this collaborator minted
};

// Published as nullock.storage -- Burp's persistence().extensionData() equivalent.
// A key/value store extensions use to keep settings/state across restarts (JSON
// values: strings, numbers, bools, arrays, objects). GLOBAL across extensions
// (Nullock runs them in one shared engine, so there is no per-extension identity
// at call time) -- extensions namespace their own keys. Persisted to a file OUTSIDE
// the watched extensions dir so a set() never trips auto-reload. Parented to
// ExtensionsApi (CppOwnership) so it survives an engine reload().
class ExtensionsStorageBridge : public QObject {
    Q_OBJECT
public:
    explicit ExtensionsStorageBridge(QObject *parent = nullptr);

    Q_INVOKABLE void     set(const QString &key, const QVariant &value);
    Q_INVOKABLE QVariant get(const QString &key, const QVariant &def = QVariant()) const;
    Q_INVOKABLE bool     has(const QString &key) const { return m_data.contains(key); }
    Q_INVOKABLE QStringList keys() const { return m_data.keys(); }
    Q_INVOKABLE void     remove(const QString &key);
    Q_INVOKABLE void     clear();

private:
    QString  filePath() const;
    void     load();
    void     save() const;
    QVariantMap m_data;
    bool        m_loaded = false;
};

} // namespace Nullock::Core

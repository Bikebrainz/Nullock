#pragma once

#include "proxy_server.hpp"

#include <QJSEngine>
#include <QJSValue>
#include <QList>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

class PassiveScanner;       // forward — wired by app.cpp so JS extensions
                            // can emit findings via nullock.reportFinding()
class ExtensionsApiBridge;  // forward — internal

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
// Read-only for v1 -- the entry passed to onResponse is a snapshot, not a
// live mutable object. Returning a modified copy doesn't change the proxy
// behavior. (Mutation hooks are a future iteration.)
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
    // Per-script granted dangerous capabilities (modify-requests/responses).
    // A script absent here (or mapped to empty) holds no mutation grant.
    const QMap<QString, QStringList> &scriptGrants() const { return m_scriptGrants; }
    QString extensionsDir() const;
    int logLineCount() const { return m_logLines.size(); }

    Q_INVOKABLE QStringList recentLog(int max = 50) const;
    Q_INVOKABLE bool reload();

    // Wire the passive scanner so extensions can call
    // nullock.reportFinding(severity, kind, summary, evidence, url).
    // Optional -- if unset, reportFinding() falls back to logging.
    void setScanner(PassiveScanner *scanner) { m_scanner = scanner; }
    PassiveScanner *scanner() const { return m_scanner; }

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
    void appendLog(const QString &message);

    // An onResponse handler carries whether its extension was granted the
    // "modify-responses" capability -- observation always runs, but a mutated
    // return value is only applied when mayMutate is true.
    struct ResponseHandler {
        QJSValue fn;
        bool     mayMutate = false;
    };

    QJSEngine            m_engine;
    ExtensionsApiBridge *m_bridge = nullptr;
    PassiveScanner      *m_scanner = nullptr;
    QList<ResponseHandler> m_onResponseHandlers;
    QList<QJSValue>      m_onRequestHandlers;   // only permitted extensions get in
    QStringList          m_loadedScripts;
    QStringList          m_logLines;
    // Capabilities granted to the extension currently being evaluated (set
    // before each evaluate() in loadAll); the bridge reads it at registration.
    QSet<QString>        m_currentGrants;
    // Per-script granted capabilities, for display / the API.
    QMap<QString, QStringList> m_scriptGrants;
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

} // namespace Nullock::Core

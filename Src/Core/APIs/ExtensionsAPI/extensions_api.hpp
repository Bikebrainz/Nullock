#pragma once

#include "proxy_server.hpp"

#include <QJSEngine>
#include <QJSValue>
#include <QList>
#include <QObject>
#include <QString>

namespace Nullock::Core {

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
    QString extensionsDir() const;
    int logLineCount() const { return m_logLines.size(); }

    Q_INVOKABLE QStringList recentLog(int max = 50) const;
    Q_INVOKABLE bool reload();

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

    QJSEngine            m_engine;
    ExtensionsApiBridge *m_bridge = nullptr;
    QList<QJSValue>      m_onResponseHandlers;
    QList<QJSValue>      m_onRequestHandlers;
    QStringList          m_loadedScripts;
    QStringList          m_logLines;
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

private:
    ExtensionsApi *m_owner;
};

} // namespace Nullock::Core

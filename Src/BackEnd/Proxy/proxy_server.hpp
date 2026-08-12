#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QDateTime>
#include <QHostAddress>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QPair>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <atomic>

class QTcpServer;
class QTcpSocket;
class QThread;

namespace Nullock::Core {
class ExtensionsApi;
class SessionManager;
class SessionRules;
}

namespace Nullock::Proxy {

class InterceptController;

class CertAuthority;

struct HttpRequest {
    QString method;
    QString target;
    QString httpVersion;
    QString host;
    quint16 port = 80;
    bool    tls = false;   // client leg encrypted? (set true on the MITM'd HTTPS path)
    QString path;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
    QDateTime timestamp;
};

struct HttpResponse {
    QString httpVersion;
    int statusCode = 0;
    QString reasonPhrase;
    QList<QPair<QString, QString>> headers;
    QByteArray body;         // exact wire bytes (may be gzip/deflate compressed)
    // Content-Encoding-decoded copy of `body`, for INSPECTION (history search,
    // passive scanning, evidence, reporting). Empty when the body wasn't
    // compressed or couldn't be decoded; the wire body is never altered.
    QByteArray decodedBody;
    QString peerAddress;
    bool wasTls = false;

    // The best readable view of the body: decoded when available, else raw.
    const QByteArray &bodyForInspection() const {
        return decodedBody.isEmpty() ? body : decodedBody;
    }
};

// Serialize an HttpRequest back into HTTP/1.1 wire bytes (request-line +
// headers + body) suitable for writing to an origin connection. Used by
// the proxy itself and by external replay paths in the control server.
QByteArray serializeRequestForOrigin(const HttpRequest &req);

// Match & replace rule. A list of these is applied to every in-scope
// round-trip after extensions run but before bytes go to the wire. Each
// rule targets a section of the request or response (URL, header set,
// body, status line) and rewrites it with a regex find+replace.
struct MatchReplaceRule {
    enum Section {
        ReqUrl = 0,    // operates on request.path/target
        ReqHeader = 1, // operates on each header as "Key: Value"
        ReqBody = 2,   // operates on request body (decoded text)
        RespHeader = 3,
        RespBody = 4,
        RespStatus = 5, // operates on "HTTP/1.1 200 OK"-style line
    };
    bool        enabled    = true;
    QString     name;        // user-facing label
    QString     hostGlob;    // empty = all hosts; "*.example.com" style
    Section     section     = ReqHeader;
    QString     find;        // regex
    QString     replace;     // replacement (supports backrefs \1 etc)
    bool        caseInsensitive = true;
    QString     comment;
};

class ProxyServer : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool isRunning READ isRunning NOTIFY runningChanged)
    Q_PROPERTY(quint16 listeningPort READ listeningPort NOTIFY runningChanged)
    Q_PROPERTY(int filteredCount READ filteredCount NOTIFY filteredCountChanged)
public:
    explicit ProxyServer(QObject *parent = nullptr);
    ~ProxyServer() override;

    Q_INVOKABLE bool start(const QHostAddress &address = QHostAddress::LocalHost,
                           quint16 port = 8080);
    // Stops ACCEPTING. Deliberately does NOT join in-flight workers -- this is
    // the UI's "stop proxy" button and must not block the GUI thread for the
    // length of a parked read. Use shutdownAndJoin() for teardown.
    Q_INVOKABLE void stop();

    // Stop accepting, wake every in-flight worker, and JOIN them.
    //
    // MUST be called while every object a Connection reaches through m_server
    // is still alive -- the extensions/intercept/model/scanner objects are
    // stack locals declared AFTER `proxy` in main(), so they are destroyed
    // BEFORE ~ProxyServer() runs. Joining in the destructor is too late; by
    // then a worker has already been dereferencing destroyed storage.
    // Idempotent.
    void shutdownAndJoin();

    // Polled by the worker threads between blocking reads, so teardown is
    // bounded by a wait SLICE rather than by a full kReadTimeoutMs per parked
    // connection. Inline: this is read in the read loops' hot path.
    bool isShuttingDown() const {
        return m_shuttingDown.load(std::memory_order_acquire);
    }

    // Same flag, handed to the h2 clients so their pump loops can poll it too.
    // Their blocking waits live in http2_client.cpp / h2_server.cpp, which have
    // no business knowing what a ProxyServer is -- they take a bare atomic.
    // Safe to hold: the server outlives every Connection by construction of
    // shutdownAndJoin().
    const std::atomic<bool> *shutdownFlag() const { return &m_shuttingDown; }

    bool isRunning() const;
    quint16 listeningPort() const;

    void setCertAuthority(CertAuthority *ca);
    CertAuthority *certAuthority() const;

    void setInterceptController(InterceptController *ic);
    InterceptController *interceptController() const;

    void setExtensions(Nullock::Core::ExtensionsApi *ext);
    Nullock::Core::ExtensionsApi *extensions() const;

    void setSessionManager(Nullock::Core::SessionManager *sm);
    Nullock::Core::SessionManager *sessionManager() const;

    void setSessionRules(Nullock::Core::SessionRules *sr);
    Nullock::Core::SessionRules *sessionRules() const;

    // Hosts we will no longer try to MITM: future CONNECTs skip the forged-cert
    // dance and blind-tunnel instead.
    //
    // Cert pinning is only ONE of the four things that put a host in here, and
    // the upstream never sees our forged leaf at all (we validate the real
    // origin chain with VerifyPeer), so the old "the client (or upstream)
    // refused our forged certificate" was wrong about most of them. The actual
    // triggers, all five call sites of markMitmBlocked():
    //   * the CLIENT rejected our leaf -- genuine pinning
    //   * the upstream TLS handshake failed, timed out, or failed VerifyPeer
    //   * the upstream negotiated an ALPN protocol we do not speak
    //   * an h2 upstream session died at connection level before serving
    //     anything (!served)
    //
    // PERSISTENT, and that matters: markMitmBlocked() writes the list to
    // m_blocklistPath and setBlocklistPath() reads it back at startup, so an
    // entry survives restarts until clearMitmBlocked(). A single slow origin
    // that blows the 3 s handshake budget therefore turns interception off for
    // that host permanently and silently -- which for a security tool is a
    // worse failure than the timeout was. See the task filed against this.
    bool isMitmBlocked(const QString &host) const;
    void markMitmBlocked(const QString &host);
    Q_INVOKABLE QStringList blockedHosts() const;
    Q_INVOKABLE void clearMitmBlocked();

    // How many round-trips the scope filter has dropped from the history
    // since startup. Exposed so the status bar can surface "you're not
    // seeing nothing, you're seeing N filtered out".
    Q_INVOKABLE int filteredCount() const { return m_filteredCount.loadAcquire(); }
    void noteFiltered();

    // How many MITM tunnels bridged an h1 browser to an "h2" upstream.
    // Incremented ONCE per tunnel, as soon as the upstream ALPN comes back
    // "h2" and before any request is sent -- NOT per round-trip, since the
    // keep-alive loop below it multiplexes N requests per increment. The
    // --h2-termination path never increments it at all, even though it also
    // drives H2Client upstream, because it returns earlier.
    // Read it as "did the h1->h2 bridge fire at all", which is how the smoke
    // test uses it -- not as a traffic counter.
    Q_INVOKABLE int h2UpstreamCount() const { return m_h2UpstreamCount.loadAcquire(); }
    void noteH2Upstream();

    // Experimental (Phase 3, OFF by default): terminate the BROWSER's HTTP/2 too
    // (advertise h2 on the server-side ALPN + run a server nghttp2 session), so a
    // browser multiplexes one connection to the proxy. Enabled with
    // --h2-termination. Set once at startup, read on worker threads.
    void setH2Termination(bool on) { m_h2Termination = on; }
    bool h2Termination() const { return m_h2Termination; }

    // Set a file path where the blocked-host list is persisted. The file is
    // loaded immediately and rewritten on every mark/clear. Plain text, one
    // host per line.
    void setBlocklistPath(const QString &path);

    // Scope filter. Out-of-scope hosts are still proxied (so the browser
    // works), but they're never MITM'd and never reach the GUI history.
    // Globs use shell-style * wildcards, e.g. "*.example.com".
    // If inScope is empty, everything is treated as in-scope subject to the
    // outOfScope exclusion list.
    void setScope(const QStringList &inScope, const QStringList &outOfScope);
    bool isInScope(const QString &host) const;

    // Match & replace rules: applied after extensions, before bytes go on
    // the wire. Set() replaces the whole list atomically; project store
    // owns the persisted copy and re-fires this on every edit.
    void setRules(const QList<MatchReplaceRule> &rules);
    QList<MatchReplaceRule> rules() const;
    int  rulesHit() const { return m_rulesHit.loadAcquire(); }
    void applyRequestRules(HttpRequest &req) const;
    void applyResponseRules(const HttpRequest &req, HttpResponse &resp) const;

signals:
    void started(quint16 port);
    void stopped();
    void runningChanged();
    void requestReceived(const Nullock::Proxy::HttpRequest &request);
    void responseReceived(const Nullock::Proxy::HttpRequest &request,
                          const Nullock::Proxy::HttpResponse &response);
    void errorOccurred(const QString &message);
    void filteredCountChanged();
    // Emitted by shutdownAndJoin(). The nested relay QEventLoops in
    // runRawRelay/runWebSocketRelay connect it to quit(); the connection is
    // queued into the worker thread and that loop IS the worker's event loop,
    // so it dispatches promptly. This is what bounds the join for a blind
    // tunnel or WebSocket, which otherwise parks a worker for the whole
    // session with no read timeout to expire.
    void shuttingDown();

private slots:
    void onNewConnection();

private:
    // Swap the tracked threads out under m_threadsMutex, then wait OUTSIDE it.
    // pump=true dispatches this thread's event queue between wait() polls,
    // which is REQUIRED whenever a worker may be parked in a
    // BlockingQueuedConnection into this thread. Only the destructor backstop
    // passes false, because by then the queued slots' receivers are gone.
    void joinWorkers(bool pump);

    // Rewrite the blocklist file from the live set, serialized against every
    // other writer. Call WITHOUT m_blockMutex held -- see the definition for
    // the lock order and the race it closes.
    void persistBlocklist();

    QTcpServer *m_server;
    CertAuthority *m_ca = nullptr;
    InterceptController *m_intercept = nullptr;
    Nullock::Core::ExtensionsApi *m_extensions = nullptr;
    Nullock::Core::SessionManager *m_sessionManager = nullptr;
    Nullock::Core::SessionRules   *m_sessionRules   = nullptr;
    bool m_h2Termination = false;   // --h2-termination (Phase 3, experimental)
    mutable QMutex m_blockMutex;
    QSet<QString> m_mitmBlocked;
    QString m_blocklistPath;
    // Serializes the blocklist FILE, separately from the set above. Two locks
    // rather than one because the set is read on the CONNECT hot path
    // (isMitmBlocked) and must never wait behind a disk write. Lock order is
    // always m_blocklistFileMutex -> m_blockMutex; never the reverse.
    mutable QMutex m_blocklistFileMutex;
    mutable QMutex m_scopeMutex;
    QList<QRegularExpression> m_inScope;
    QList<QRegularExpression> m_outOfScope;
    QAtomicInt m_filteredCount {0};
    QAtomicInt m_h2UpstreamCount {0};
    mutable QMutex m_rulesMutex;
    QList<MatchReplaceRule> m_rules;
    // Parallel to m_rules: holds the pre-compiled regex for each rule's
    // `find` and `hostGlob`. Building QRegularExpression once per rule
    // and reusing it on every request avoids ~500k regex compiles/sec
    // under typical traffic. Filled by setRules(), used by apply*Rules.
    struct CompiledRule {
        QRegularExpression find;       // null pattern => skip rule
        QRegularExpression host;       // null pattern => match all hosts
        bool               hostAll = true;
    };
    QList<CompiledRule> m_compiledRules;
    mutable QAtomicInt m_rulesHit {0};

    // --- worker-thread ownership -----------------------------------------
    // onNewConnection() spawns one QThread per accepted socket. These used to
    // be detached (created, connect(finished -> deleteLater), forgotten), so
    // nothing stopped them and nothing joined them: at teardown main()'s
    // locals unwound while workers were still calling m_server->...,
    // m_server->extensions()->... and m_server->interceptController()->...
    // Worse, once app->exec() has returned there is no main event loop left,
    // so that deleteLater could never be dispatched -- it was not actually a
    // retirement mechanism at all. Same lesson as port_scanner.cpp.
    //
    // The list is now owned here. Finished threads are reaped on the next
    // accept; joinWorkers() swaps the list out under the mutex and waits
    // OUTSIDE it. The reason for swapping is NOT that a worker might take this
    // mutex -- no worker ever does; the only two takers are onNewConnection()
    // and joinWorkers(), both on this object's own thread. It is that the join
    // PUMPS the event queue while it waits, and a dispatched newConnection
    // would re-enter onNewConnection() and take the mutex again.
    std::atomic<bool>  m_shuttingDown { false };
    mutable QMutex     m_threadsMutex;
    QList<QThread *>   m_threads;
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::HttpRequest)
Q_DECLARE_METATYPE(Nullock::Proxy::HttpResponse)

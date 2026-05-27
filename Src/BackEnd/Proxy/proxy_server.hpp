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

class QTcpServer;
class QTcpSocket;

namespace Nullock::Core {
class ExtensionsApi;
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
    QByteArray body;
    QString peerAddress;
    bool wasTls = false;
};

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
    Q_INVOKABLE void stop();
    bool isRunning() const;
    quint16 listeningPort() const;

    void setCertAuthority(CertAuthority *ca);
    CertAuthority *certAuthority() const;

    void setInterceptController(InterceptController *ic);
    InterceptController *interceptController() const;

    void setExtensions(Nullock::Core::ExtensionsApi *ext);
    Nullock::Core::ExtensionsApi *extensions() const;

    // Hosts where we tried to MITM but the client (or upstream) refused our
    // forged certificate — typically apps that do cert pinning. Future
    // CONNECTs to these hosts skip the MITM and use a blind tunnel instead.
    bool isMitmBlocked(const QString &host) const;
    void markMitmBlocked(const QString &host);
    Q_INVOKABLE QStringList blockedHosts() const;
    Q_INVOKABLE void clearMitmBlocked();

    // How many round-trips the scope filter has dropped from the history
    // since startup. Exposed so the status bar can surface "you're not
    // seeing nothing, you're seeing N filtered out".
    Q_INVOKABLE int filteredCount() const { return m_filteredCount.loadAcquire(); }
    void noteFiltered();

    // How many round-trips have actually gone through the HTTP/2 upstream
    // path (i.e. upstream ALPN came back as "h2" and H2Client handled the
    // request). Useful for verifying the h2 bridge is exercised in tests.
    Q_INVOKABLE int h2UpstreamCount() const { return m_h2UpstreamCount.loadAcquire(); }
    void noteH2Upstream();

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

private slots:
    void onNewConnection();

private:
    QTcpServer *m_server;
    CertAuthority *m_ca = nullptr;
    InterceptController *m_intercept = nullptr;
    Nullock::Core::ExtensionsApi *m_extensions = nullptr;
    mutable QMutex m_blockMutex;
    QSet<QString> m_mitmBlocked;
    QString m_blocklistPath;
    mutable QMutex m_scopeMutex;
    QList<QRegularExpression> m_inScope;
    QList<QRegularExpression> m_outOfScope;
    QAtomicInt m_filteredCount {0};
    QAtomicInt m_h2UpstreamCount {0};
    mutable QMutex m_rulesMutex;
    QList<MatchReplaceRule> m_rules;
    mutable QAtomicInt m_rulesHit {0};
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::HttpRequest)
Q_DECLARE_METATYPE(Nullock::Proxy::HttpResponse)

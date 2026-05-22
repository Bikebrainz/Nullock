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
    mutable QMutex m_blockMutex;
    QSet<QString> m_mitmBlocked;
    QString m_blocklistPath;
    mutable QMutex m_scopeMutex;
    QList<QRegularExpression> m_inScope;
    QList<QRegularExpression> m_outOfScope;
    QAtomicInt m_filteredCount {0};
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::HttpRequest)
Q_DECLARE_METATYPE(Nullock::Proxy::HttpResponse)

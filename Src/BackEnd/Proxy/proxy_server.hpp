#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QPair>
#include <QString>

class QTcpServer;
class QTcpSocket;

namespace Nullock::Proxy {

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
public:
    explicit ProxyServer(QObject *parent = nullptr);
    ~ProxyServer() override;

    bool start(const QHostAddress &address = QHostAddress::LocalHost,
               quint16 port = 8080);
    void stop();
    bool isRunning() const;
    quint16 listeningPort() const;

signals:
    void started(quint16 port);
    void stopped();
    void requestReceived(const Nullock::Proxy::HttpRequest &request);
    void responseReceived(const Nullock::Proxy::HttpRequest &request,
                          const Nullock::Proxy::HttpResponse &response);
    void errorOccurred(const QString &message);

private slots:
    void onNewConnection();

private:
    QTcpServer *m_server;
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::HttpRequest)
Q_DECLARE_METATYPE(Nullock::Proxy::HttpResponse)

#include "proxy_server.hpp"

#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>

namespace Nullock::Proxy {

namespace {

constexpr int kReadTimeoutMs = 15'000;
constexpr int kMaxHeaderBytes = 64 * 1024;

bool readHeaderBlock(QTcpSocket *socket, QByteArray &out) {
    while (!out.contains("\r\n\r\n")) {
        if (out.size() > kMaxHeaderBytes) return false;
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kReadTimeoutMs))
            return false;
        out.append(socket->readAll());
        if (socket->state() != QAbstractSocket::ConnectedState && !out.contains("\r\n\r\n"))
            return false;
    }
    return true;
}

bool readExact(QTcpSocket *socket, qint64 n, QByteArray &out) {
    while (out.size() < n) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kReadTimeoutMs))
            return false;
        out.append(socket->read(n - out.size()));
        if (socket->state() != QAbstractSocket::ConnectedState && out.size() < n)
            return false;
    }
    return true;
}

void readUntilClose(QTcpSocket *socket, QByteArray &out) {
    while (socket->state() == QAbstractSocket::ConnectedState) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kReadTimeoutMs))
            break;
        out.append(socket->readAll());
    }
    out.append(socket->readAll());
}

bool readChunkedBody(QTcpSocket *socket, QByteArray &buffer, QByteArray &decoded) {
    while (true) {
        int crlf = buffer.indexOf("\r\n");
        while (crlf < 0) {
            if (!socket->waitForReadyRead(kReadTimeoutMs)) return false;
            buffer.append(socket->readAll());
            crlf = buffer.indexOf("\r\n");
        }
        QByteArray sizeLine = buffer.left(crlf);
        const int semi = sizeLine.indexOf(';');
        if (semi >= 0) sizeLine = sizeLine.left(semi);
        bool ok = false;
        const qint64 chunkSize = sizeLine.trimmed().toLongLong(&ok, 16);
        if (!ok) return false;
        buffer.remove(0, crlf + 2);
        if (chunkSize == 0) {
            while (buffer.indexOf("\r\n") < 0) {
                if (!socket->waitForReadyRead(kReadTimeoutMs)) return false;
                buffer.append(socket->readAll());
            }
            const int end = buffer.indexOf("\r\n");
            buffer.remove(0, end + 2);
            return true;
        }
        while (buffer.size() < chunkSize + 2) {
            if (!socket->waitForReadyRead(kReadTimeoutMs)) return false;
            buffer.append(socket->readAll());
        }
        decoded.append(buffer.left(chunkSize));
        buffer.remove(0, chunkSize + 2);
    }
}

QList<QPair<QString, QString>> parseHeaders(const QByteArray &headerBlock) {
    QList<QPair<QString, QString>> headers;
    const QList<QByteArray> lines = headerBlock.split('\n');
    for (int i = 1; i < lines.size(); ++i) {
        QByteArray line = lines[i];
        if (line.endsWith('\r')) line.chop(1);
        if (line.isEmpty()) continue;
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        headers.append({
            QString::fromLatin1(line.left(colon)).trimmed(),
            QString::fromLatin1(line.mid(colon + 1)).trimmed()
        });
    }
    return headers;
}

QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0)
            return h.second;
    return {};
}

void rewriteHostPort(HttpRequest &req) {
    const QUrl url = QUrl::fromUserInput(req.target);
    if (url.isValid() && !url.host().isEmpty()) {
        req.host = url.host();
        req.port = static_cast<quint16>(url.port(80));
        req.path = url.path(QUrl::FullyEncoded);
        if (url.hasQuery()) req.path += "?" + url.query(QUrl::FullyEncoded);
        if (req.path.isEmpty()) req.path = "/";
        return;
    }
    const QString hostHeader = findHeader(req.headers, "Host");
    const int colon = hostHeader.indexOf(':');
    if (colon >= 0) {
        req.host = hostHeader.left(colon);
        req.port = hostHeader.mid(colon + 1).toUShort();
    } else {
        req.host = hostHeader;
        req.port = 80;
    }
    req.path = req.target;
}

QByteArray serializeRequestForOrigin(const HttpRequest &req) {
    QByteArray out;
    out += req.method.toLatin1() + " " + req.path.toLatin1() + " "
         + req.httpVersion.toLatin1() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Proxy-Connection", Qt::CaseInsensitive) == 0) continue;
        out += h.first.toLatin1() + ": " + h.second.toLatin1() + "\r\n";
    }
    out += "\r\n";
    out += req.body;
    return out;
}

class Connection : public QObject {
public:
    Connection(QTcpSocket *client, ProxyServer *server)
        : QObject(server), m_client(client), m_server(server) {
        m_client->setParent(this);
        connect(m_client, &QTcpSocket::disconnected, this, &QObject::deleteLater);
    }

    void run() {
        HttpRequest req;
        req.timestamp = QDateTime::currentDateTime();
        if (!readRequest(req)) { fail("malformed request"); return; }

        if (req.method.compare("CONNECT", Qt::CaseInsensitive) == 0) {
            runTunnel(req);
            return;
        }

        rewriteHostPort(req);
        emit m_server->requestReceived(req);

        QTcpSocket upstream;
        upstream.connectToHost(req.host, req.port);
        if (!upstream.waitForConnected(kReadTimeoutMs)) {
            fail("upstream connect failed: " + upstream.errorString());
            return;
        }

        upstream.write(serializeRequestForOrigin(req));
        if (!upstream.waitForBytesWritten(kReadTimeoutMs)) {
            fail("upstream write failed");
            return;
        }

        HttpResponse resp;
        resp.peerAddress = upstream.peerAddress().toString();
        resp.wasTls = false;
        if (!readResponse(&upstream, resp)) { fail("malformed response"); return; }
        emit m_server->responseReceived(req, resp);

        m_client->write(serializeResponse(resp));
        m_client->waitForBytesWritten(kReadTimeoutMs);
        m_client->disconnectFromHost();
    }

    void runTunnel(HttpRequest &req) {
        const int colon = req.target.indexOf(':');
        if (colon <= 0) { fail("malformed CONNECT target"); return; }
        const QString host = req.target.left(colon);
        const quint16 port = req.target.mid(colon + 1).toUShort();

        m_upstream = new QTcpSocket(this);
        connect(m_upstream, &QTcpSocket::disconnected, this, &QObject::deleteLater);

        m_upstream->connectToHost(host, port);
        if (!m_upstream->waitForConnected(kReadTimeoutMs)) {
            m_client->write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
            m_client->waitForBytesWritten(kReadTimeoutMs);
            fail("tunnel connect failed: " + m_upstream->errorString());
            return;
        }

        req.host = host;
        req.port = port;
        req.path = "(tunnel)";
        emit m_server->requestReceived(req);

        HttpResponse resp;
        resp.httpVersion = "HTTP/1.1";
        resp.statusCode = 200;
        resp.reasonPhrase = "Connection Established";
        resp.peerAddress = m_upstream->peerAddress().toString();
        resp.wasTls = true;
        emit m_server->responseReceived(req, resp);

        m_client->write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (!m_client->waitForBytesWritten(kReadTimeoutMs)) {
            fail("tunnel ack write failed");
            return;
        }

        QTcpSocket *client = m_client;
        QTcpSocket *up = m_upstream;
        connect(client, &QTcpSocket::readyRead, this, [client, up]() {
            up->write(client->readAll());
        });
        connect(up, &QTcpSocket::readyRead, this, [client, up]() {
            client->write(up->readAll());
        });
    }

private:
    bool readRequest(HttpRequest &req) {
        QByteArray buf;
        if (!readHeaderBlock(m_client, buf)) return false;
        const int sep = buf.indexOf("\r\n\r\n");
        const QByteArray headerBlock = buf.left(sep);
        QByteArray rest = buf.mid(sep + 4);

        const int firstLineEnd = headerBlock.indexOf("\r\n");
        const QByteArray requestLine = (firstLineEnd >= 0)
            ? headerBlock.left(firstLineEnd) : headerBlock;
        const QList<QByteArray> parts = requestLine.split(' ');
        if (parts.size() < 3) return false;
        req.method = QString::fromLatin1(parts[0]);
        req.target = QString::fromLatin1(parts[1]);
        req.httpVersion = QString::fromLatin1(parts[2]);
        req.headers = parseHeaders(headerBlock);

        if (req.method.compare("CONNECT", Qt::CaseInsensitive) == 0) return true;

        const QString cl = findHeader(req.headers, "Content-Length");
        if (!cl.isEmpty()) {
            const qint64 n = cl.toLongLong();
            req.body = rest;
            if (req.body.size() < n) {
                QByteArray extra;
                if (!readExact(m_client, n - req.body.size(), extra)) return false;
                req.body.append(extra);
            } else {
                req.body = req.body.left(n);
            }
        }
        return true;
    }

    bool readResponse(QTcpSocket *upstream, HttpResponse &resp) {
        QByteArray buf;
        if (!readHeaderBlock(upstream, buf)) return false;
        const int sep = buf.indexOf("\r\n\r\n");
        const QByteArray headerBlock = buf.left(sep);
        QByteArray rest = buf.mid(sep + 4);

        const int firstLineEnd = headerBlock.indexOf("\r\n");
        const QByteArray statusLine = headerBlock.left(firstLineEnd);
        const int sp1 = statusLine.indexOf(' ');
        const int sp2 = statusLine.indexOf(' ', sp1 + 1);
        if (sp1 < 0 || sp2 < 0) return false;
        resp.httpVersion = QString::fromLatin1(statusLine.left(sp1));
        resp.statusCode = statusLine.mid(sp1 + 1, sp2 - sp1 - 1).toInt();
        resp.reasonPhrase = QString::fromLatin1(statusLine.mid(sp2 + 1));
        resp.headers = parseHeaders(headerBlock);

        const QString te = findHeader(resp.headers, "Transfer-Encoding");
        const QString cl = findHeader(resp.headers, "Content-Length");

        if (te.compare("chunked", Qt::CaseInsensitive) == 0) {
            QByteArray decoded;
            if (!readChunkedBody(upstream, rest, decoded)) return false;
            resp.body = decoded;
        } else if (!cl.isEmpty()) {
            const qint64 n = cl.toLongLong();
            resp.body = rest;
            if (resp.body.size() < n) {
                QByteArray extra;
                if (!readExact(upstream, n - resp.body.size(), extra)) return false;
                resp.body.append(extra);
            } else {
                resp.body = resp.body.left(n);
            }
        } else {
            QByteArray tail;
            readUntilClose(upstream, tail);
            resp.body = rest + tail;
        }
        return true;
    }

    QByteArray serializeResponse(const HttpResponse &resp) {
        QByteArray out;
        out += resp.httpVersion.toLatin1() + " "
             + QByteArray::number(resp.statusCode) + " "
             + resp.reasonPhrase.toLatin1() + "\r\n";
        bool sawContentLength = false;
        for (const auto &h : resp.headers) {
            if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
            if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) sawContentLength = true;
            out += h.first.toLatin1() + ": " + h.second.toLatin1() + "\r\n";
        }
        if (!sawContentLength)
            out += "Content-Length: " + QByteArray::number(resp.body.size()) + "\r\n";
        out += "\r\n";
        out += resp.body;
        return out;
    }

    void fail(const QString &msg) {
        emit m_server->errorOccurred(msg);
        m_client->disconnectFromHost();
    }

    QTcpSocket *m_client;
    QTcpSocket *m_upstream = nullptr;
    ProxyServer *m_server;
};

} // namespace

ProxyServer::ProxyServer(QObject *parent)
    : QObject(parent), m_server(new QTcpServer(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &ProxyServer::onNewConnection);
}

ProxyServer::~ProxyServer() = default;

bool ProxyServer::start(const QHostAddress &address, quint16 port) {
    if (m_server->isListening()) return true;
    if (!m_server->listen(address, port)) {
        emit errorOccurred(m_server->errorString());
        return false;
    }
    emit started(m_server->serverPort());
    emit runningChanged();
    return true;
}

void ProxyServer::stop() {
    if (!m_server->isListening()) return;
    m_server->close();
    emit stopped();
    emit runningChanged();
}

bool ProxyServer::isRunning() const { return m_server->isListening(); }
quint16 ProxyServer::listeningPort() const { return m_server->serverPort(); }

void ProxyServer::onNewConnection() {
    while (QTcpSocket *client = m_server->nextPendingConnection()) {
        auto *conn = new Connection(client, this);
        conn->run();
    }
}

} // namespace Nullock::Proxy

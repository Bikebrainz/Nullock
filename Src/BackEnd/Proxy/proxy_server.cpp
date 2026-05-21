#include "proxy_server.hpp"

#include "cert_authority.hpp"

#include <QEventLoop>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
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
    // No QObject parent: the Connection lives on a worker thread and
    // owning it from main-thread server would cross thread boundaries.
    // Lifetime is bound to its QThread's run() stack frame instead.
    Connection(QTcpSocket *client, ProxyServer *server)
        : QObject(nullptr), m_client(client), m_server(server) {
        m_client->setParent(this);
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
        const bool inScope = m_server->isInScope(req.host);
        if (inScope) emit m_server->requestReceived(req);

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
        if (inScope) emit m_server->responseReceived(req, resp);

        m_client->write(serializeResponse(resp));
        m_client->waitForBytesWritten(kReadTimeoutMs);
        m_client->disconnectFromHost();
    }

    void runTunnel(HttpRequest &req) {
        const int colon = req.target.indexOf(':');
        if (colon <= 0) { fail("malformed CONNECT target"); return; }
        const QString host = req.target.left(colon);
        const quint16 port = req.target.mid(colon + 1).toUShort();

        // Out-of-scope hosts: never MITM, never log. Just keep their TLS
        // opaque so the user's regular browsing doesn't break, but their
        // bank login doesn't end up in the project history either.
        const bool inScope = m_server->isInScope(host);

        QSslSocket *sslClient = qobject_cast<QSslSocket *>(m_client);
        CertAuthority *ca = m_server->certAuthority();
        LeafCert leaf;
        const bool blocked = m_server->isMitmBlocked(host);
        if (inScope && sslClient && ca && ca->hasOpenssl() && !blocked) {
            leaf = ca->leafCertFor(host);
        }

        if (leaf.valid()) {
            runMitmTunnel(req, sslClient, host, port, leaf);
        } else {
            runBlindTunnel(req, host, port, /*emitSignals=*/inScope);
        }
    }

    void runBlindTunnel(HttpRequest &req, const QString &host, quint16 port,
                        bool emitSignals = true) {
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
        if (emitSignals) emit m_server->requestReceived(req);

        HttpResponse resp;
        resp.httpVersion = "HTTP/1.1";
        resp.statusCode = 200;
        resp.reasonPhrase = "Connection Established";
        resp.peerAddress = m_upstream->peerAddress().toString();
        resp.wasTls = true;
        if (emitSignals) emit m_server->responseReceived(req, resp);

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

    void runMitmTunnel(HttpRequest &connectReq, QSslSocket *sslClient,
                       const QString &host, quint16 port, const LeafCert &leaf) {
        // 1. Ack the CONNECT before starting our server-side TLS.
        sslClient->write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (!sslClient->waitForBytesWritten(kReadTimeoutMs)) {
            fail("mitm ack write failed");
            return;
        }

        // 2. Configure the client socket to present our forged leaf as the
        //    server cert, then start the server-side TLS handshake.
        QSslCertificate cert(leaf.certPem, QSsl::Pem);
        QSslKey key(leaf.keyPem, QSsl::Rsa, QSsl::Pem);
        if (cert.isNull() || key.isNull()) {
            fail("mitm: leaf cert/key failed to parse");
            return;
        }
        QSslConfiguration cfg = sslClient->sslConfiguration();
        cfg.setLocalCertificate(cert);
        cfg.setPrivateKey(key);
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
        sslClient->setSslConfiguration(cfg);
        sslClient->startServerEncryption();
        if (!sslClient->waitForEncrypted(kReadTimeoutMs)) {
            // Client refused our forged cert -- usually cert pinning.
            // Add host to the bypass list so the next CONNECT to it skips
            // MITM and falls through to a blind tunnel.
            m_server->markMitmBlocked(host);
            fail("mitm: client TLS handshake failed (host blocked for future MITM): " + sslClient->errorString());
            return;
        }

        // 3. Open ONE upstream TLS connection and reuse it for every request
        //    the client sends inside this tunnel (HTTP/1.1 keep-alive).
        auto *upstream = new QSslSocket(this);
        m_upstream = upstream;
        connect(upstream, &QSslSocket::disconnected, this, &QObject::deleteLater);
        upstream->connectToHostEncrypted(host, port);
        if (!upstream->waitForEncrypted(kReadTimeoutMs)) {
            fail("mitm: upstream TLS handshake failed: " + upstream->errorString());
            return;
        }

        // 4. Loop: read a request, forward, read response, send back.
        //    Stop when either side closes or asks for Connection: close.
        while (sslClient->state() == QAbstractSocket::ConnectedState
               && upstream->state() == QAbstractSocket::ConnectedState) {

            HttpRequest req;
            req.timestamp = QDateTime::currentDateTime();
            if (!readRequestFrom(sslClient, req)) {
                // Empty read on a keep-alive connection is a clean close,
                // not a protocol error worth surfacing.
                break;
            }
            req.host = host;
            req.port = port;
            if (req.path.isEmpty() || !req.path.startsWith('/'))
                req.path = "/" + req.path;
            emit m_server->requestReceived(req);

            upstream->write(serializeRequestForOrigin(req));
            if (!upstream->waitForBytesWritten(kReadTimeoutMs)) {
                fail("mitm: upstream write failed");
                return;
            }

            HttpResponse resp;
            resp.peerAddress = upstream->peerAddress().toString();
            resp.wasTls = true;
            if (!readResponse(upstream, resp)) {
                fail("mitm: malformed upstream response");
                return;
            }
            emit m_server->responseReceived(req, resp);

            // Protocol switch (WebSocket etc.): forward the 101 headers plus
            // any already-buffered upgrade bytes, then bridge raw frames in
            // both directions until either side closes. Subsequent traffic
            // on this tunnel is no longer HTTP and we shouldn't try to parse
            // it as such.
            if (resp.statusCode == 101) {
                sslClient->write(serializeUpgradeResponse(resp));
                sslClient->waitForBytesWritten(kReadTimeoutMs);
                runRawRelay(sslClient, upstream);
                return;
            }

            sslClient->write(serializeResponse(resp));
            if (!sslClient->waitForBytesWritten(kReadTimeoutMs)) {
                fail("mitm: response write to client failed");
                return;
            }

            // Honor explicit Connection: close from either party. HTTP/1.0
            // defaults to close; HTTP/1.1 defaults to keep-alive.
            const QString reqConn  = findHeader(req.headers,  "Connection");
            const QString respConn = findHeader(resp.headers, "Connection");
            const bool reqWantsClose  = reqConn.compare("close",  Qt::CaseInsensitive) == 0;
            const bool respWantsClose = respConn.compare("close", Qt::CaseInsensitive) == 0;
            const bool http10 = req.httpVersion.compare("HTTP/1.0", Qt::CaseInsensitive) == 0
                             || resp.httpVersion.compare("HTTP/1.0", Qt::CaseInsensitive) == 0;
            const bool http10KeepAlive =
                reqConn.compare("keep-alive", Qt::CaseInsensitive) == 0
             && respConn.compare("keep-alive", Qt::CaseInsensitive) == 0;
            if (reqWantsClose || respWantsClose || (http10 && !http10KeepAlive))
                break;
        }

        sslClient->disconnectFromHost();
        if (upstream->state() == QAbstractSocket::ConnectedState)
            upstream->disconnectFromHost();
    }

private:
    bool readRequest(HttpRequest &req) {
        return readRequestFrom(m_client, req);
    }

    bool readRequestFrom(QTcpSocket *socket, HttpRequest &req) {
        QByteArray buf;
        if (!readHeaderBlock(socket, buf)) return false;
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
        req.path = req.target;

        if (req.method.compare("CONNECT", Qt::CaseInsensitive) == 0) return true;

        const QString cl = findHeader(req.headers, "Content-Length");
        if (!cl.isEmpty()) {
            const qint64 n = cl.toLongLong();
            req.body = rest;
            if (req.body.size() < n) {
                QByteArray extra;
                if (!readExact(socket, n - req.body.size(), extra)) return false;
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

        // 1xx and 204/304 have no body. 101 in particular signals a protocol
        // switch (typically WebSocket); the bytes after the empty line are
        // not HTTP framed, they belong to whatever protocol the upgrade
        // negotiated. Hand any leftover buffer back via resp.body so the
        // caller can flush it to the client before relaying frames.
        if (resp.statusCode == 101 || resp.statusCode == 204
            || resp.statusCode == 304 || (resp.statusCode >= 100 && resp.statusCode < 200)) {
            resp.body = rest;
            return true;
        }

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

    // Serialize a protocol-switching response (101 Switching Protocols and
    // friends): preserve the original headers verbatim and tack on any
    // already-buffered post-header bytes from upstream so the client sees
    // the start of the new protocol stream without us re-framing it.
    QByteArray serializeUpgradeResponse(const HttpResponse &resp) {
        QByteArray out;
        out += resp.httpVersion.toLatin1() + " "
             + QByteArray::number(resp.statusCode) + " "
             + resp.reasonPhrase.toLatin1() + "\r\n";
        for (const auto &h : resp.headers)
            out += h.first.toLatin1() + ": " + h.second.toLatin1() + "\r\n";
        out += "\r\n";
        out += resp.body;
        return out;
    }

    // After a 101 Switching Protocols handshake the framing is no longer
    // HTTP. Bridge raw bytes between client and upstream in both directions
    // and exit when either side closes. Uses a local QEventLoop because
    // QThread::create lambdas don't run an event loop by default.
    void runRawRelay(QTcpSocket *client, QTcpSocket *upstream) {
        QEventLoop loop;
        auto quit = [&loop] { loop.quit(); };
        connect(client,   &QTcpSocket::disconnected, &loop, quit);
        connect(upstream, &QTcpSocket::disconnected, &loop, quit);
        connect(client, &QTcpSocket::readyRead, this, [client, upstream] {
            upstream->write(client->readAll());
        });
        connect(upstream, &QTcpSocket::readyRead, this, [client, upstream] {
            client->write(upstream->readAll());
        });
        if (client->state() == QAbstractSocket::ConnectedState
            && upstream->state() == QAbstractSocket::ConnectedState)
            loop.exec();
    }

    void fail(const QString &msg) {
        emit m_server->errorOccurred(msg);
        m_client->disconnectFromHost();
    }

    QTcpSocket *m_client;
    QTcpSocket *m_upstream = nullptr;
    ProxyServer *m_server;
};

// Hand out QSslSocket instances (in unencrypted mode) for every incoming
// connection so the CONNECT handler can later call startServerEncryption()
// without having to rewrap an existing QTcpSocket.
class SslReadyTcpServer : public QTcpServer {
public:
    using QTcpServer::QTcpServer;
protected:
    void incomingConnection(qintptr handle) override {
        auto *socket = new QSslSocket(this);
        if (socket->setSocketDescriptor(handle))
            addPendingConnection(socket);
        else
            socket->deleteLater();
    }
};

} // namespace

ProxyServer::ProxyServer(QObject *parent)
    : QObject(parent), m_server(new SslReadyTcpServer(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &ProxyServer::onNewConnection);
}

void ProxyServer::setCertAuthority(CertAuthority *ca) { m_ca = ca; }
CertAuthority *ProxyServer::certAuthority() const { return m_ca; }

bool ProxyServer::isMitmBlocked(const QString &host) const {
    QMutexLocker lock(&m_blockMutex);
    return m_mitmBlocked.contains(host);
}
void ProxyServer::markMitmBlocked(const QString &host) {
    QMutexLocker lock(&m_blockMutex);
    m_mitmBlocked.insert(host);
}

void ProxyServer::setScope(const QStringList &inScope, const QStringList &outOfScope) {
    auto compile = [](const QStringList &globs) {
        QList<QRegularExpression> out;
        for (const QString &g : globs) {
            // Glob -> anchored regex with * mapped to .*, everything else literal.
            QString pattern = QRegularExpression::escape(g);
            pattern.replace("\\*", ".*");
            out.append(QRegularExpression("^" + pattern + "$",
                                          QRegularExpression::CaseInsensitiveOption));
        }
        return out;
    };
    QMutexLocker lock(&m_scopeMutex);
    m_inScope    = compile(inScope);
    m_outOfScope = compile(outOfScope);
}

bool ProxyServer::isInScope(const QString &host) const {
    QMutexLocker lock(&m_scopeMutex);
    // Out-of-scope wins.
    for (const auto &rx : m_outOfScope)
        if (rx.match(host).hasMatch()) return false;
    if (m_inScope.isEmpty()) return true;
    for (const auto &rx : m_inScope)
        if (rx.match(host).hasMatch()) return true;
    return false;
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
        // Hand each connection off to its own QThread so blocking I/O
        // (waitForReadyRead, waitForEncrypted, waitForBytesWritten) on
        // one connection doesn't stall every other one. Browsers open
        // 6-12 parallel sockets per page; without this, every resource
        // serializes through a single thread and the proxy is unusable.
        client->setParent(nullptr);

        ProxyServer *self = this;
        auto *thread = QThread::create([self, client]() {
            Connection conn(client, self);
            conn.run();
            // conn goes out of scope here; its destructor deletes the
            // client socket (parent ownership). The QThread then exits.
        });

        client->moveToThread(thread);
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
    }
}

} // namespace Nullock::Proxy

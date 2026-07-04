#include "proxy_server.hpp"

#include "cert_authority.hpp"
#include "extensions_api.hpp"
#include "http2_client.hpp"
#include "intercept.hpp"
#include "proxy_logic.hpp"
#include "session_manager.hpp"
#include "session_rules.hpp"
#include "networking.hpp"
#include "websocket.hpp"
#include "ws_repeater.hpp"

#include <QEventLoop>
#include <QFile>

#include <memory>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QSslSocket>
#include <QStringList>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QUrl>

namespace Nullock::Proxy {

namespace {

// Pure framing helpers now live in proxy_logic.cpp (unit-tested); pull them in by
// name so the existing call sites read unchanged.
using HttpLogic::findHeader;
using HttpLogic::isChunkedTransfer;
using HttpLogic::isFramingSafe;
using HttpLogic::parseHeaders;

constexpr int kReadTimeoutMs      = 15'000;
constexpr int kHandshakeTimeoutMs = 3'000;  // short so h2-only hosts bypass fast
constexpr int kMaxHeaderBytes     = 64 * 1024;

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

// parseHeaders / findHeader / isFramingSafe / isChunkedTransfer and the bounded
// chunked decoder live in proxy_logic.cpp (pure, Qt6::Core only) so they can be
// unit-tested; this socket-side wrapper just feeds bytes to the pure decoder.
bool readChunkedBody(QTcpSocket *socket, QByteArray &buffer, QByteArray &decoded) {
    using HttpLogic::ChunkResult;
    while (true) {
        const ChunkResult r = HttpLogic::decodeChunkedAvailable(buffer, decoded);
        if (r == ChunkResult::Complete) return true;
        if (r == ChunkResult::Error)    return false;   // bad / oversized / overflowing chunk
        // NeedMore: pull more wire bytes and try again.
        if (!socket->waitForReadyRead(kReadTimeoutMs)) return false;
        buffer.append(socket->readAll());
    }
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
        else         m_server->noteFiltered();

        // Let JS extensions rewrite headers / body / method / path before
        // we serialize. Mutations apply even to filtered hosts so a
        // plugin can do things like global header injection regardless
        // of scope.
        if (auto *ext = m_server->extensions())
            req = ext->applyRequestMutation(req);
        m_server->applyRequestRules(req);

        QTcpSocket upstream;
        upstream.connectToHost(req.host, req.port);
        if (!upstream.waitForConnected(kReadTimeoutMs)) {
            fail("upstream connect failed: " + upstream.errorString());
            return;
        }

        QByteArray outBytes = serializeRequestForOrigin(req);
        if (auto *ic = m_server->interceptController(); ic && inScope) {
            const InterceptResult ir = ic->pend(outBytes, req.host, req.port, /*tls=*/false);
            if (ir.dropped) {
                m_client->disconnectFromHost();
                return;
            }
            outBytes = ir.bytes;
        }
        upstream.write(outBytes);
        if (!upstream.waitForBytesWritten(kReadTimeoutMs)) {
            fail("upstream write failed");
            return;
        }

        HttpResponse resp;
        resp.peerAddress = upstream.peerAddress().toString();
        resp.wasTls = false;
        if (!readResponse(&upstream, resp)) { fail("malformed response"); return; }
        if (auto *ext = m_server->extensions())
            resp = ext->applyResponseMutation(req, resp);
        m_server->applyResponseRules(req, resp);
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
        if (!inScope) m_server->noteFiltered();

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

        // Advertise both h2 and http/1.1 ALPN to upstream. If the server
        // picks h2 we hand the request off to H2Client (libnghttp2 wrapper);
        // h1 stays in the existing keep-alive loop. Either way the browser
        // sees a transparent HTTP/1.1 response.
        QSslConfiguration upstreamCfg = upstream->sslConfiguration();
        upstreamCfg.setAllowedNextProtocols({
            QByteArrayLiteral("h2"),
            QByteArrayLiteral("http/1.1"),
        });
        // Explicitly verify the upstream chain and hostname. Default in
        // client mode is AutoVerifyPeer, but we set it explicitly here so
        // the security posture is visible at the call site. Without this,
        // a network attacker between Nullock and the real origin could
        // present a self-signed cert and we'd happily forward decrypted
        // bytes from the attacker as if they came from the real server
        // (and the browser sees a TLS-green badge because *our* forged
        // cert to the browser is valid).
        upstreamCfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
        // Browser-shaped TLS handshake to defeat tier-1 WAF
        // fingerprinting. Default profile is None == Qt defaults; set
        // via --tls-fingerprint=chrome|firefox.
        Nullock::Core::TlsProfile::apply(upstreamCfg,
            Nullock::Core::HttpClient::defaultProfile());
        upstream->setSslConfiguration(upstreamCfg);
        upstream->setPeerVerifyName(host);

        // sslErrors fires before the handshake completes. Our handler
        // records the errors for diagnostics and does NOT call
        // ignoreSslErrors(), which causes Qt to abort the handshake.
        // This is what turns a self-signed/expired/wrong-host upstream
        // cert into a connection failure instead of a silent MITM.
        QStringList tlsErrors;
        connect(upstream, &QSslSocket::sslErrors, this,
                [&tlsErrors, host](const QList<QSslError> &errs) {
            for (const auto &e : errs) {
                tlsErrors << (host + ": " + e.errorString());
            }
        });

        upstream->connectToHostEncrypted(host, port);
        if (!upstream->waitForEncrypted(kHandshakeTimeoutMs)) {
            // h2-only origins land here (handshake gets refused because we
            // only offered http/1.1 ALPN). Mark blocked so future CONNECTs
            // skip the MITM dance and pass through opaquely. Short timeout
            // means the user sees ~3s on first hit, not 15s.
            m_server->markMitmBlocked(host);
            QString reason = upstream->errorString();
            if (!tlsErrors.isEmpty()) {
                // Show the cert-level errors first -- "Hostname doesn't
                // match" or "Certificate signed by unknown authority" is
                // far more actionable than Qt's generic "TLS error".
                reason = tlsErrors.join("; ") + " :: " + reason;
            }
            fail("mitm: upstream TLS handshake failed: " + reason);
            return;
        }
        const QByteArray negotiated = upstream->sslConfiguration().nextNegotiatedProtocol();
        const bool upstreamIsH2 = (negotiated == "h2");
        if (!negotiated.isEmpty() && negotiated != "http/1.1" && !upstreamIsH2) {
            m_server->markMitmBlocked(host);
            fail("mitm: upstream negotiated unexpected ALPN: " + QString::fromLatin1(negotiated));
            return;
        }

        // ── h2 upstream path: bridge h1-client to h2-server ──────────────
        // Browser side stays HTTP/1.1 (we never advertised h2 on the
        // server socket). Read one h1 request, fire it through H2Client,
        // translate the h2 response back to h1 for the browser, close.
        // No keep-alive in this branch -- each request gets a fresh
        // tunnel. (Real h2 multiplexing is out of scope; we just want to
        // unblock h2-only origins.)
        if (upstreamIsH2) {
            m_server->noteH2Upstream();
            HttpRequest req;
            req.timestamp = QDateTime::currentDateTime();
            if (!readRequestFrom(sslClient, req)) {
                fail("mitm/h2: malformed inner request");
                return;
            }
            req.host = host;
            req.port = port;
            if (req.path.isEmpty() || !req.path.startsWith('/'))
                req.path = "/" + req.path;
            emit m_server->requestReceived(req);

            if (auto *ext = m_server->extensions())
                req = ext->applyRequestMutation(req);
            m_server->applyRequestRules(req);

            // Intercept still works -- pend before sending upstream.
            if (auto *ic = m_server->interceptController()) {
                QByteArray dummyBytes = serializeRequestForOrigin(req);
                const InterceptResult ir = ic->pend(dummyBytes, host, port, true);
                if (ir.dropped) { sslClient->disconnectFromHost(); return; }
                // For h2 we send via H2Client which takes an HttpRequest, not
                // bytes -- so we just use the (possibly user-edited) bytes to
                // re-derive the request fields. Keep it simple: re-use the
                // original req. (Editing intercept text in h2 mode is a known
                // limitation; documented in README.)
            }

            H2Client h2;
            const auto h2res = h2.sendRequest(upstream, req);
            if (!h2res.ok) {
                qWarning().noquote() << "mitm/h2 failed for" << host
                                     << ":" << h2res.errorMessage;
                m_server->markMitmBlocked(host);
                fail("mitm/h2: " + h2res.errorMessage);
                return;
            }
            HttpResponse h2resp = h2res.response;
            if (auto *ext = m_server->extensions())
                h2resp = ext->applyResponseMutation(req, h2resp);
            m_server->applyResponseRules(req, h2resp);
            emit m_server->responseReceived(req, h2resp);

            sslClient->write(serializeResponse(h2resp));
            sslClient->waitForBytesWritten(kReadTimeoutMs);
            sslClient->disconnectFromHost();
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

            if (auto *ext = m_server->extensions())
                req = ext->applyRequestMutation(req);
            m_server->applyRequestRules(req);

            QByteArray outBytes = serializeRequestForOrigin(req);
            if (auto *ic = m_server->interceptController()) {
                const InterceptResult ir = ic->pend(outBytes, host, port, /*tls=*/true);
                if (ir.dropped) {
                    sslClient->disconnectFromHost();
                    return;
                }
                outBytes = ir.bytes;
            }
            upstream->write(outBytes);
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
            if (auto *ext = m_server->extensions())
                resp = ext->applyResponseMutation(req, resp);
            m_server->applyResponseRules(req, resp);
            emit m_server->responseReceived(req, resp);

            // Protocol switch (WebSocket etc.): forward the 101 headers plus
            // any already-buffered upgrade bytes, then bridge raw frames in
            // both directions until either side closes. Subsequent traffic
            // on this tunnel is no longer HTTP and we shouldn't try to parse
            // it as such.
            if (resp.statusCode == 101) {
                sslClient->write(serializeUpgradeResponse(resp));
                sslClient->waitForBytesWritten(kReadTimeoutMs);
                const QString upgrade = findHeader(req.headers, "Upgrade");
                if (upgrade.compare("websocket", Qt::CaseInsensitive) == 0)
                    runWebSocketRelay(sslClient, upstream, host, port);
                else
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

        // Smuggling defence: refuse messages framed by both CL and TE, conflicting/
        // duplicate Content-Length, an obfuscated Transfer-Encoding, a control-byte
        // header, or ANY Transfer-Encoding on a request (no request chunked decoder).
        if (!isFramingSafe(req.headers, /*isRequest=*/true)) return false;

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

        // Smuggling defence: same CL+TE / duplicate-CL check on the
        // response. A hostile upstream that frames the body two ways at
        // once would otherwise let us pick one length and the browser
        // pick the other, splitting one response into two on the
        // keep-alive socket.
        if (!isFramingSafe(resp.headers, /*isRequest=*/false)) return false;

        const QString te = findHeader(resp.headers, "Transfer-Encoding");
        const QString cl = findHeader(resp.headers, "Content-Length");

        // Same canonical chunked decision the guard used (last coding == chunked),
        // so the guard and the decoder can't disagree about the body boundary.
        if (isChunkedTransfer(te)) {
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

    // Same shape as runRawRelay but parses each direction's bytes as
    // RFC 6455 WebSocket frames before forwarding them unchanged. Every
    // complete frame surfaces as a synthetic entry in the HTTP History
    // so the user actually sees the messages flowing through.
    void runWebSocketRelay(QTcpSocket *client, QTcpSocket *upstream,
                           const QString &host, quint16 port) {
        auto clientParser = std::make_shared<WsFrameParser>();
        auto upstreamParser = std::make_shared<WsFrameParser>();
        // Per-direction permessage-deflate (RFC 7692) state. Each direction has
        // its own DEFLATE context (shared across that direction's messages under
        // context-takeover), so it gets its own stateful inflater; the reassembly
        // buffer accumulates a fragmented message's payload until FIN.
        struct WsMsgState { bool inMsg = false; bool compressed = false;
                            quint8 opcode = 0; QByteArray buf; };
        auto clientInflater   = std::make_shared<WsInflater>();
        auto upstreamInflater = std::make_shared<WsInflater>();
        auto clientMsg   = std::make_shared<WsMsgState>();
        auto upstreamMsg = std::make_shared<WsMsgState>();
        QString hostCopy = host;
        quint16 portCopy = port;
        auto *server = m_server;

        // Register this tunnel with the WS repeater so the user can
        // inject frames from the UI / control API into either side
        // while the connection is live. Deregistered when either socket
        // closes.
        const qint64 wsId = WsRepeater::instance()->registerSession(
            client, upstream, host, port);
        connect(client,   &QTcpSocket::disconnected, this,
                [wsId]{ WsRepeater::instance()->deregisterSession(wsId); });
        connect(upstream, &QTcpSocket::disconnected, this,
                [wsId]{ WsRepeater::instance()->deregisterSession(wsId); });

        // Surface one WebSocket message (already reassembled + inflated) as a
        // synthetic History entry. `wasDeflated` records that we successfully
        // decompressed a permessage-deflate message so the UI can flag it.
        auto emitMessage = [server, hostCopy, portCopy](
                bool fromClient, quint8 opcode, bool fin,
                const QByteArray &payload, bool wasDeflated) {
            const QString label = QString::fromLatin1(wsOpcodeLabel(opcode));
            HttpRequest req;
            req.timestamp = QDateTime::currentDateTime();
            req.method = fromClient ? QStringLiteral("WS↑") : QStringLiteral("WS↓");
            req.host = hostCopy;
            req.port = portCopy;
            req.path = QString("(%1%2, %3 B%4)")
                           .arg(label)
                           .arg(wasDeflated ? QStringLiteral(" deflate") : QString())
                           .arg(payload.size())
                           .arg(fin ? "" : ", continued");
            req.body = payload;
            HttpResponse resp;
            resp.httpVersion  = "WS";
            resp.statusCode   = 101;
            resp.reasonPhrase = wasDeflated ? (label + QStringLiteral(" deflate")) : label;
            resp.wasTls       = true;
            resp.body         = payload;
            // Carry the content-type-ish info via a header so the inspector
            // body renderer treats text frames as text.
            QString mime = (opcode == 0x1)
                ? QStringLiteral("text/plain")
                : QStringLiteral("application/octet-stream");
            resp.headers.append({ QStringLiteral("Content-Type"), mime });
            emit server->requestReceived(req);
            emit server->responseReceived(req, resp);
        };

        // Reassemble a data message across fragments and, if permessage-deflate
        // marked it (RSV1 on the opening frame), inflate it before display.
        // Control frames pass straight through -- they're never fragmented or
        // compressed and must not disturb an in-flight data message.
        auto processFrame = [emitMessage](bool fromClient, WsMsgState &st,
                                          WsInflater &inf, const WsFrame &f) {
            constexpr qint64 kMaxWsMessageBytes = 64 * 1024 * 1024;  // reassembly cap
            if (f.opcode & 0x08) {                 // control frame
                emitMessage(fromClient, f.opcode, f.fin, f.payload, false);
                return;
            }
            if (f.opcode != 0x0) {                 // first frame of a data message
                st.inMsg = true;
                st.compressed = f.rsv1;
                st.opcode = f.opcode;
                st.buf = f.payload;
            } else if (st.inMsg) {                 // continuation
                st.buf.append(f.payload);
            } else {                               // stray continuation -> raw
                emitMessage(fromClient, 0x0, f.fin, f.payload, false);
                return;
            }
            if (st.buf.size() > kMaxWsMessageBytes) {   // bound reassembly memory
                emitMessage(fromClient, st.opcode, false, st.buf, false);
                st = WsMsgState{};
                return;
            }
            if (!f.fin) return;                    // more fragments pending

            QByteArray payload = st.buf;
            bool deflated = false;
            if (st.compressed) {
                bool ok = false;
                const QByteArray dec = inf.inflateMessage(st.buf, &ok);
                if (ok) { payload = dec; deflated = true; }
                // On inflate failure fall back to the raw compressed bytes so a
                // message is still visible rather than silently dropped.
            }
            emitMessage(fromClient, st.opcode, true, payload, deflated);
            st = WsMsgState{};
        };

        QEventLoop loop;
        auto quit = [&loop] { loop.quit(); };
        connect(client,   &QTcpSocket::disconnected, &loop, quit);
        connect(upstream, &QTcpSocket::disconnected, &loop, quit);

        connect(client, &QTcpSocket::readyRead, this,
            [client, upstream, clientParser, clientMsg, clientInflater, processFrame, wsId] {
                const QByteArray bytes = client->readAll();
                upstream->write(bytes);
                for (const WsFrame &f : clientParser->feed(bytes)) {
                    processFrame(true, *clientMsg, *clientInflater, f);
                    WsRepeater::instance()->noteFrame(wsId, true);
                }
            });
        connect(upstream, &QTcpSocket::readyRead, this,
            [client, upstream, upstreamParser, upstreamMsg, upstreamInflater, processFrame, wsId] {
                const QByteArray bytes = upstream->readAll();
                client->write(bytes);
                for (const WsFrame &f : upstreamParser->feed(bytes)) {
                    processFrame(false, *upstreamMsg, *upstreamInflater, f);
                    WsRepeater::instance()->noteFrame(wsId, false);
                }
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

// Pulled out of the anon namespace so other TUs (control server, replay)
// can serialize the same way the proxy does.
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

ProxyServer::ProxyServer(QObject *parent)
    : QObject(parent), m_server(new SslReadyTcpServer(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &ProxyServer::onNewConnection);
}

void ProxyServer::setCertAuthority(CertAuthority *ca) { m_ca = ca; }
CertAuthority *ProxyServer::certAuthority() const { return m_ca; }

void ProxyServer::setInterceptController(InterceptController *ic) { m_intercept = ic; }
InterceptController *ProxyServer::interceptController() const { return m_intercept; }

void ProxyServer::setExtensions(Nullock::Core::ExtensionsApi *ext) { m_extensions = ext; }
Nullock::Core::ExtensionsApi *ProxyServer::extensions() const { return m_extensions; }

void ProxyServer::setSessionManager(Nullock::Core::SessionManager *sm) { m_sessionManager = sm; }
Nullock::Core::SessionManager *ProxyServer::sessionManager() const { return m_sessionManager; }

void ProxyServer::setSessionRules(Nullock::Core::SessionRules *sr) { m_sessionRules = sr; }
Nullock::Core::SessionRules *ProxyServer::sessionRules() const { return m_sessionRules; }

bool ProxyServer::isMitmBlocked(const QString &host) const {
    QMutexLocker lock(&m_blockMutex);
    return m_mitmBlocked.contains(host);
}
void ProxyServer::markMitmBlocked(const QString &host) {
    QString pathToWrite;
    QStringList snapshot;
    {
        QMutexLocker lock(&m_blockMutex);
        if (m_mitmBlocked.contains(host)) return;
        m_mitmBlocked.insert(host);
        pathToWrite = m_blocklistPath;
        snapshot = QStringList(m_mitmBlocked.constBegin(), m_mitmBlocked.constEnd());
    }
    if (!pathToWrite.isEmpty()) {
        QFile f(pathToWrite);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            snapshot.sort();
            f.write(snapshot.join('\n').toUtf8());
            f.write("\n");
        }
    }
}

QStringList ProxyServer::blockedHosts() const {
    QMutexLocker lock(&m_blockMutex);
    QStringList out(m_mitmBlocked.constBegin(), m_mitmBlocked.constEnd());
    out.sort();
    return out;
}

void ProxyServer::clearMitmBlocked() {
    QString pathToWrite;
    {
        QMutexLocker lock(&m_blockMutex);
        m_mitmBlocked.clear();
        pathToWrite = m_blocklistPath;
    }
    if (!pathToWrite.isEmpty())
        QFile::remove(pathToWrite);
}

void ProxyServer::setBlocklistPath(const QString &path) {
    QMutexLocker lock(&m_blockMutex);
    m_blocklistPath = path;
    m_mitmBlocked.clear();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    while (!f.atEnd()) {
        const QString line = QString::fromUtf8(f.readLine()).trimmed();
        if (!line.isEmpty()) m_mitmBlocked.insert(line);
    }
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

void ProxyServer::noteFiltered() {
    m_filteredCount.fetchAndAddOrdered(1);
    emit filteredCountChanged();
}

void ProxyServer::setRules(const QList<MatchReplaceRule> &rules) {
    // Pre-compile patterns once. Massive speedup vs. re-compiling on
    // every request, and rejects truly insane patterns at edit time so
    // a malformed rule can't blow up in the request hot path.
    QList<MatchReplaceRule>           accepted;
    QList<ProxyServer::CompiledRule>  compiled;
    accepted.reserve(rules.size());
    compiled.reserve(rules.size());

    // Hard cap on individual pattern size. ~4 KB find / 4 KB replace is
    // more than any real Burp-style rule. Refuses obvious DoS payloads
    // like a 1 MB regex.
    constexpr int kMaxPatternBytes = 4096;

    for (const auto &r : rules) {
        if (r.find.size() > kMaxPatternBytes) continue;
        if (r.replace.size() > kMaxPatternBytes) continue;
        if (r.hostGlob.size() > 256) continue;

        QRegularExpression::PatternOptions opts =
            QRegularExpression::NoPatternOption
          | QRegularExpression::DontCaptureOption;
        if (r.caseInsensitive) opts |= QRegularExpression::CaseInsensitiveOption;
        QRegularExpression findRx(r.find, opts);
        if (!findRx.isValid()) continue;     // refuse malformed at edit time
        findRx.optimize();

        ProxyServer::CompiledRule cr;
        cr.find = findRx;

        if (r.hostGlob.isEmpty()) {
            cr.hostAll = true;
        } else {
            QString pattern = QRegularExpression::escape(r.hostGlob);
            pattern.replace("\\*", ".*");
            cr.host = QRegularExpression("^" + pattern + "$",
                                          QRegularExpression::CaseInsensitiveOption);
            if (!cr.host.isValid()) continue;
            cr.host.optimize();
            cr.hostAll = false;
        }

        accepted.append(r);
        compiled.append(cr);
    }

    QMutexLocker lock(&m_rulesMutex);
    m_rules          = accepted;
    m_compiledRules  = compiled;
}

QList<MatchReplaceRule> ProxyServer::rules() const {
    QMutexLocker lock(&m_rulesMutex);
    return m_rules;
}

namespace {

// Run a pre-compiled regex find/replace against `s`. Returns true if at
// least one substitution happened (so the caller can count hits / update
// Content-Length).
bool applyOne(QString &s, const MatchReplaceRule &r,
              const QRegularExpression &compiledFind) {
    if (!compiledFind.isValid()) return false;
    const QString before = s;
    s.replace(compiledFind, r.replace);
    return s != before;
}

// Keep Content-Length honest after body mutations. If a header named
// Content-Length exists, rewrite it; otherwise leave alone (chunked
// bodies will end up wrong anyway -- a known limitation surfaced via
// the rules-hit counter).
void fixContentLength(QList<QPair<QString, QString>> &headers, int newSize) {
    for (auto &h : headers) {
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) {
            h.second = QString::number(newSize);
            return;
        }
    }
}

} // namespace

void ProxyServer::applyRequestRules(HttpRequest &req) const {
    QList<MatchReplaceRule> rs;
    QList<CompiledRule>     cs;
    {
        QMutexLocker lock(&m_rulesMutex);
        rs = m_rules;
        cs = m_compiledRules;
    }

    // Scope-gate Match & Replace. A wildcard rule (host pattern ".*", which
    // is the default) would otherwise rewrite EVERY outgoing request --
    // including the user's normal browser traffic to out-of-scope hosts.
    // A rule like (Cookie: (.*) -> X-Exfil: $1) imported from a hostile
    // project file or a compromised extension would exfil cookies from
    // unrelated sites the user happens to visit while running Nullock.
    // Apply rules only to in-scope hosts (when scope is configured); the
    // per-rule host regex still narrows from there. When in-scope is
    // unset, fall through to the previous behaviour.
    if (!isInScope(req.host)) return;

    bool bodyChanged = false;
    for (int i = 0; i < rs.size() && i < cs.size(); ++i) {
        const auto &r = rs[i];
        const auto &c = cs[i];
        if (!r.enabled) continue;
        if (!c.hostAll && !c.host.match(req.host).hasMatch()) continue;

        if (r.section == MatchReplaceRule::ReqUrl) {
            QString p = req.path;   if (applyOne(p, r, c.find)) { req.path = p; m_rulesHit.fetchAndAddOrdered(1); }
            QString t = req.target; if (applyOne(t, r, c.find)) { req.target = t; m_rulesHit.fetchAndAddOrdered(1); }
        } else if (r.section == MatchReplaceRule::ReqHeader) {
            for (auto &h : req.headers) {
                QString combined = h.first + ": " + h.second;
                if (applyOne(combined, r, c.find)) {
                    const int colon = combined.indexOf(": ");
                    if (colon > 0) { h.first = combined.left(colon); h.second = combined.mid(colon + 2); }
                    else           { h.first = combined; h.second.clear(); }
                    m_rulesHit.fetchAndAddOrdered(1);
                }
            }
        } else if (r.section == MatchReplaceRule::ReqBody) {
            QString body = QString::fromUtf8(req.body);
            if (applyOne(body, r, c.find)) {
                req.body = body.toUtf8();
                bodyChanged = true;
                m_rulesHit.fetchAndAddOrdered(1);
            }
        }
    }
    if (bodyChanged) fixContentLength(req.headers, req.body.size());

    // Session injection runs AFTER user-defined rules so the rules can
    // see what the client originally sent. With autoInject on for the
    // host, server-captured cookies overwrite same-name client cookies
    // in the outgoing Cookie header.
    if (m_sessionManager) m_sessionManager->injectInto(req);

    // Session handling rules: substitute {{var}} placeholders from the
    // variable bag into matching request headers / cookies / body /
    // URL params. Runs LAST so it sees the request the way it would
    // actually go on the wire.
    if (m_sessionRules) m_sessionRules->applyToRequest(req);
}

void ProxyServer::applyResponseRules(const HttpRequest &req, HttpResponse &resp) const {
    QList<MatchReplaceRule> rs;
    QList<CompiledRule>     cs;
    {
        QMutexLocker lock(&m_rulesMutex);
        rs = m_rules;
        cs = m_compiledRules;
    }
    if (rs.isEmpty()) return;
    // Same scope-gate as applyRequestRules. Without it, a "Set-Cookie:
    // (.*) -> Set-Cookie: $1; Domain=.attacker.example" rule would let
    // a wildcard-import rule rewrite cookies on unrelated browsing
    // traffic and re-scope them to an attacker domain.
    if (!isInScope(req.host)) return;

    bool bodyChanged = false;
    for (int i = 0; i < rs.size() && i < cs.size(); ++i) {
        const auto &r = rs[i];
        const auto &c = cs[i];
        if (!r.enabled) continue;
        if (!c.hostAll && !c.host.match(req.host).hasMatch()) continue;

        if (r.section == MatchReplaceRule::RespStatus) {
            QString line = resp.httpVersion + " " + QString::number(resp.statusCode)
                         + " " + resp.reasonPhrase;
            if (applyOne(line, r, c.find)) {
                const QStringList parts = line.split(' ', Qt::KeepEmptyParts);
                if (parts.size() >= 2) {
                    resp.httpVersion  = parts[0];
                    resp.statusCode   = parts[1].toInt();
                    resp.reasonPhrase = parts.mid(2).join(' ');
                }
                m_rulesHit.fetchAndAddOrdered(1);
            }
        } else if (r.section == MatchReplaceRule::RespHeader) {
            for (auto &h : resp.headers) {
                QString combined = h.first + ": " + h.second;
                if (applyOne(combined, r, c.find)) {
                    const int colon = combined.indexOf(": ");
                    if (colon > 0) { h.first = combined.left(colon); h.second = combined.mid(colon + 2); }
                    else           { h.first = combined; h.second.clear(); }
                    m_rulesHit.fetchAndAddOrdered(1);
                }
            }
        } else if (r.section == MatchReplaceRule::RespBody) {
            QString body = QString::fromUtf8(resp.body);
            if (applyOne(body, r, c.find)) {
                resp.body = body.toUtf8();
                bodyChanged = true;
                m_rulesHit.fetchAndAddOrdered(1);
            }
        }
    }
    if (bodyChanged) fixContentLength(resp.headers, resp.body.size());
}

void ProxyServer::noteH2Upstream() {
    m_h2UpstreamCount.fetchAndAddOrdered(1);
}

ProxyServer::~ProxyServer() = default;

bool ProxyServer::start(const QHostAddress &address, quint16 port) {
    if (m_server->isListening()) return true;

    // Windows occasionally puts 8080 into its dynamic protected-port range
    // (returns WSAEACCES "The address is protected"). Try the requested
    // port first, then walk a small fallback list of common alternatives
    // before giving up.
    const QList<quint16> tries = {
        port, quint16(port + 1), 8888, 8081, 8090, 9090,
    };
    QString lastError;
    for (quint16 p : tries) {
        if (m_server->listen(address, p)) {
            emit started(m_server->serverPort());
            emit runningChanged();
            return true;
        }
        lastError = m_server->errorString();
        qWarning().noquote() << "proxy: listen failed on" << address.toString()
                             << ":" << p << "--" << lastError;
    }
    emit errorOccurred(lastError);
    return false;
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

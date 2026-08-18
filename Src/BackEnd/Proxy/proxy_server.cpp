#include "proxy_server.hpp"

#include "cert_authority.hpp"
#include "content_decode.hpp"
#include "extensions_api.hpp"
#include "http2_client.hpp"
#include "h2_server.hpp"
#include "h2_server_logic.hpp"
#include "intercept.hpp"
#include "proxy_logic.hpp"
#include "session_manager.hpp"
#include "session_rules.hpp"
#include "tls_accept_logic.hpp"
#include "networking.hpp"
#include "websocket.hpp"
#include "ws_repeater.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>

#include <algorithm>
#include <cstdio>
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
// Short so an origin we cannot MITM bypasses fast rather than costing the user
// a full kReadTimeoutMs on first contact. NOT, as this said until now, "so
// h2-only hosts bypass fast" -- we advertise h2 upstream (see the ALPN list in
// runMitmTunnel), so an h2-only origin handshakes normally and never reaches
// the branch this bounds. What lands there is an unreachable or blackholed
// origin, or one whose own certificate fails VerifyPeer.
constexpr int kHandshakeTimeoutMs = 3'000;
constexpr int kMaxHeaderBytes     = 64 * 1024;
// QTcpSocket::waitForReadyRead is UNINTERRUPTIBLE: a worker parked in a
// 15 s read cannot notice that the app is shutting down. Waiting in slices
// makes the teardown join cost one slice per parked connection instead of a
// full kReadTimeoutMs, without changing the aggregate deadline any caller
// sees. Same shape as HttpClient's nextReadTimeoutMs budget.
constexpr int kWaitSliceMs        = 500;
// joinWorkers() polls each thread this often so it can pump the event queue
// in between (see the deadlock note there), and gives up after the budget
// rather than hanging the app on exit.
//
// What this budget has to outlast, and the one thing it still does not.
//
// Every blocking wait a Connection can sit in is now sliced at kWaitSliceMs and
// polls a shutdown flag: the four waitFor* families in this file, and -- since
// they were the real hole -- H2Client::pump (http2_client.cpp) and
// H2Terminator::run (h2_server.cpp), which take the flag via setAbortFlag().
// That matters because their per-wait timeouts RESET on every byte, so before
// they were sliced a streaming upstream or a browser sending PING could park a
// worker for their whole-batch deadlines (120 s and 300 s) with nothing wrong.
// A worker now unwinds within about one slice.
//
// STILL UNSLICED: leaf-certificate minting. CertAuthority shells out to openssl
// with waitForStarted(5 s) + waitForFinished(30 s) -- that is 35 s PER
// INVOCATION, and a mint is not one invocation:
//
//   leafCertFor()  req -new -newkey   +  x509 -req        =  up to  70 s
//   ...and on the very first mint it calls ensureCa() INSIDE the same lock,
//      which adds genrsa + req -x509                      =  up to 140 s
//
// all of it under CertAuthority::m_mutex, which is process-wide rather than
// per-host -- so every other worker that needs ANY leaf queues behind it, not
// just the one doing the minting.
//
// (An earlier version of this comment said "~35 s" and framed it as affecting
// only the minting worker. Both were wrong, and this number is the stated
// reason kJoinBudgetMs is what it is, so the error propagates to whoever tunes
// it next.)
//
// Those are hard QProcess timeouts rather than resettable ones, so it is
// bounded and rare (first contact with a new host only), but it means the
// give-up branch in joinWorkers is still reachable there. Raising the budget
// past even the 70 s case would trade a rare detach for a routinely slower
// exit, which is the worse deal. The qWarning is how it surfaces if it ever
// happens.
constexpr int kJoinPollMs         = 25;
constexpr int kJoinBudgetMs       = 20'000;
// Once the global budget is blown, every REMAINING thread still gets its own
// grace window. Without this, one stuck worker makes the budget expire and
// every healthy thread behind it is detached on its first 25 ms poll -- turning
// a single un-interruptible site into N use-after-frees.
constexpr int kJoinGraceMs        = 500;

// Sliced, shutdown-aware waitForReadyRead.
//
// `srv` is REQUIRED on every caller, deliberately without a default: a
// defaulted nullptr is a silent opt-out of the entire shutdown mechanism, and
// the next helper call site added would revert to a 15 s uninterruptible wait
// with no compile error and no test failure. The null branch stays only for
// the (currently nonexistent) caller that genuinely has no server.
bool waitReadable(QTcpSocket *socket, int totalMs, const ProxyServer *srv) {
    if (!srv) return socket->waitForReadyRead(totalMs);
    QElapsedTimer clock;
    clock.start();
    for (;;) {
        if (srv->isShuttingDown()) return false;
        const qint64 left = static_cast<qint64>(totalMs) - clock.elapsed();
        if (left <= 0) return false;
        const int slice = static_cast<int>(std::min<qint64>(left, kWaitSliceMs));
        if (socket->waitForReadyRead(slice)) return true;
        // A slice expiring is not a failure; a dead socket is. Without this
        // the loop would spin out the whole budget on a closed connection.
        if (socket->state() != QAbstractSocket::ConnectedState) return false;
    }
}

// Same slicing for the two OTHER long uninterruptible waits on a connection's
// critical path. connectToHost + TLS handshake against an unreachable or
// blackholed origin park a worker for the full budget with no data ever
// arriving, so leaving these un-sliced would let a single dead upstream push
// the teardown join past its budget -- the join would then give up and LEAK
// that worker, which is the outcome this whole change exists to avoid.
// Both Qt calls are safe to re-enter: a slice expiring does not cancel the
// connect or the handshake, it just stops waiting on it.
bool waitConnected(QAbstractSocket *socket, int totalMs, const ProxyServer *srv) {
    if (!srv) return socket->waitForConnected(totalMs);
    QElapsedTimer clock;
    clock.start();
    for (;;) {
        if (srv->isShuttingDown()) return false;
        if (socket->state() == QAbstractSocket::ConnectedState) return true;
        const qint64 left = static_cast<qint64>(totalMs) - clock.elapsed();
        if (left <= 0) return false;
        if (socket->waitForConnected(static_cast<int>(std::min<qint64>(left, kWaitSliceMs))))
            return true;
        if (socket->state() == QAbstractSocket::UnconnectedState) return false;
    }
}

bool waitWritten(QAbstractSocket *socket, int totalMs, const ProxyServer *srv) {
    if (!srv) return socket->waitForBytesWritten(totalMs);
    QElapsedTimer clock;
    clock.start();
    for (;;) {
        if (socket->bytesToWrite() == 0) return true;
        if (srv->isShuttingDown()) return false;
        const qint64 left = static_cast<qint64>(totalMs) - clock.elapsed();
        if (left <= 0) return false;
        if (socket->waitForBytesWritten(static_cast<int>(std::min<qint64>(left, kWaitSliceMs))))
            return true;
        if (socket->state() != QAbstractSocket::ConnectedState) return false;
    }
}

bool waitEncrypted(QSslSocket *socket, int totalMs, const ProxyServer *srv) {
    if (!srv) return socket->waitForEncrypted(totalMs);
    QElapsedTimer clock;
    clock.start();
    for (;;) {
        if (srv->isShuttingDown()) return false;
        if (socket->isEncrypted()) return true;
        const qint64 left = static_cast<qint64>(totalMs) - clock.elapsed();
        if (left <= 0) return false;
        if (socket->waitForEncrypted(static_cast<int>(std::min<qint64>(left, kWaitSliceMs))))
            return true;
        if (socket->state() != QAbstractSocket::ConnectedState) return false;
    }
}

bool readHeaderBlock(QTcpSocket *socket, QByteArray &out, const ProxyServer *srv) {
    while (!out.contains("\r\n\r\n")) {
        if (out.size() > kMaxHeaderBytes) return false;
        if (socket->bytesAvailable() == 0 && !waitReadable(socket, kReadTimeoutMs, srv))
            return false;
        out.append(socket->readAll());
        if (socket->state() != QAbstractSocket::ConnectedState && !out.contains("\r\n\r\n"))
            return false;
    }
    return true;
}

bool readExact(QTcpSocket *socket, qint64 n, QByteArray &out, const ProxyServer *srv) {
    while (out.size() < n) {
        if (socket->bytesAvailable() == 0 && !waitReadable(socket, kReadTimeoutMs, srv))
            return false;
        out.append(socket->read(n - out.size()));
        if (socket->state() != QAbstractSocket::ConnectedState && out.size() < n)
            return false;
    }
    return true;
}

void readUntilClose(QTcpSocket *socket, QByteArray &out, const ProxyServer *srv) {
    while (socket->state() == QAbstractSocket::ConnectedState) {
        if (socket->bytesAvailable() == 0 && !waitReadable(socket, kReadTimeoutMs, srv))
            break;
        out.append(socket->readAll());
    }
    out.append(socket->readAll());
}

// parseHeaders / findHeader / isFramingSafe / isChunkedTransfer and the bounded
// chunked decoder live in proxy_logic.cpp (pure, Qt6::Core only) so they can be
// unit-tested; this socket-side wrapper just feeds bytes to the pure decoder.
bool readChunkedBody(QTcpSocket *socket, QByteArray &buffer, QByteArray &decoded,
                     const ProxyServer *srv) {
    using HttpLogic::ChunkResult;
    while (true) {
        const ChunkResult r = HttpLogic::decodeChunkedAvailable(buffer, decoded);
        if (r == ChunkResult::Complete) return true;
        if (r == ChunkResult::Error)    return false;   // bad / oversized / overflowing chunk
        // NeedMore: pull more wire bytes and try again.
        if (!waitReadable(socket, kReadTimeoutMs, srv)) return false;
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
    // Lifetime is bound to its QThread's run() stack frame instead:
    // onNewConnection() stack-allocates `Connection conn(...)` inside the
    // QThread::create lambda, so run() returning destroys it exactly once
    // and the destructor closes both child sockets.
    //
    // It must therefore NEVER self-delete -- do not wire
    // connect(..., this, &QObject::deleteLater). deleteLater() on stack
    // storage is UB: a nested relay QEventLoop (runRawRelay /
    // runWebSocketRelay) could dispatch the DeferredDelete and `delete this`
    // on a stack object, then the run()-returns unwind double-destroys it.
    // Break out of a nested relay loop on disconnect via the local
    // connect(disconnected, &loop, quit) wiring instead.
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
        const bool inScope = m_server->isUrlInScope(req.tls, req.host, req.port, req.path);
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
        if (!waitConnected(&upstream, kReadTimeoutMs, m_server)) {
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
        if (!waitWritten(&upstream, kReadTimeoutMs, m_server)) {
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

        // Response interception: hold the response for the operator (edit/
        // forward/drop) before it reaches the client, mirroring the request
        // pend() above. Scope-gated like the request side.
        const InterceptResult ir =
            resolveResponseForClient(resp, req.host, req.port, /*tls=*/false, inScope);
        if (ir.dropped) { m_client->disconnectFromHost(); return; }
        m_client->write(ir.bytes);
        waitWritten(m_client, kReadTimeoutMs, m_server);
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

        m_upstream->connectToHost(host, port);
        if (!waitConnected(m_upstream, kReadTimeoutMs, m_server)) {
            m_client->write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
            waitWritten(m_client, kReadTimeoutMs, m_server);
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
        if (!waitWritten(m_client, kReadTimeoutMs, m_server)) {
            fail("tunnel ack write failed");
            return;
        }

        // Pump both directions until either side closes. This previously just
        // connected the readyRead relays and returned -- but run() then returns
        // too, and the stack-allocated Connection (which owns m_client, m_upstream
        // and these relay connections) is destroyed immediately, so the tunnel
        // tore down without ever forwarding a byte: out-of-scope / cert-pinned
        // HTTPS browsing silently broke. runRawRelay runs a local QEventLoop that
        // keeps the relay alive for the life of the connection (the same helper
        // the post-101 WebSocket/raw path already uses).
        runRawRelay(m_client, m_upstream);
    }

    void runMitmTunnel(HttpRequest &connectReq, QSslSocket *sslClient,
                       const QString &host, quint16 port, const LeafCert &leaf) {
        // 1. Ack the CONNECT before starting our server-side TLS.
        sslClient->write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (!waitWritten(sslClient, kReadTimeoutMs, m_server)) {
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
        // Phase 3 (experimental, off by default): advertise h2 to the browser so
        // it can multiplex one connection to us. Only when --h2-termination is on,
        // because without the terminator a raw-h2 browser would break.
        if (m_server->h2Termination())
            cfg.setAllowedNextProtocols({ QByteArrayLiteral("h2"),
                                          QByteArrayLiteral("http/1.1") });
        sslClient->setSslConfiguration(cfg);
        sslClient->startServerEncryption();
        if (!waitEncrypted(sslClient, kReadTimeoutMs, m_server)) {
            // Client refused our forged cert -- usually cert pinning.
            // Add host to the bypass list so the next CONNECT to it skips
            // MITM and falls through to a blind tunnel.
            m_server->markMitmBlocked(host);
            fail("mitm: client TLS handshake failed (host blocked for future MITM): " + sslClient->errorString());
            return;
        }
        // Did the browser accept our h2 offer? (Only possible with --h2-termination.)
        const bool browserIsH2 = m_server->h2Termination()
            && sslClient->sslConfiguration().nextNegotiatedProtocol() == QByteArrayLiteral("h2");

        // 3. Open ONE upstream TLS connection and reuse it for every request
        //    the client sends inside this tunnel (HTTP/1.1 keep-alive).
        auto *upstream = new QSslSocket(this);
        m_upstream = upstream;

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
        // Per-host "accept invalid cert" exception, read once at handshake time.
        const QString hostPort = host + QLatin1Char(':') + QString::number(port);
        const bool acceptInvalid = m_server->isAcceptInvalidHost(hostPort);
        QStringList tlsErrors;
        QStringList ignoredCertErrors;   // names of errors we waved through (empty = none)
        connect(upstream, &QSslSocket::sslErrors, this,
                [&tlsErrors, &ignoredCertErrors, upstream, host, acceptInvalid](const QList<QSslError> &errs) {
            for (const auto &e : errs)
                tlsErrors << (host + ": " + e.errorString());
            if (!acceptInvalid) return;   // default: verify the origin chain normally
            // Ignore ONLY when EVERY presented error is a benign validation error.
            // A blacklisted/revoked/no-peer-cert (or any non-cert) error leaves the
            // filtered list SMALLER, so we ignore NOTHING and the handshake fails
            // CLOSED -- "accept my staging cert" never means "accept a forged one".
            const QList<QSslError> ignorable =
                Nullock::Proxy::TlsAcceptLogic::filterIgnorableErrors(errs);
            if (ignorable.size() == errs.size() && !ignorable.isEmpty()) {
                upstream->ignoreSslErrors(ignorable);
                for (const auto &e : ignorable) ignoredCertErrors << e.errorString();
            }
        });

        upstream->connectToHostEncrypted(host, port);
        if (!waitEncrypted(upstream, kHandshakeTimeoutMs, m_server)) {
            // We could not complete a TLS handshake with the ORIGIN: it is
            // unreachable or blackholed, its own certificate failed VerifyPeer,
            // or the 3 s budget expired. (This is also reached when the proxy
            // is shutting down, since waitEncrypted is shutdown-aware.)
            //
            // Root-cause fix for "one bad-cert attempt permanently blocklists the
            // host": a CERT-level failure means the sslErrors handler fired, so
            // tlsErrors is non-empty. Those fail FAST (the origin answered, its cert
            // was rejected) and are re-evaluable -- so we do NOT markMitmBlocked
            // them; adding the host to the accept-invalid list and retrying then
            // Just Works. Only a genuine unreachable/timeout (tlsErrors EMPTY) keeps
            // blocklisting, to spare the ~3 s handshake wait on every future hit.
            if (tlsErrors.isEmpty())
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
        // Handshake succeeded. If we waved an invalid cert through for an
        // allow-listed host, record EXACTLY what we accepted -- leaf SHA-256 +
        // which errors -- so the operator can see the relaxed leg (and can spot an
        // unexpected cert), and warn loudly on the console (fwrite+fflush: this is
        // a WIN32-GUI-subsystem app, qInfo is invisible and stdout is buffered).
        if (!ignoredCertErrors.isEmpty()) {
            const QByteArray fp = upstream->peerCertificate()
                                      .digest(QCryptographicHash::Sha256).toHex(':');
            const QString errs = ignoredCertErrors.join(", ");
            m_server->recordAcceptedInvalidCert(
                hostPort, QString::fromLatin1(fp), errs,
                QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
            const QByteArray warn =
                "[nullock] WARNING: accepted INVALID upstream TLS cert for " + hostPort.toUtf8()
                + " (" + errs.toUtf8() + "); leaf SHA-256 " + fp + "\n";
            std::fwrite(warn.constData(), 1, warn.size(), stderr);
            std::fflush(stderr);
        }
        const QByteArray negotiated = upstream->sslConfiguration().nextNegotiatedProtocol();
        const bool upstreamIsH2 = (negotiated == "h2");
        if (!negotiated.isEmpty() && negotiated != "http/1.1" && !upstreamIsH2) {
            m_server->markMitmBlocked(host);
            fail("mitm: upstream negotiated unexpected ALPN: " + QString::fromLatin1(negotiated));
            return;
        }

        // ── Phase 3 (experimental): the browser negotiated h2 with US ────
        // Terminate the browser's h2 and bridge each browser request stream to
        // the upstream (h2 via the persistent H2Client, or h1). The upstream send
        // + history/rules/extensions/intercept live in the callback.
        if (browserIsH2) {
            H2Client upstreamH2;   // reused across all of this tunnel's streams
            // note: hand it the shutdown flag, or its pump loop is un-interruptible
            // for up to its own 120 s deadline -- far past the teardown budget
            upstreamH2.setAbortFlag(m_server->shutdownFlag());
            bool served = false;   // did any request complete upstream on this session?
            H2Terminator term;
            // note: same reason as the H2Client above -- a browser can hold this
            // tunnel open with PING/WINDOW_UPDATE past the teardown budget
            term.setAbortFlag(m_server->shutdownFlag());
            term.run(sslClient, host + ":" + QString::number(port),
                [this, upstream, upstreamIsH2, host, port, &upstreamH2, &served](
                    const QList<QPair<QString, QString>> &h2h, const QByteArray &body,
                    HttpResponse &out) -> H2Terminator::UpstreamOutcome {
                    using UO = H2Terminator::UpstreamOutcome;
                    const auto f = Nullock::Proxy::H2ServerLogic::parseRequestHeaders(h2h);
                    if (!f.valid) return UO::RejectStream;
                    HttpRequest req;
                    req.timestamp = QDateTime::currentDateTime();
                    req.method = f.method;
                    req.host   = host;
                    req.port   = port;
                    req.tls    = true;   // HTTP/2 over the MITM'd TLS leg
                    req.path   = f.path.startsWith('/') ? f.path : ("/" + f.path);
                    req.headers = f.headers;
                    req.body    = body;
                    emit m_server->requestReceived(req);
                    if (auto *ext = m_server->extensions()) req = ext->applyRequestMutation(req);
                    m_server->applyRequestRules(req);
                    if (auto *ic = m_server->interceptController()) {
                        QByteArray dummy = serializeRequestForOrigin(req);
                        const InterceptResult ir = ic->pend(dummy, host, port, /*tls=*/true);
                        if (ir.dropped) return UO::RejectStream;   // drop one stream, keep the tunnel
                    }
                    HttpResponse resp;
                    if (upstreamIsH2) {
                        const auto r = upstreamH2.send(upstream, req);
                        if (!r.ok) {
                            if (r.connectionFailed) {
                                // Genuine upstream connection death: tear the tunnel
                                // down (browser reconnects with a fresh session) and,
                                // if it was the FIRST request, learn to blind-tunnel
                                // this host -- mirrors the h1/h2 sibling branches.
                                if (!served) m_server->markMitmBlocked(host);
                                return UO::TunnelDead;
                            }
                            return UO::RejectStream;   // per-stream error -> RST just this one
                        }
                        resp = r.response;
                    } else {
                        if (upstream->state() != QAbstractSocket::ConnectedState)
                            return UO::TunnelDead;
                        upstream->write(serializeRequestForOrigin(req));
                        if (!waitWritten(upstream, kReadTimeoutMs, m_server)) return UO::TunnelDead;
                        resp.peerAddress = upstream->peerAddress().toString();
                        resp.wasTls = true;
                        if (!readResponse(upstream, resp)) return UO::TunnelDead;   // h1 upstream broke
                    }
                    served = true;
                    if (auto *ext = m_server->extensions()) resp = ext->applyResponseMutation(req, resp);
                    m_server->applyResponseRules(req, resp);
                    emit m_server->responseReceived(req, resp);
                    // Response interception is intentionally NOT hooked on the
                    // h2-terminated browser leg: H2Terminator re-serializes this
                    // struct into h2 frames, so there are no raw h1 response
                    // bytes for the operator to edit. Same documented limitation
                    // as request editing on this path (drop-only above). h1 and
                    // h2-upstream->h1 legs carry the full edit/forward/drop.
                    out = resp;
                    return UO::Ok;
                });
            sslClient->disconnectFromHost();
            if (upstream->state() == QAbstractSocket::ConnectedState)
                upstream->disconnectFromHost();
            return;
        }

        // ── h2 upstream path: bridge h1-client to h2-server ──────────────
        // Browser side stays HTTP/1.1 (we never advertised h2 on the server
        // socket). Phase 2: keep-alive loop -- read each h1 request the browser
        // sends on this tunnel, translate it to an h2 stream on ONE reused
        // nghttp2 session (H2Client::send), and translate the h2 response back
        // to h1. Reusing the session means sequential requests share the upstream
        // TCP+TLS+h2 connection instead of paying a fresh handshake each time.
        if (upstreamIsH2) {
            m_server->noteH2Upstream();
            H2Client h2;
            h2.setAbortFlag(m_server->shutdownFlag());   // see the note above
            bool served = false;   // did at least one request complete on this session?
            while (sslClient->state() == QAbstractSocket::ConnectedState
                   && upstream->state() == QAbstractSocket::ConnectedState
                   && !m_server->isShuttingDown()) {
                HttpRequest req;
                req.timestamp = QDateTime::currentDateTime();
                if (!readRequestFrom(sslClient, req))
                    break;   // clean keep-alive close (empty read), not an error
                req.host = host;
                req.port = port;
                req.tls  = true;   // decrypted HTTPS via the MITM sslClient
                if (req.path.isEmpty() || !req.path.startsWith('/'))
                    req.path = "/" + req.path;
                emit m_server->requestReceived(req);

                if (auto *ext = m_server->extensions())
                    req = ext->applyRequestMutation(req);
                m_server->applyRequestRules(req);

                // Intercept still pends before sending upstream. (Editing the
                // request text in h2 mode is a known limitation; documented.)
                if (auto *ic = m_server->interceptController()) {
                    QByteArray dummyBytes = serializeRequestForOrigin(req);
                    const InterceptResult ir = ic->pend(dummyBytes, host, port, true);
                    if (ir.dropped) { sslClient->disconnectFromHost(); return; }
                }

                const auto h2res = h2.send(upstream, req);
                if (!h2res.ok) {
                    qWarning().noquote() << "mitm/h2 failed for" << host
                                         << ":" << h2res.errorMessage;
                    // Permanently bypass MITM for this host ONLY when the FIRST
                    // request hit a genuine connection-level h2 failure (the origin
                    // can't hold an h2 session with us). A per-stream error, a
                    // truncation, a timeout, or any failure AFTER serving is NOT
                    // grounds to block a provably-h2 origin (ALPN already agreed
                    // "h2") -- just close the tunnel and let the browser reconnect.
                    if (!served && h2res.connectionFailed) {
                        m_server->markMitmBlocked(host);
                        fail("mitm/h2: " + h2res.errorMessage);
                        return;
                    }
                    break;
                }
                served = true;

                HttpResponse h2resp = h2res.response;
                if (auto *ext = m_server->extensions())
                    h2resp = ext->applyResponseMutation(req, h2resp);
                m_server->applyResponseRules(req, h2resp);
                emit m_server->responseReceived(req, h2resp);

                // Response interception on the h2-upstream bridge too: the
                // browser leg is h1, so the operator edits the same serialized
                // response bytes as any other h1 response.
                {
                    const InterceptResult ir =
                        resolveResponseForClient(h2resp, host, port, /*tls=*/true, /*inScope=*/true);
                    if (ir.dropped) { sslClient->disconnectFromHost(); return; }
                    sslClient->write(ir.bytes);
                }
                if (!waitWritten(sslClient, kReadTimeoutMs, m_server)) {
                    fail("mitm/h2: response write to client failed");
                    return;
                }

                // The browser leg is h1: honor an explicit Connection: close.
                if (findHeader(req.headers, "Connection")
                        .compare("close", Qt::CaseInsensitive) == 0)
                    break;
            }
            sslClient->disconnectFromHost();
            if (upstream->state() == QAbstractSocket::ConnectedState)
                upstream->disconnectFromHost();
            return;
        }

        // 4. Loop: read a request, forward, read response, send back.
        //    Stop when either side closes or asks for Connection: close.
        while (sslClient->state() == QAbstractSocket::ConnectedState
               && upstream->state() == QAbstractSocket::ConnectedState
               && !m_server->isShuttingDown()) {

            HttpRequest req;
            req.timestamp = QDateTime::currentDateTime();
            if (!readRequestFrom(sslClient, req)) {
                // Empty read on a keep-alive connection is a clean close,
                // not a protocol error worth surfacing.
                break;
            }
            req.host = host;
            req.port = port;
            req.tls  = true;   // decrypted HTTPS via the MITM sslClient
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
            if (!waitWritten(upstream, kReadTimeoutMs, m_server)) {
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
                waitWritten(sslClient, kReadTimeoutMs, m_server);
                const QString upgrade = findHeader(req.headers, "Upgrade");
                if (upgrade.compare("websocket", Qt::CaseInsensitive) == 0)
                    runWebSocketRelay(sslClient, upstream, host, port);
                else
                    runRawRelay(sslClient, upstream);
                return;
            }

            // Response interception before the client sees it. The tunnel is
            // only MITM'd for in-scope hosts, so inScope is implicitly true.
            {
                const InterceptResult ir =
                    resolveResponseForClient(resp, host, port, /*tls=*/true, /*inScope=*/true);
                if (ir.dropped) { sslClient->disconnectFromHost(); return; }
                sslClient->write(ir.bytes);
            }
            if (!waitWritten(sslClient, kReadTimeoutMs, m_server)) {
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
        if (!readHeaderBlock(socket, buf, m_server)) return false;
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
            // Attacker-controlled Content-Length (MITM); cap it so a huge value
            // can't buffer an unbounded request body -> memory DoS.
            if (n < 0 || n > 128LL * 1024 * 1024) return false;
            req.body = rest;
            if (req.body.size() < n) {
                QByteArray extra;
                if (!readExact(socket, n - req.body.size(), extra, m_server)) return false;
                req.body.append(extra);
            } else {
                req.body = req.body.left(n);
            }
        }
        return true;
    }

    bool readResponse(QTcpSocket *upstream, HttpResponse &resp) {
        QByteArray buf;
        if (!readHeaderBlock(upstream, buf, m_server)) return false;
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
            if (!readChunkedBody(upstream, rest, decoded, m_server)) return false;
            resp.body = decoded;
        } else if (!cl.isEmpty()) {
            const qint64 n = cl.toLongLong();
            // A peer-declared Content-Length is attacker-controlled in a MITM;
            // cap it so a huge value can't buffer an unbounded body into one
            // QByteArray -> memory DoS.
            //
            // The chunked path has its own, SEPARATE limits and they are not the
            // same number: HttpLogic::kMaxChunkBytes (16 MiB per chunk) and
            // kMaxDecodedBytes (256 MiB total decoded) in proxy_logic.hpp. There
            // is no shared kMaxBodyBytes -- this comment named one for a while,
            // and grepping for it finds nothing.
            if (n < 0 || n > 128LL * 1024 * 1024) return false;
            resp.body = rest;
            if (resp.body.size() < n) {
                QByteArray extra;
                if (!readExact(upstream, n - resp.body.size(), extra, m_server)) return false;
                resp.body.append(extra);
            } else {
                resp.body = resp.body.left(n);
            }
        } else {
            QByteArray tail;
            readUntilClose(upstream, tail, m_server);
            resp.body = rest + tail;
        }
        // Decode Content-Encoding for inspection (history/search, passive scan,
        // evidence, reports). resp.body stays the exact wire bytes we forward to
        // the client -- only this readable copy is decompressed.
        const QByteArray dec = decodeContentEncoding(
            findHeader(resp.headers, "Content-Encoding"), resp.body);
        if (!dec.isEmpty()) resp.decodedBody = dec;
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

    // Serialize `resp` and, if response interception is enabled (and the host
    // is in scope), park the raw bytes for the operator to edit / forward /
    // drop BEFORE they reach the client -- the response-side mirror of the
    // request pend() at the top of run(). Returns the (possibly edited) bytes
    // to write and sets `dropped` when the operator dropped the response (the
    // caller then tears the client connection down, so the browser gets
    // nothing). When response interception is off this is a cheap serialize +
    // verbatim pass-through, exactly like the old direct serializeResponse()
    // write. `tls` records whether the client leg is encrypted, purely for the
    // operator-facing display. This blocks the per-connection worker thread on
    // the intercept semaphore; the cap + toggle-off drain in InterceptController
    // guarantee it can never deadlock the proxy.
    InterceptResult resolveResponseForClient(const HttpResponse &resp,
                                             const QString &host, int port,
                                             bool tls, bool inScope) {
        QByteArray bytes = serializeResponse(resp);
        auto *ic = m_server->interceptController();
        if (ic && inScope && ic->responsesEnabled())
            return ic->pendResponse(bytes, host, port, tls);
        return { false, bytes };
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
        // A blind tunnel has no read timeout to expire -- it parks this worker
        // for the whole browsing session. The queued shuttingDown() hop is
        // dispatched by this very loop, so it is what bounds the teardown join.
        connect(m_server, &ProxyServer::shuttingDown, &loop, quit);
        connect(client, &QTcpSocket::readyRead, this, [client, upstream] {
            upstream->write(client->readAll());
        });
        connect(upstream, &QTcpSocket::readyRead, this, [client, upstream] {
            client->write(upstream->readAll());
        });
        // Drain anything that arrived between the handshake ack and now. A peer
        // that pipelines data right after the ack (curl fires the TLS ClientHello
        // the instant it sees our "200 Connection Established") emits readyRead
        // for those bytes BEFORE we connected the relay above; readyRead is
        // edge-triggered and won't re-fire for already-buffered data, so without
        // this initial drain the relay would sit idle and the connection hangs.
        if (client->bytesAvailable())   upstream->write(client->readAll());
        if (upstream->bytesAvailable()) client->write(upstream->readAll());
        // isShuttingDown() closes the window where shuttingDown() was emitted
        // BEFORE the connect above: the signal would be missed and exec()
        // would never return.
        if (client->state() == QAbstractSocket::ConnectedState
            && upstream->state() == QAbstractSocket::ConnectedState
            && !m_server->isShuttingDown())
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

        /*
         *  Injected frames are WRITTEN HERE, not by the repeater. Both sockets
         *  are children of this Connection and live on this worker thread; the
         *  repeater is called from the control server's thread and must not go
         *  near them.
         *
         *  `this` as the context object is the whole point of the fix. ~QObject
         *  severs a context-object connection and drops that receiver's posted
         *  events BEFORE it deletes its children, so once this Connection is
         *  gone no queued frame can reach a destroyed socket -- it is discarded
         *  instead. Capturing the sockets is therefore safe: the lambda cannot
         *  outlive their parent.
         *
         *  Delivery is queued (the emitter is on another thread) and it is the
         *  relay's own loop.exec() below that dispatches it, so a frame only
         *  lands while the tunnel is actually being pumped.
        */
        connect(WsRepeater::instance(), &WsRepeater::frameQueued, this,
                [wsId, client, upstream](qint64 id, const QByteArray &frame,
                                         bool toUpstream) {
                    if (id != wsId) return;          // a different tunnel's frame
                    QTcpSocket *sock = toUpstream ? upstream : client;
                    if (sock && sock->state() == QAbstractSocket::ConnectedState)
                        sock->write(frame);
                });

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
        // See runRawRelay: an idle WebSocket parks this worker indefinitely.
        connect(m_server, &ProxyServer::shuttingDown, &loop, quit);

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

        // isShuttingDown() closes the window where shuttingDown() was emitted
        // BEFORE the connect above: the signal would be missed and exec()
        // would never return.
        if (client->state() == QAbstractSocket::ConnectedState
            && upstream->state() == QAbstractSocket::ConnectedState
            && !m_server->isShuttingDown())
            loop.exec();

        // Deregister on EVERY exit, not just on a socket `disconnected`. The
        // registration at the top of this function is unconditional, but the
        // deregistration was wired only to the two disconnected() signals --
        // so an exit that skips exec() (either socket already closed before we
        // connected, or now a shutdown) left a permanently stale entry in the
        // process-wide WsRepeater singleton, visible in the UI's session list
        // forever. remove() on an absent id is a no-op, so the normal
        // disconnected() path is unaffected.
        WsRepeater::instance()->deregisterSession(wsId);
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
    {
        QMutexLocker lock(&m_blockMutex);
        if (m_mitmBlocked.contains(host)) return;
        m_mitmBlocked.insert(host);
    }
    // Every caller is a per-connection worker thread (a pinned cert refused our
    // forged one), so two hosts can be marked at the same instant. Taking the
    // snapshot inside the mutex and writing outside it -- which is what this
    // used to do -- lets the two writers race: each opens the file Truncate and
    // rewrites it from ITS OWN snapshot, so whichever finishes last wins and the
    // other worker's host is silently dropped from the persisted list. Worse,
    // the two truncate-then-write sequences interleave at the byte level, so a
    // shorter list landing on top of a longer one leaves a torn file that
    // setBlocklistPath will happily parse back as real hosts.
    //
    // Re-reading the set from INSIDE the file lock fixes both: the writes are
    // serialized, and whoever gets the lock persists the current state rather
    // than a stale copy, so the last write is always the complete one. The
    // state mutex is still never held across disk I/O -- isMitmBlocked() runs on
    // the CONNECT hot path and must not block behind a write.
    persistBlocklist();
}

// Rewrite the blocklist file from the live set. MUST be called without
// m_blockMutex held; takes m_blocklistFileMutex, then m_blockMutex. That order
// is the same everywhere the two are held together, which is what keeps it
// deadlock-free.
void ProxyServer::persistBlocklist() {
    QMutexLocker fileLock(&m_blocklistFileMutex);

    QString path;
    QStringList snapshot;
    {
        QMutexLocker lock(&m_blockMutex);
        path = m_blocklistPath;
        if (path.isEmpty()) return;
        snapshot = QStringList(m_mitmBlocked.constBegin(), m_mitmBlocked.constEnd());
    }

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    snapshot.sort();
    f.write(snapshot.join('\n').toUtf8());
    f.write("\n");
}

QStringList ProxyServer::blockedHosts() const {
    QMutexLocker lock(&m_blockMutex);
    QStringList out(m_mitmBlocked.constBegin(), m_mitmBlocked.constEnd());
    out.sort();
    return out;
}

void ProxyServer::clearMitmBlocked() {
    // markMitmBlocked's twin, and it needs the same file lock for the same
    // reason. Without it a worker that marked a host just before this call can
    // still be inside its rewrite, and would recreate the file -- with the host
    // the user just cleared in it -- moments after we deleted it. Holding the
    // file lock across both the clear and the delete makes the two orderings
    // the only possible ones: the mark lands first and is then deleted, or it
    // lands after and writes the (now empty) set.
    QMutexLocker fileLock(&m_blocklistFileMutex);

    QString pathToRemove;
    {
        QMutexLocker lock(&m_blockMutex);
        m_mitmBlocked.clear();
        pathToRemove = m_blocklistPath;
    }
    if (!pathToRemove.isEmpty())
        QFile::remove(pathToRemove);
}

void ProxyServer::clearMitmBlocked(const QString &host) {
    // Per-host unblock: drop ONE host and rewrite the file from the reduced set.
    // Holds the file lock across the mutate+rewrite (same ordering as everywhere),
    // and rewrites inline rather than calling persistBlocklist() -- the file mutex
    // is non-recursive, so re-entering it would self-deadlock.
    QMutexLocker fileLock(&m_blocklistFileMutex);
    QString path;
    QStringList snapshot;
    bool removed = false;
    {
        QMutexLocker lock(&m_blockMutex);
        removed = (m_mitmBlocked.remove(host) > 0);
        path = m_blocklistPath;
        snapshot = QStringList(m_mitmBlocked.constBegin(), m_mitmBlocked.constEnd());
    }
    if (!removed || path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    snapshot.sort();
    f.write(snapshot.join('\n').toUtf8());
    f.write("\n");
}

bool ProxyServer::isAcceptInvalidHost(const QString &hostPort) const {
    QMutexLocker lock(&m_acceptMutex);
    return m_acceptInvalidUpstreamHosts.contains(hostPort);
}
QStringList ProxyServer::acceptInvalidUpstreamHosts() const {
    QMutexLocker lock(&m_acceptMutex);
    QStringList out(m_acceptInvalidUpstreamHosts.constBegin(), m_acceptInvalidUpstreamHosts.constEnd());
    out.sort();
    return out;
}
void ProxyServer::setAcceptInvalidUpstreamHosts(const QStringList &hosts) {
    {
        QMutexLocker lock(&m_acceptMutex);
        m_acceptInvalidUpstreamHosts = QSet<QString>(hosts.constBegin(), hosts.constEnd());
    }
    emit acceptInvalidStateChanged();
}
void ProxyServer::addAcceptInvalidHost(const QString &hostPort) {
    {
        QMutexLocker lock(&m_acceptMutex);
        if (m_acceptInvalidUpstreamHosts.contains(hostPort)) return;
        m_acceptInvalidUpstreamHosts.insert(hostPort);
    }
    emit acceptInvalidStateChanged();
}
void ProxyServer::removeAcceptInvalidHost(const QString &hostPort) {
    bool changed = false;
    {
        QMutexLocker lock(&m_acceptMutex);
        changed = (m_acceptInvalidUpstreamHosts.remove(hostPort) > 0);
        m_acceptedCerts.remove(hostPort);   // forget what we accepted for it too
    }
    if (changed) emit acceptInvalidStateChanged();
}
void ProxyServer::recordAcceptedInvalidCert(const QString &hostPort, const QString &sha256,
                                            const QString &ignoredErrors, const QString &acceptedAt) {
    {
        QMutexLocker lock(&m_acceptMutex);
        m_acceptedCerts.insert(hostPort, AcceptedCert{ sha256, ignoredErrors, acceptedAt });
    }
    emit acceptInvalidStateChanged();
}
QList<QPair<QString, ProxyServer::AcceptedCert>> ProxyServer::acceptedInvalidCerts() const {
    QMutexLocker lock(&m_acceptMutex);
    QList<QPair<QString, AcceptedCert>> out;
    for (auto it = m_acceptedCerts.constBegin(); it != m_acceptedCerts.constEnd(); ++it)
        out.append({ it.key(), it.value() });
    return out;
}

void ProxyServer::setBlocklistPath(const QString &path) {
    // Called once at startup, before the listener is up -- but it both reads the
    // file and replaces the set, so it takes the file lock in the same order as
    // everything else rather than relying on that timing staying true.
    QMutexLocker fileLock(&m_blocklistFileMutex);
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

void ProxyServer::setAdvancedScope(const QJsonArray &rulesJson) {
    // Validate + compile (drops oversized/invalid/blank-exclude rules) OFF the
    // lock, then swap in under the lock. Called from the GUI/main thread only.
    auto compiled = ScopeLogic::compile(ScopeLogic::rulesFromJson(rulesJson));
    QMutexLocker lock(&m_scopeMutex);
    m_advancedScope = std::move(compiled);
}

// Evaluate the simple host-glob layer for `host`, returning its (out, in)
// booleans. Called with m_scopeMutex HELD. The globs are anchored literals, so
// this stays safe under the lock; the advanced user-regex matching is deliberately
// done by the caller AFTER releasing the lock.
static void globVerdict(const QList<QRegularExpression> &inScope,
                        const QList<QRegularExpression> &outOfScope,
                        const QString &host, bool &globOut, bool &globIn) {
    globOut = false;
    for (const auto &rx : outOfScope)
        if (rx.match(host).hasMatch()) { globOut = true; break; }
    globIn = inScope.isEmpty();
    if (!globIn)
        for (const auto &rx : inScope)
            if (rx.match(host).hasMatch()) { globIn = true; break; }
}

bool ProxyServer::isInScope(const QString &host) const {
    bool globOut, globIn;
    QList<ScopeLogic::CompiledRule> adv;
    {
        QMutexLocker lock(&m_scopeMutex);
        globVerdict(m_inScope, m_outOfScope, host, globOut, globIn);
        adv = m_advancedScope;   // implicitly-shared copy; regex matched outside the lock
    }
    // No enabled advanced rule -> byte-identical to the legacy host-glob decision.
    if (!ScopeLogic::configured(adv)) return !globOut && globIn;
    // Advanced configured but this caller only has the host: fail-closed host-only.
    return ScopeLogic::hostInScope(adv, globOut, globIn, host);
}

bool ProxyServer::isUrlInScope(bool tls, const QString &host, int port,
                               const QString &path) const {
    bool globOut, globIn;
    QList<ScopeLogic::CompiledRule> adv;
    {
        QMutexLocker lock(&m_scopeMutex);
        globVerdict(m_inScope, m_outOfScope, host, globOut, globIn);
        adv = m_advancedScope;
    }
    if (!ScopeLogic::configured(adv)) return !globOut && globIn;
    return ScopeLogic::urlInScope(adv, globOut, globIn, tls, host, port, path);
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

    // NOTE: the early return below leaves this function entirely, so it also
    // skips the SessionManager cookie injection and the SessionRules {{var}}
    // substitution at the bottom -- not just Match & Replace, which is all this
    // comment used to describe. That is defensible (you probably do not want
    // captured session cookies injected into out-of-scope traffic either), but
    // it is a policy decision no one wrote down, and it only bites once a scope
    // is actually configured: isInScope() returns true for everything while the
    // in-scope list is empty.
    //
    // Scope-gate Match & Replace. A wildcard rule (host pattern ".*", which
    // is the default) would otherwise rewrite EVERY outgoing request --
    // including the user's normal browser traffic to out-of-scope hosts.
    // A rule like (Cookie: (.*) -> X-Exfil: $1) imported from a hostile
    // project file or a compromised extension would exfil cookies from
    // unrelated sites the user happens to visit while running Nullock.
    // Apply rules only to in-scope hosts (when scope is configured); the
    // per-rule host regex still narrows from there. When in-scope is
    // unset, fall through to the previous behaviour.
    if (!isUrlInScope(req.tls, req.host, req.port, req.path)) return;

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
    if (!isUrlInScope(req.tls, req.host, req.port, req.path)) return;

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

ProxyServer::~ProxyServer() {
    // Backstop only. By the time a stack-local ProxyServer is destroyed in
    // main(), every object declared AFTER it -- extensions, intercept, model,
    // scanner -- has ALREADY been destroyed, and a live worker has been
    // dereferencing that freed storage the whole time. So this cannot touch
    // m_intercept/m_extensions (they may dangle); it only stops accepting and
    // joins, which at least keeps the threads from outliving `this` too.
    //
    // The real fix is app.cpp calling shutdownAndJoin() while everything is
    // still alive. If that happened, this is a no-op.
    if (!m_shuttingDown.exchange(true, std::memory_order_acq_rel)) {
        qWarning("proxy: ~ProxyServer() reached without shutdownAndJoin(); "
                 "workers may already have touched destroyed objects");
        if (m_server->isListening()) m_server->close();
        emit shuttingDown();
    }
    joinWorkers(/*pump=*/false);
}

// Swap the list out under the mutex and wait OUTSIDE it.
//
// The reason is NOT "a worker thread might take this mutex" -- none does; the
// only two takers are onNewConnection() and this function, both on the
// ProxyServer's own thread. It is that the loop below PUMPS the event queue,
// and a dispatched newConnection would re-enter onNewConnection(), which takes
// m_threadsMutex. Holding it across the wait would self-deadlock.
void ProxyServer::joinWorkers(bool pump) {
    QList<QThread *> mine;
    {
        QMutexLocker lock(&m_threadsMutex);
        mine.swap(m_threads);
    }
    if (mine.isEmpty()) return;

    // A PLAIN wait() HERE DEADLOCKS, and it is not a subtle case:
    // ExtensionsApi::applyRequestMutation/applyResponseMutation marshal into
    // THIS thread with Qt::BlockingQueuedConnection whenever an extension has
    // registered a handler. A worker parked in that hop is blocked on a
    // semaphore that only the dispatch of its QMetaCallEvent releases -- and
    // that event is sitting in this thread's queue. Waiting without pumping
    // means the worker waits on us while we wait on the worker, forever.
    //
    // So pump while joining. ExcludeUserInputEvents keeps a click from
    // re-entering the UI during teardown; the metacalls we actually need are
    // not user-input events.
    QElapsedTimer budget;
    budget.start();
    QList<QThread *> stuck;
    for (QThread *t : mine) {
        QElapsedTimer grace;
        grace.start();
        // Unconditional wait, same reasoning as port_scanner.cpp: an
        // `if (isRunning())` guard can miss the window between start()
        // returning and the OS thread being observed as running.
        while (!t->wait(kJoinPollMs)) {
            // pump=false on the destructor backstop: by then the objects
            // those queued slots would reach are already destroyed, so
            // dispatching them would turn one use-after-free into several.
            //
            // ExcludeSocketNotifiers is load-bearing, not tidiness. Without
            // it this pump re-enters ControlServer's still-listening HTTP API
            // mid-teardown, and its handlers reach straight back into the
            // objects main() is unwinding -- a stray /api/proxy/toggle would
            // call start() on us and re-open the listener while we are draining
            // it. Posted QMetaCallEvents (the BlockingQueuedConnection hops we
            // actually need to service) are NOT socket notifiers, so they still
            // get dispatched.
            //
            // The 5 ms cap keeps one slow queued slot (a ProjectStore disk
            // append, a passive scan) from stalling the poll loop.
            if (pump && QCoreApplication::instance())
                QCoreApplication::processEvents(
                    QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers,
                    5);
            // Give up only when BOTH the shared budget and this thread's own
            // grace are exhausted. Budget alone would let the first stuck
            // worker detach every healthy thread queued behind it.
            if (budget.elapsed() > kJoinBudgetMs && grace.elapsed() > kJoinGraceMs) break;
        }
        if (t->isFinished()) delete t;
        else                 stuck.append(t);
    }

    if (!stuck.isEmpty()) {
        // LEAKED ON PURPOSE. Deleting a still-running QThread is UB, so the
        // safe failure is to let these outlive us and say so. This is a
        // degraded outcome -- those workers can still reach freed objects, the
        // bug this whole change exists to prevent -- so it must never be
        // silent. Reaching it means some blocking site is not shutdown-aware.
        qWarning("proxy: %lld worker thread(s) still running after %d ms; "
                 "leaving them detached rather than destroying a live QThread",
                 static_cast<long long>(stuck.size()), kJoinBudgetMs);
    }
}

void ProxyServer::shutdownAndJoin() {
    if (m_shuttingDown.exchange(true, std::memory_order_acq_rel)) {
        joinWorkers(/*pump=*/true);   // idempotent: a second call still reaps late finishers
        return;
    }
    if (m_server->isListening()) m_server->close();

    // Unpark anything waiting on the operator BEFORE joining. A worker sitting
    // in InterceptController::pend() is blocked on a QSemaphore that only a UI
    // click releases -- there is no timeout -- so without this the join waits
    // forever on a window that is already gone. Safe here and only here:
    // shutdownAndJoin() is called while m_intercept is still alive.
    //
    // Both steps are load-bearing, and in this order. The toggles first,
    // because pend()/pendResponse() early-out on them from the WORKER thread
    // (intercept.cpp:191/199) -- otherwise a worker entering pend() just after
    // the drain would post addPendingOnMain to a main event loop that has
    // already returned from exec() and then block on the semaphore forever.
    // forwardAll() second, to release the ones already parked.
    if (m_intercept) {
        m_intercept->setEnabled(false);
        m_intercept->setResponsesEnabled(false);
        m_intercept->forwardAll();
    }

    // Wakes the nested relay event loops (blind tunnels / WebSockets), which
    // have no read timeout of their own. Queued into each worker thread and
    // dispatched by the relay's own exec().
    emit shuttingDown();

    joinWorkers(/*pump=*/true);
}

bool ProxyServer::start(const QHostAddress &address, quint16 port) {
    // start() is Q_INVOKABLE and reachable from QML and /api/proxy/toggle.
    // m_shuttingDown is never reset, so restarting after shutdownAndJoin()
    // would hand back a server whose every read fails instantly and whose
    // accepts are refused -- listening but functionally dead. Refuse instead.
    // (stop() does NOT set the flag, so the ordinary stop/start toggle still
    // works; only teardown is one-way.)
    if (isShuttingDown()) return false;
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
            // Remember the bind so restart() (stop/start toggle) re-listens on the
            // same interface + actually-bound port, not the LocalHost:8080 defaults.
            m_bindAddress = address;
            m_bindPort    = m_server->serverPort();
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

bool ProxyServer::restart() {
    return start(m_bindAddress, m_bindPort);
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

        // Refuse new work once teardown has begun -- a connection accepted
        // after shutdownAndJoin() swapped the thread list would never be
        // joined, which is the exact bug this is fixing.
        if (isShuttingDown()) { client->deleteLater(); continue; }

        // Reap threads that have already finished. This is the ONLY reaping
        // point: a finished->deleteLater could never fire once the main event
        // loop is gone, and reaping from the worker's own finished signal
        // would take m_threadsMutex on a thread the joiner may be waiting on.
        // Cost is O(live connections) per accept, on a path that is already
        // doing a socket accept + thread spawn.
        {
            QMutexLocker lock(&m_threadsMutex);
            for (auto it = m_threads.begin(); it != m_threads.end(); ) {
                if ((*it)->isFinished()) { (*it)->wait(); delete *it; it = m_threads.erase(it); }
                else                     { ++it; }
            }
        }

        ProxyServer *self = this;
        auto *thread = QThread::create([self, client]() {
            Connection conn(client, self);
            conn.run();
            // conn goes out of scope here; its destructor deletes the
            // client socket (parent ownership). The QThread then exits.
        });

        client->moveToThread(thread);
        // NO connect(finished -> deleteLater): the thread is OWNED by
        // m_threads now and retired by the reap above or by joinWorkers().
        // deleteLater would race that ownership, and could not be dispatched
        // at teardown anyway (no main event loop after exec() returns).
        {
            QMutexLocker lock(&m_threadsMutex);
            m_threads.append(thread);
        }
        thread->start();
        if (!thread->isRunning() && !thread->isFinished()) {
            // QThread::start() returns void and only warns on failure (thread
            // exhaustion is reachable at one-thread-per-connection). The entry
            // would then never satisfy isFinished(), so it would never be
            // reaped and would burn the join grace at every shutdown. Retire it
            // here, and take the socket with it -- it was already moved to this
            // thread, so nothing else can ever service it.
            QMutexLocker lock(&m_threadsMutex);
            m_threads.removeOne(thread);
            delete thread;   // never started: safe to destroy
            delete client;
        }
    }
}

} // namespace Nullock::Proxy

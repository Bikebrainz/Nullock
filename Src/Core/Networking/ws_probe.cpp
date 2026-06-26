#include "ws_probe.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>

namespace Nullock::Core::WsProbe {

namespace {

constexpr int kTimeoutMs = 10000;

QByteArray randomKey() {
    quint32 w[4];
    for (quint32 &x : w) x = QRandomGenerator::global()->generate();
    return QByteArray(reinterpret_cast<const char *>(w), 16).toBase64();
}

// expectedAccept(), headerValue(), statusFromHeaderBlock() and buildHandshake()
// are pure and live in ws_logic.cpp so they can be unit-tested (against the RFC
// 6455 known vector) against Qt6::Core alone.

struct Shake { int status = 0; bool acceptValid = false; bool ok = false; QString error; };

// One upgrade handshake. `origin` empty -> omit the Origin header (control).
Shake handshake(const Request &req, const QString &origin) {
    Shake out;
    QTcpSocket *sock = nullptr;
    QSslSocket *ssl = nullptr;
    if (req.tls) {
        ssl = new QSslSocket();
        QSslConfiguration cfg = ssl->sslConfiguration();
        cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
        ssl->setSslConfiguration(cfg);
        ssl->setPeerVerifyName(req.host);
        sock = ssl;
        ssl->connectToHostEncrypted(req.host, static_cast<quint16>(req.port));
        if (!ssl->waitForEncrypted(kTimeoutMs)) {
            out.error = "TLS handshake failed: " + ssl->errorString();
            sock->deleteLater(); return out;
        }
    } else {
        sock = new QTcpSocket();
        sock->connectToHost(req.host, static_cast<quint16>(req.port));
        if (!sock->waitForConnected(kTimeoutMs)) {
            out.error = "connect failed: " + sock->errorString();
            sock->deleteLater(); return out;
        }
    }

    const QByteArray key = randomKey();
    const QByteArray r = buildHandshake(req, origin, key);
    if (r.isEmpty()) { out.error = "request build aborted (CR/LF in host/path)"; sock->deleteLater(); return out; }

    sock->write(r);
    if (!sock->waitForBytesWritten(kTimeoutMs)) {
        out.error = "write failed"; sock->deleteLater(); return out;
    }

    QByteArray resp;
    while (!resp.contains("\r\n\r\n")) {
        if (sock->bytesAvailable() == 0 && !sock->waitForReadyRead(kTimeoutMs)) break;
        resp.append(sock->readAll());
        if (sock->state() != QAbstractSocket::ConnectedState && !resp.contains("\r\n\r\n")) break;
        if (resp.size() > 64 * 1024) break;   // a handshake response is tiny
    }
    sock->abort();
    sock->deleteLater();

    const int sep = resp.indexOf("\r\n\r\n");
    if (sep < 0) { out.error = out.error.isEmpty() ? "no response headers" : out.error; return out; }
    const QByteArray headerBlock = resp.left(sep);
    out.status = statusFromHeaderBlock(headerBlock);
    out.ok = true;
    if (out.status == 101) {
        const QString accept = headerValue(headerBlock, "Sec-WebSocket-Accept");
        out.acceptValid = (accept.toUtf8() == expectedAccept(key));
    }
    return out;
}

} // namespace

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");
    result.attackerOrigin = req.attackerOrigin.isEmpty()
        ? QStringLiteral("https://nullock-cswsh.test") : req.attackerOrigin;

    // CSWSH is only EXPLOITABLE when the socket authenticates the victim via an
    // ambient credential (cookie / HTTP auth) the browser attaches cross-site.
    // If the caller supplied one, a cross-origin 101 is a CONFIRMED hijack; if
    // not, it only proves Origin isn't validated -- a public/no-auth WS that
    // accepts any Origin is expected, not a vulnerability. Grade accordingly.
    const bool authed = hasCredential(req.headers);
    auto gradeAccepted = [&](const QString &origin) {
        result.isWebSocket = true;
        if (authed) {
            result.crossOriginAccepted = true;
            result.detail = "upgrade completed (101 + valid Sec-WebSocket-Accept) cross-origin (Origin "
                            + origin + ") while carrying the supplied session credential -- CSWSH";
        } else {
            result.originNotValidated = true;
            result.detail = "upgrade completed cross-origin (Origin " + origin
                            + ") but NO session credential was supplied -- Origin is not validated; "
                              "confirm the socket is authenticated/cookie-gated before treating as "
                              "CSWSH (a public WS accepting any Origin is expected)";
        }
    };

    // 1) Attacker-Origin handshake.
    const Shake atk = handshake(req, result.attackerOrigin);
    if (!atk.ok && atk.status == 0) { result.error = atk.error; return result; }
    result.attackerStatus = atk.status;
    if (atk.status == 101 && atk.acceptValid) { gradeAccepted(result.attackerOrigin); return result; }

    // 2) "null" Origin -- the single most common allow-listed bypass (a
    // sandboxed iframe / cross-scheme redirect sends Origin: null). A 101 + valid
    // accept here is an unambiguous Origin-validation bypass.
    const Shake nul = handshake(req, QStringLiteral("null"));
    if (nul.status == 101 && nul.acceptValid) { gradeAccepted(QStringLiteral("null")); return result; }

    // 3) Both refused -> a no-Origin control distinguishes "the endpoint
    // validates Origin" from "not a WebSocket endpoint at all".
    const Shake ctl = handshake(req, QString());
    result.controlStatus = ctl.status;
    if (ctl.status == 101 && ctl.acceptValid) {
        result.isWebSocket = true;
        result.originValidated = true;
        result.detail = "WebSocket endpoint refused both the attacker (status "
                        + QString::number(atk.status) + ") and the null-Origin (status "
                        + QString::number(nul.status) + ") handshakes while the no-Origin control "
                          "upgraded -- Origin appears validated";
    } else {
        result.detail = "no valid WebSocket upgrade observed (attacker status "
                        + QString::number(atk.status) + ", null-Origin status "
                        + QString::number(nul.status) + ", control status "
                        + QString::number(ctl.status) + ")";
    }
    return result;
}

} // namespace Nullock::Core::WsProbe

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
const char *kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

QByteArray randomKey() {
    quint32 w[4];
    for (quint32 &x : w) x = QRandomGenerator::global()->generate();
    return QByteArray(reinterpret_cast<const char *>(w), 16).toBase64();
}

// RFC 6455: the server must echo base64(SHA1(key + GUID)).
QByteArray expectedAccept(const QByteArray &keyB64) {
    return QCryptographicHash::hash(keyB64 + kWsGuid, QCryptographicHash::Sha1).toBase64();
}

QString headerValue(const QByteArray &headerBlock, const char *name) {
    const QByteArray lower = headerBlock.toLower();
    const QByteArray key = QByteArray(name).toLower() + ":";
    int i = lower.indexOf("\r\n" + key);
    if (i < 0) { if (lower.startsWith(key)) i = 0; else return QString(); }
    else i += 2;
    // Anchor the colon to the end of the matched name, not the next ':' in the
    // line -- so a value that itself contains a colon can't be misparsed.
    const int colon = i + static_cast<int>(qstrlen(name));
    const int eol = headerBlock.indexOf("\r\n", colon);
    return QString::fromLatin1(headerBlock.mid(colon + 1, (eol < 0 ? headerBlock.size() : eol) - colon - 1)).trimmed();
}

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
    QByteArray r;
    r  = "GET " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    r += "Host: " + req.host.toUtf8() + "\r\n";
    r += "Upgrade: websocket\r\n";
    r += "Connection: Upgrade\r\n";
    r += "Sec-WebSocket-Key: " + key + "\r\n";
    r += "Sec-WebSocket-Version: 13\r\n";
    if (!origin.isEmpty() && !origin.contains('\r') && !origin.contains('\n'))
        r += "Origin: " + origin.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Origin", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        r += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    r += "\r\n";

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
    const int firstEol = headerBlock.indexOf("\r\n");
    const QByteArray statusLine = headerBlock.left(firstEol < 0 ? headerBlock.size() : firstEol);
    const int sp1 = statusLine.indexOf(' ');
    out.status = sp1 < 0 ? 0 : statusLine.mid(sp1 + 1, 3).toInt();
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

    // 1) Attacker-Origin handshake.
    const Shake atk = handshake(req, result.attackerOrigin);
    if (!atk.ok && atk.status == 0) { result.error = atk.error; return result; }
    result.attackerStatus = atk.status;

    if (atk.status == 101 && atk.acceptValid) {
        result.isWebSocket = true;
        result.crossOriginAccepted = true;
        result.detail = "upgrade completed (101 + valid Sec-WebSocket-Accept) with a cross-origin Origin: "
                        + result.attackerOrigin;
        return result;
    }

    // 2) Attacker Origin refused -> a no-Origin control distinguishes "the
    // endpoint validates Origin" from "not a WebSocket endpoint at all".
    const Shake ctl = handshake(req, QString());
    result.controlStatus = ctl.status;
    if (ctl.status == 101 && ctl.acceptValid) {
        result.isWebSocket = true;
        result.originValidated = true;
        result.detail = "WebSocket endpoint refused the cross-origin handshake (attacker status "
                        + QString::number(atk.status) + ") -- Origin appears validated";
    } else {
        result.detail = "no valid WebSocket upgrade observed (attacker status "
                        + QString::number(atk.status) + ", control status "
                        + QString::number(ctl.status) + ")";
    }
    return result;
}

} // namespace Nullock::Core::WsProbe

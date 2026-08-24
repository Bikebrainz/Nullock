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
    const bool authed = hasCredential(req.headers);

    // Grade a cross-origin acceptance. A 101 + valid accept alone only proves the
    // Origin wasn't validated. It's a CONFIRMED hijack only when a session
    // credential rides along AND the socket actually GATES on that session --
    // which we verify by RE-ISSUING the same cross-origin handshake with the
    // credential STRIPPED (the "authed baseline"): if that no-credential baseline
    // ALSO upgrades, the socket ignores the session, so the cross-origin accept
    // is the expected behaviour of a public WS (a LEAD), not a credentialed
    // hijack. Only a REFUSED baseline confirms the socket honors the session
    // cross-site. Without a supplied credential there's nothing to confirm -> LEAD.
    auto gradeAccepted = [&](const QString &origin) {
        result.isWebSocket = true;
        result.attackerOrigin = origin;
        bool confirmed = false;
        if (authed) {
            Request bare = req;
            bare.headers = stripCredentials(req.headers);
            const Shake base = handshake(bare, origin);   // same Origin, credential removed
            result.controlStatus = base.status;           // the no-credential baseline status
            // Only a baseline that actually RESPONDED and refused the upgrade
            // confirms a hijack; a transient reconnect failure must NOT (pure,
            // unit-tested -- see wsConfirmsHijack).
            confirmed = wsConfirmsHijack(base.ok, base.status, base.acceptValid);
        }
        if (confirmed) {
            result.crossOriginAccepted = true;
            result.detail = "upgrade completed (101 + valid Sec-WebSocket-Accept) cross-origin (Origin "
                            + origin + ") carrying the supplied session credential, while the same "
                              "handshake WITHOUT the credential was refused (status "
                            + QString::number(result.controlStatus) + ") -- the socket honors the "
                              "session cross-site: CSWSH";
        } else {
            result.originNotValidated = true;
            result.detail = authed
                ? "upgrade completed cross-origin (Origin " + origin + ") but the SAME handshake "
                  "without the credential ALSO upgraded -- the socket ignores the session and accepts "
                  "any Origin regardless of authentication; Origin is not validated, but this is not a "
                  "credentialed hijack (LEAD, not CSWSH)"
                : "upgrade completed cross-origin (Origin " + origin + ") but NO session credential "
                  "was supplied -- Origin is not validated; confirm the socket is cookie-gated before "
                  "treating as CSWSH (a public WS accepting any Origin is expected)";
        }
    };

    // 1) Sweep a set of malicious Origins: the foreign sentinel, the "null"
    // bypass (sandboxed iframe / cross-scheme redirect), then host-derived
    // variants that defeat a naive endsWith/startsWith/contains allow-list. The
    // FIRST valid cross-origin upgrade grades and returns -- testing only the
    // sentinel would miss an allow-list that refuses it yet accepts a subdomain
    // variant (the false negative cswsh-subdomain models).
    QStringList origins;
    origins << result.attackerOrigin << QStringLiteral("null");
    origins << originVariants(req.host);
    origins << schemePortVariants(req.host, req.tls, req.port);

    int firstStatus = -1;
    bool anyConnected = false;   // did ANY origin variant get a real response?
    QString firstError;
    for (const QString &origin : origins) {
        const Shake s = handshake(req, origin);
        if (firstStatus < 0) {
            firstStatus = s.status;
            result.attackerStatus = s.status;
            firstError = s.error;
        }
        if (!wsHandshakeDead(s.ok, s.status)) anyConnected = true;
        if (s.status == 101 && s.acceptValid) { gradeAccepted(origin); return result; }
    }
    // A dead host answers NONE of the variants; only then bail. A transient
    // failure on the FIRST origin used to abort here before the subdomain/scheme
    // variants were tried -- so a real cross-origin upgrade on a later variant
    // was missed (a false negative). Bail only when EVERY variant came back dead.
    if (!anyConnected) { result.error = firstError; return result; }

    // 2) Every malicious Origin refused -> a no-Origin control distinguishes "the
    // endpoint validates Origin" from "not a WebSocket endpoint at all".
    const Shake ctl = handshake(req, QString());
    result.controlStatus = ctl.status;
    if (ctl.status == 101 && ctl.acceptValid) {
        result.isWebSocket = true;
        result.originValidated = true;
        result.detail = "WebSocket endpoint refused every cross-origin variant ("
                        + QString::number(origins.size()) + " Origins incl. null + host-derived "
                          "subdomain/affix bypasses) while the no-Origin control upgraded -- Origin "
                          "appears validated";
    } else {
        result.detail = "no valid WebSocket upgrade observed (first attacker status "
                        + QString::number(firstStatus) + ", control status "
                        + QString::number(ctl.status) + ")";
    }
    return result;
}

} // namespace Nullock::Core::WsProbe

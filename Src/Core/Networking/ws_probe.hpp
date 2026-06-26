#pragma once

// Cross-Site WebSocket Hijacking (CSWSH, CWE-1385). A WebSocket endpoint that
// completes the upgrade handshake without validating the Origin header lets any
// web page the victim visits open an authenticated socket to it (cookies ride
// along), then read/write on the victim's behalf -- a CSRF that survives
// SameSite because the WS handshake is a top-level GET.
//
// The passive scanner already flags a cross-origin 101 it happens to OBSERVE in
// proxied traffic; this is the ACTIVE probe: it sends a real upgrade handshake
// carrying an attacker Origin and confirms the bug only when the server returns
// 101 Switching Protocols AND a correct Sec-WebSocket-Accept (RFC 6455: the
// base64 SHA-1 of our key + the magic GUID). Requiring a valid accept proves
// the responder is a genuine WebSocket server, not something that 101s blindly,
// so the finding is sound. If the attacker Origin is refused, a control
// handshake (no Origin) tells apart "endpoint validates Origin" (good posture)
// from "not a WebSocket endpoint".

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::WsProbe {

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;                         // wss:// when true
    QString basePath = QStringLiteral("/");
    QString attackerOrigin;                      // empty -> a default sentinel origin
    QList<QPair<QString, QString>> headers;      // optional (e.g. Cookie for an authed socket)
};

struct Result {
    bool    isWebSocket        = false;  // a valid handshake (101 + correct accept) was seen
    bool    crossOriginAccepted = false; // CONFIRMED CSWSH: a session credential was supplied
                                         // AND the cross-origin handshake still completed
    bool    originNotValidated  = false; // LEAD: cross-origin handshake completed but NO
                                         // credential was supplied -- Origin isn't validated,
                                         // but a public/unauthenticated WS accepting any
                                         // Origin is expected, not a hijack. Confirm the
                                         // socket is cookie-gated before treating as CSWSH.
    bool    originValidated     = false; // attacker Origin refused but a control handshake works
    int     attackerStatus      = 0;
    int     controlStatus       = 0;
    QString attackerOrigin;
    QString detail;
    QString error;
};

// Send a cross-origin upgrade handshake (and a no-Origin control if it's
// refused). Confirms CSWSH only on 101 + a correct Sec-WebSocket-Accept.
Result test(const Request &req);

// --- Pure helpers, exposed for the unit test (no I/O; in ws_logic.cpp) ---
//   expectedAccept   -- RFC 6455 base64(SHA1(key + GUID)) (known test vector).
//   headerValue      -- value of a header from a response header block.
//   statusFromHeaderBlock -- numeric status from the first line.
//   buildHandshake   -- render the upgrade request; {} on CR/LF in basePath/host.
QByteArray expectedAccept(const QByteArray &keyB64);
QString headerValue(const QByteArray &headerBlock, const char *name);
int statusFromHeaderBlock(const QByteArray &headerBlock);
QByteArray buildHandshake(const Request &req, const QString &origin, const QByteArray &key);
// Did the caller supply an ambient credential (Cookie / Authorization)? A
// cross-origin 101 is only a CONFIRMED hijack when a session rides along.
bool hasCredential(const QList<QPair<QString, QString>> &headers);

} // namespace Nullock::Core::WsProbe

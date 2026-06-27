#pragma once

// JWT attack toolkit. Decode + weakness analysis + the three classic
// forging attacks, all offline (no network) so they're safe to run on
// any token you've captured.
//
// Burp ships JWT support only via the (paid) "JWT Editor" extension.
// Nullock does it in the core:
//   - decode header + payload, surface every claim
//   - analyse for alg:none, missing/!past exp, weak HMAC, privilege
//     claims worth tampering, kid injection surface
//   - brute-force the HS256 secret against a wordlist (QMessageAuth)
//   - forge: alg:none (strip signature) and HS256 (re-sign once the
//     secret is known -- also the primitive for the RS256->HS256
//     confusion attack, signing with the server's RSA public key bytes)

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::JwtTool {

struct Decoded {
    bool       ok = false;
    bool       payloadOk = false;  // the payload parsed as a JSON object. When false,
                                   // d.payload is empty and analyze() must NOT read it
                                   // as "no claims" (that fabricated a false jwt-no-exp).
    QString    error;
    QString    headerJson;     // pretty-printed
    QString    payloadJson;    // pretty-printed
    QString    alg;
    QString    typ;
    QString    kid;
    QByteArray signature;      // raw signature bytes (decoded from b64url)
    QByteArray signingInput;   // exact bytes that were signed: "header.payload"
    QJsonObject header;
    QJsonObject payload;
};

// Parse a compact JWS ("a.b.c"). Tolerant of missing signature (a.b or
// a.b.). Returns ok=false with a reason if the structure is wrong.
Decoded decode(const QString &token);

struct Weakness {
    QString id;        // stable kind, e.g. "jwt-alg-none"
    QString severity;  // critical | high | medium | low | info
    QString detail;
};

// Static analysis of a decoded token. `nowEpoch` lets callers pin the
// clock (tests); pass 0 to use the system clock.
QList<Weakness> analyze(const Decoded &d, qint64 nowEpoch = 0);

// Exposed for tests: is a `kid` worth flagging for injection testing? Risky when
// it contains anything outside the conservative key-id allowlist [A-Za-z0-9._-]
// (or a ".." traversal) -- a real kid is an opaque id, so any other char is a
// path-traversal / SQLi / command-injection lead in the server's key lookup.
bool kidLooksRisky(const QString &kid);

// Try each candidate as the HS256/384/512 secret. Returns the first that
// verifies the signature, or an empty string if none match.
QString bruteHmac(const Decoded &d, const QStringList &candidates);

// Sign "headerJson.payloadJson" with HMAC (alg taken from the header
// object; defaults HS256) and return the full compact token. `secret`
// is the HMAC key -- for the RS256->HS256 confusion attack, pass the
// server's PEM public key bytes here.
QString signHmac(const QJsonObject &header,
                 const QJsonObject &payload,
                 const QByteArray &secret);

// Forge an alg:none token from a decoded one, applying optional claim
// overrides to the payload. Signature is empty (the alg:none bypass).
QString forgeNone(const Decoded &d, const QJsonObject &claimOverrides = {});

} // namespace Nullock::Core::JwtTool

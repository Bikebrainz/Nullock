#pragma once

// Active JWT attack probe (CWE-347 / CWE-345). JwtTool decodes, analyses, and
// FORGES tokens offline; this is the ACTIVE half -- it sends forged tokens to a
// live endpoint and confirms whether the server ACCEPTS them, the test that
// turns a static weakness into a proven auth bypass. Burp only does JWT testing
// through a paid extension; this is core.
//
// Soundness via calibration: first send the captured VALID token and record its
// (authorized) status, then a signature-corrupted token and record its
// (rejected) status. We only judge acceptance when those differ -- i.e. the
// endpoint actually authenticates -- so an endpoint that 200s everything (or
// 401s everything) yields "inconclusive", never a false positive. A forged
// token is "accepted" only when its response matches the VALID baseline.
//
// Attacks: alg:none (and case/empty/absent variants), signature-not-verified
// (a token with a genuinely-invalid signature is still accepted), weak-HMAC-
// secret (crack the HS256 secret against a wordlist, then re-sign a tampered
// token), and -- when the token is asymmetric (RS*/ES*/PS*) and a public key is
// supplied -- RS256->HS256 algorithm confusion (re-sign as HS256 using the
// public-key bytes as the HMAC secret). Each is run independently so a server
// with several flaws reports them all, and every candidate hit is re-confirmed
// on a second send so a transient throttle can't flip the verdict.
//
// When no `location` is given it FANS OUT across the common carriers
// (Authorization: Bearer, the usual cookie names, X-Auth-Token/X-Access-Token),
// testing each independently and tagging hits with the carrier. A request body
// (Request.body) rides on every shot so body-bearing POST/PUT routes calibrate,
// and acceptance is content-aware (status + body length) so a generic 200 isn't
// mistaken for a real authorized one. An asymmetric token with no public key is
// surfaced as "algorithm-confusion not tested", not silently passed.

#include "jwt_tool.hpp"

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::JwtProbe {

struct Hit {
    QString attack;    // "alg-none" | "signature-not-verified" | "weak-secret" | "alg-confusion" | "blank-secret" | "kid-injection"
    QString kind;      // finding kind (jwt-alg-none | jwt-signature-not-verified | jwt-weak-secret | jwt-alg-confusion | jwt-blank-secret | jwt-kid-injection)
    QString detail;
    QString forged;    // the forged token that was accepted
    QString carrier;   // where the forgery was accepted (e.g. "Authorization: Bearer", "cookie:jwt")
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;
    QString token;                          // a captured, currently-valid JWT
    QString location;                       // ""/"bearer" (default) | "header:Name" | "cookie:name"
    QString publicKeyPem;                   // server public key, for RS256->HS256 confusion (optional)
    QByteArray body;                        // request body to send on EVERY shot (write routes)
    QString contentType;                    // body Content-Type (default application/json)
    QStringList secretWordlist;             // HS256 crack candidates (empty -> a small built-in list)
    QList<QPair<QString, QString>> headers; // extra request headers (cookies, etc.)
};

struct Result {
    bool    vulnerable  = false;
    bool    calibrated  = false;            // valid != rejected -> the endpoint authenticates
    int     authStatus  = 0;                // status with the valid token
    int     rejectStatus = 0;               // status with a signature-corrupted token
    int     requestsSent = 0;
    QList<Hit> hits;
    QString error;                          // set when inconclusive / unusable
};

// Send the valid token (baseline), a corrupted token (calibration), then the
// forgeries; flag only forgeries the endpoint accepts as the valid baseline.
Result test(const Request &req);

// --- Pure forgery/request builders, exposed for the unit test (jwt_probe_logic.cpp) ---
//   buildRequest    -- render a shot; {} on CR/LF in any field; drops secondary
//                      credentials on the no-token calibration shot.
//   corruptSignature-- flip a DECODED signature byte (avoids the base64-padding
//                      round-trip that would re-accept ~1/16 of tokens).
//   algNoneVariants -- the 6 alg:none bypass tokens (case/empty/absent).
//   blankSecretVariants -- HS256/384/512 signed with an EMPTY key (blank secret).
//   kidInjectionVariants -- HS256/384/512 tokens with a malicious `kid` (path
//                      traversal to an empty file like /dev/null) signed empty-key.
//   isCredentialHeader / defaultSecrets -- helpers exposed for coverage.
QByteArray buildRequest(const Request &req, const QString &token);
QString corruptSignature(const QString &token);
QStringList algNoneVariants(const JwtTool::Decoded &d);
QStringList blankSecretVariants(const JwtTool::Decoded &d);
QStringList kidInjectionVariants(const JwtTool::Decoded &d);
bool isCredentialHeader(const QString &name);
QStringList defaultSecrets();

} // namespace Nullock::Core::JwtProbe

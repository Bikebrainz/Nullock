// Regression corpus for the active JWT probe's pure forgery/request builders
// (no network):
//   - corruptSignature: flips a DECODED signature byte (not a base64 char, which
//     could land in dropped padding and round-trip to the SAME bytes -> a false
//     "signature not verified"); appends a junk sig to a token that has none;
//   - algNoneVariants: the 6 alg:none bypass tokens (none/None/NONE/nOnE/empty/
//     absent), each header.payload. with an empty third segment;
//   - buildRequest: the Authorization/header/cookie carriers, the no-token
//     calibration shot (no auth + secondary credentials dropped), the body, and
//     CR/LF guards on every field.
//
// Run via:  ctest -R jwt_probe -V

#include "jwt_probe.hpp"
#include "jwt_tool.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core;            // for JwtTool::
using namespace Nullock::Core::JwtProbe;  // for buildRequest, corruptSignature, ...

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QByteArray b64uDecode(const QString &s) {
    return QByteArray::fromBase64(s.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}
QString algOf(const QString &variant) {                 // alg field of a token's header
    const QByteArray hdr = b64uDecode(variant.split('.').value(0));
    return QJsonDocument::fromJson(hdr).object().value("alg").toString();
}
bool headerHasAlg(const QString &variant) {
    const QByteArray hdr = b64uDecode(variant.split('.').value(0));
    return QJsonDocument::fromJson(hdr).object().contains("alg");
}
Request mk() { Request r; r.host = "victim.tld"; r.basePath = "/api/me"; r.method = "GET"; return r; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // A real HS256 token to attack.
    QJsonObject hdr; hdr["alg"] = "HS256"; hdr["typ"] = "JWT";
    QJsonObject pl;  pl["sub"] = "alice"; pl["role"] = "user";
    const QString token = JwtTool::signHmac(hdr, pl, QByteArray("secret"));
    const JwtTool::Decoded d = JwtTool::decode(token);
    chk("setup: token signs + decodes", !token.isEmpty() && d.ok && d.signature.size() == 32);

    // ===== corruptSignature ==============================================
    {
        const QString c = corruptSignature(token);
        const QStringList tp = token.split('.'), cp = c.split('.');
        chk("corrupt: header+payload unchanged", cp.size() == 3 && cp[0] == tp[0] && cp[1] == tp[1]);
        chk("corrupt: signature actually changed", cp[2] != tp[2]);
        const QByteArray cs = b64uDecode(cp[2]);
        chk("corrupt: decoded sig same length, differs by exactly the first byte",
            cs.size() == d.signature.size() && cs.size() == 32
            && cs[0] != d.signature[0] && cs.mid(1) == d.signature.mid(1));
        chk("corrupt: deterministic (same in == same out)", corruptSignature(token) == c);
    }
    chk("corrupt: a 2-part token (no sig) gets a junk 3rd segment",
        corruptSignature("aaa.bbb").split('.').size() == 3
        && !corruptSignature("aaa.bbb").split('.').value(2).isEmpty());
    chk("corrupt: a token with an EMPTY sig (a.b.) gets a junk 3rd segment",
        !corruptSignature("aaa.bbb.").split('.').value(2).isEmpty());
    // A 3-part token whose signature segment is PRESENT but decodes to zero bytes
    // (a single base64 char) must take the empty-decoded-sig guard -- NOT sig[0]^=1
    // on an empty QByteArray (that would be an out-of-bounds write). It still
    // yields a valid 3-part token with a non-empty (junk) signature.
    {
        const QStringList cp = corruptSignature("aaa.bbb.X").split('.');
        chk("corrupt: a present-but-undecodable sig is guarded (no OOB), stays 3-part w/ non-empty sig",
            cp.size() == 3 && !cp.value(2).isEmpty());
    }

    // ===== algNoneVariants ===============================================
    {
        const QStringList v = algNoneVariants(d);
        chk("algNone: 6 variants", v.size() == 6);
        bool allEmptySig = true, payloadStable = true;
        const QString basePayload = token.split('.').value(1);
        for (const QString &t : v) {
            const QStringList p = t.split('.');
            if (p.size() != 3 || !p[2].isEmpty()) allEmptySig = false;   // header.payload. (empty sig)
            if (p.value(1) != basePayload) payloadStable = false;
        }
        chk("algNone: every variant is header.payload. (empty signature)", allEmptySig);
        chk("algNone: payload is preserved across variants", payloadStable);
        chk("algNone: covers none/None/NONE/nOnE",
            algOf(v[0]) == "none" && algOf(v[1]) == "None" && algOf(v[2]) == "NONE" && algOf(v[3]) == "nOnE");
        chk("algNone: covers the empty-string alg", algOf(v[4]).isEmpty() && headerHasAlg(v[4]));
        chk("algNone: covers the absent-alg header", !headerHasAlg(v[5]));
    }

    // ===== buildRequest carriers =========================================
    {
        const QByteArray r = buildRequest(mk(), "TOK");
        chk("build: default carrier -> Authorization: Bearer", r.contains("Authorization: Bearer TOK\r\n"));
        chk("build: request line", r.startsWith("GET /api/me HTTP/1.1\r\n"));

        Request hr = mk(); hr.location = "header:X-Auth-Token";
        const QByteArray rh = buildRequest(hr, "TOK");
        chk("build: header carrier -> raw header value (no Bearer)",
            rh.contains("X-Auth-Token: TOK\r\n") && !rh.contains("Bearer"));

        Request cr = mk(); cr.location = "cookie:jwt";
        chk("build: cookie carrier -> Cookie: name=token",
            buildRequest(cr, "TOK").contains("Cookie: jwt=TOK\r\n"));
    }

    // ===== buildRequest no-token calibration shot ========================
    {
        Request r = mk();
        r.headers.append({QStringLiteral("Cookie"), QStringLiteral("session=abc")});
        r.headers.append({QStringLiteral("X-Api-Key"), QStringLiteral("k")});
        r.headers.append({QStringLiteral("X-Trace"), QStringLiteral("t")});
        const QByteArray noTok = buildRequest(r, QString());
        chk("build: no-token shot sends NO Authorization", !noTok.contains("Authorization:"));
        chk("build: no-token shot drops the Cookie credential", !noTok.contains("session=abc"));
        chk("build: no-token shot drops X-Api-Key credential", !noTok.contains("X-Api-Key"));
        chk("build: no-token shot keeps a non-credential header", noTok.contains("X-Trace: t\r\n"));
        // With a token, the JWT is the SOLE credential: the injected carrier is
        // sent, but every carried secondary credential (session cookie, api key)
        // is stripped -- so a "bypass" verdict can only mean the forged JWT
        // itself authorized the request, not a session cookie riding along.
        // Non-credential headers still ride along.
        const QByteArray withTok = buildRequest(r, "TOK");
        chk("build: WITH a token, the JWT carrier IS sent",
            withTok.contains("Authorization: Bearer TOK\r\n"));
        chk("build: WITH a token, secondary Cookie credential is STRIPPED",
            !withTok.contains("session=abc"));
        chk("build: WITH a token, X-Api-Key credential is STRIPPED",
            !withTok.contains("X-Api-Key"));
        chk("build: WITH a token, a non-credential header is kept",
            withTok.contains("X-Trace: t\r\n"));
    }

    // ===== buildRequest body + CR/LF guards ==============================
    {
        Request r = mk(); r.method = "POST"; r.body = "{\"x\":1}";
        const QByteArray rr = buildRequest(r, "TOK");
        chk("build: body -> Content-Type + Content-Length + body",
            rr.contains("Content-Type: application/json\r\n")
            && rr.contains("Content-Length: 7\r\n") && rr.endsWith("{\"x\":1}"));
        Request bh = mk(); bh.host = "victim.tld\r\nEvil: 1";
        chk("build: CR/LF host -> abort {}", buildRequest(bh, "TOK").isEmpty());
        Request bt = mk();
        chk("build: CR/LF token -> abort {}", buildRequest(bt, "TOK\r\nEvil: 1").isEmpty());
        Request bl = mk(); bl.location = "header:X-Auth\r\nEvil: 1";
        chk("build: CR/LF carrier name -> abort {}", buildRequest(bl, "TOK").isEmpty());
        // audit-3: contentType is spliced into the Content-Type header -> guard it.
        Request bc = mk(); bc.method = "POST"; bc.body = "{\"x\":1}";
        bc.contentType = "application/json\r\nX-Smuggled: 1";
        chk("build: CR/LF contentType -> abort {}", buildRequest(bc, "TOK").isEmpty());

        // Carried framing/encoding headers must be dropped so the ones this builder
        // forces stand alone -- else body-length grading is corrupted or the scanner
        // emits its own CL.TE smuggling/desync.
        Request pae = mk(); pae.method = "POST"; pae.body = "{\"x\":1}";
        pae.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        pae.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        pae.headers.append(qMakePair(QString("Connection"), QString("keep-alive")));
        const QByteArray p = buildRequest(pae, "TOK");
        chk("build: carried Accept-Encoding dropped -> only forced identity",
            !p.contains("gzip") && p.contains("Accept-Encoding: identity\r\n")
            && p.toLower().count("accept-encoding:") == 1);
        chk("build: carried Transfer-Encoding dropped -> only computed Content-Length",
            !p.contains("Transfer-Encoding") && p.contains("Content-Length: 7\r\n"));
        chk("build: carried Connection dropped -> only forced close",
            !p.contains("keep-alive") && p.contains("Connection: close\r\n"));
        Request gc = mk(); gc.method = "POST"; gc.body = "{\"x\":1}"; gc.contentType = "application/xml";
        chk("build: a clean custom contentType still builds",
            buildRequest(gc, "TOK").contains("Content-Type: application/xml\r\n"));
        // A caller-supplied Content-Length must be DROPPED: on a bodyless shot it
        // would make the server wait for a body that never comes (hang/desync); on
        // a body shot it must be replaced by the correct computed length. This drop
        // (the header loop's Content-Length skip) was untested.
        Request clg = mk();   // bodyless GET
        clg.headers.append({ QStringLiteral("Content-Length"), QStringLiteral("999") });
        chk("build: a caller Content-Length is dropped on a bodyless shot (no desync)",
            !buildRequest(clg, "TOK").contains("Content-Length"));
        Request clp = mk(); clp.method = "POST"; clp.body = "{\"x\":1}";
        clp.headers.append({ QStringLiteral("Content-Length"), QStringLiteral("999") });
        const QByteArray rclp = buildRequest(clp, "TOK");
        chk("build: a caller Content-Length is replaced by the computed one (7, not 999)",
            rclp.contains("Content-Length: 7\r\n") && !rclp.contains("Content-Length: 999"));
    }

    // ===== isCredentialHeader / defaultSecrets ===========================
    chk("isCredentialHeader: Cookie", isCredentialHeader("Cookie"));
    chk("isCredentialHeader: Authorization", isCredentialHeader("authorization"));
    chk("isCredentialHeader: X-Auth-Token (contains auth/token)", isCredentialHeader("X-Auth-Token"));
    chk("isCredentialHeader: X-Trace -> false", !isCredentialHeader("X-Trace"));
    chk("defaultSecrets: non-empty + includes 'secret'", defaultSecrets().contains("secret"));

    // ===== blankSecretVariants: HS256/384/512 signed with an EMPTY key ===
    {
        const QStringList v = blankSecretVariants(d);
        chk("blank-secret: one variant per HS alg (>=3)", v.size() >= 3);
        bool has256 = false, has384 = false, has512 = false, allEmptyKey = true, claimsOk = true;
        for (const QString &t : v) {
            const QString a = algOf(t);
            if (a == "HS256") has256 = true;
            if (a == "HS384") has384 = true;
            if (a == "HS512") has512 = true;
            const JwtTool::Decoded fd = JwtTool::decode(t);
            if (fd.payload.value("sub").toString() != "alice") claimsOk = false;
            // empty-key signature must DIFFER from a non-empty-key sig over the same
            // header+payload (proves the key is genuinely empty, not 'secret') AND
            // equal an independent empty-key re-derivation.
            if (t.section('.', 2, 2) == JwtTool::signHmac(fd.header, fd.payload, QByteArray("secret")).section('.', 2, 2))
                allEmptyKey = false;
            if (t != JwtTool::signHmac(fd.header, fd.payload, QByteArray()))
                allEmptyKey = false;
        }
        chk("blank-secret: covers HS256/HS384/HS512", has256 && has384 && has512);
        chk("blank-secret: every variant is empty-key signed (and != a real key)", allEmptyKey);
        chk("blank-secret: claims preserved across variants (sub=alice)", claimsOk);
    }

    // ===== kidInjectionVariants: malicious kid + empty-key HS family =====
    {
        const QStringList v = kidInjectionVariants(d);
        chk("kid-injection: kids x HS-algs (>=6 variants)", v.size() >= 6);
        bool allHs = true, allKid = true, anyTraversal = false, anyNullDevice = false;
        bool has384 = false, has512 = false;
        for (const QString &t : v) {
            const QString a = algOf(t);
            if (a != "HS256" && a != "HS384" && a != "HS512") allHs = false;
            if (a == "HS384") has384 = true;
            if (a == "HS512") has512 = true;
            const QJsonObject h = QJsonDocument::fromJson(b64uDecode(t.split('.').value(0))).object();
            const QString kid = h.value("kid").toString();
            if (!h.contains("kid") || kid.isEmpty()) allKid = false;
            if (kid.contains("..")) anyTraversal = true;
            if (kid.contains("/dev/null") || kid.contains("NUL")) anyNullDevice = true;
        }
        chk("kid-injection: every variant is an HS-family alg", allHs);
        chk("kid-injection: HS384 + HS512 variants present (not HS256-only)", has384 && has512);
        chk("kid-injection: every variant carries a non-empty kid header", allKid);
        chk("kid-injection: a path-traversal kid is present", anyTraversal);
        chk("kid-injection: a null-device (/dev/null or NUL) kid is present", anyNullDevice);
        const JwtTool::Decoded fd0 = JwtTool::decode(v.first());
        chk("kid-injection: first variant decodes + a real signature", fd0.ok && fd0.signature.size() >= 32);
        chk("kid-injection: claims preserved (sub=alice)", fd0.payload.value("sub").toString() == "alice");
        chk("kid-injection: empty-key sig != 'secret'-key sig (key really is empty)",
            v.first().section('.', 2, 2)
            != JwtTool::signHmac(fd0.header, fd0.payload, QByteArray("secret")).section('.', 2, 2));
    }

    // ===== acceptance verdict (pure) ====================================
    // The security brain of scan(), extracted from inline lambdas. A false
    // positive brands a secure server JWT-forgeable; a false negative misses a
    // real bypass. Cases pin the exact status-tiebreak and length rules.
    {
        // ---- forgeryAccepted: same status required --------------------
        chk("verdict: forgery with a different status is not accepted",
            !forgeryAccepted(/*x*/403,100, /*valid*/200,100, /*rej*/401,100));
        // A reject baseline with a DIFFERENT status settles it on status alone:
        // an authorized-status forgery is accepted regardless of its body size.
        chk("verdict: authorized-status forgery accepted despite far body len "
            "(status-distinguished reject)",
            forgeryAccepted(200,5000, 200,100, 401,90));
        // Body-only gate (valid & reject share status): length proximity decides.
        chk("verdict: body-only gate, len closer to valid -> accepted",
            forgeryAccepted(200,105, 200,100, 200,500));
        chk("verdict: body-only gate, len closer to reject -> not accepted",
            !forgeryAccepted(200,480, 200,100, 200,500));
        // Strict '<' -- an exact midpoint no longer auto-accepts (valid=100,
        // rej=200 -> midpoint 150; |150-100| == |150-200|).
        chk("verdict: exact midpoint is NOT accepted (strict inequality)",
            !forgeryAccepted(200,150, 200,100, 200,200));

        // ---- corruptLooksAuthorized: the signature-ignored neighbourhood --
        chk("verdict: corrupt page with a different status is not authorized",
            !corruptLooksAuthorized(403,100, 200,100, 50));
        // span==0 (valid.len==noAuth.len) demands an exact length match.
        chk("verdict: zero-span requires exact length match (hit)",
            corruptLooksAuthorized(200,100, 200,100, 100));
        chk("verdict: zero-span requires exact length match (miss by 1)",
            !corruptLooksAuthorized(200,101, 200,100, 100));
        // valid=1000, noAuth=200 -> span 800, neighbourhood = 1/8 = 100.
        chk("verdict: corrupt len within 1/8 span of valid -> authorized",
            corruptLooksAuthorized(200,1050, 200,1000, 200));
        chk("verdict: 1/8-span boundary is inclusive (<=)",
            corruptLooksAuthorized(200,900, 200,1000, 200));   // |100|*8 == 800
        // THE headline FP guard: a verbose reject page sized PAST the midpoint
        // (nearer valid than noAuth) but outside the neighbourhood is NOT
        // "authorized" -- else sig-not-verified fires on a server that rejects.
        chk("verdict: reject page past midpoint but outside neighbourhood is NOT authorized",
            !corruptLooksAuthorized(200,700, 200,1000, 200));  // nearer valid, |300|*8 > 800

        // ---- corruptProbeAccepted: composition + baseline gate --------
        chk("verdict: no forged-rejection baseline -> corrupt never 'accepted'",
            !corruptProbeAccepted(/*rejectHasBaseline*/false, 200,1000, 200,200, 200,1000));
        // Status-gate endpoint (valid 200 vs noAuth 401): a corrupt page that
        // returns the authorized status means the signature was ignored.
        chk("verdict: status-gate, corrupt returns authorized status -> accepted",
            corruptProbeAccepted(true, 200,100, 401,50, 200,999));
        chk("verdict: status-gate, corrupt returns the no-auth status -> not accepted",
            !corruptProbeAccepted(true, 200,100, 401,50, 401,50));
        // Body-only endpoint (valid & noAuth share status): the absolute
        // neighbourhood decides whether the corrupt page was accepted.
        chk("verdict: body-only gate, corrupt in neighbourhood -> accepted",
            corruptProbeAccepted(true, 200,1000, 200,200, 200,1050));
        chk("verdict: body-only gate, corrupt outside neighbourhood -> not accepted",
            !corruptProbeAccepted(true, 200,1000, 200,200, 200,700));
    }

    std::fprintf(stderr, "jwt_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

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
        // With a token, the credentials ride along.
        const QByteArray withTok = buildRequest(r, "TOK");
        chk("build: WITH a token, the Cookie credential is kept", withTok.contains("session=abc"));
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
    }

    // ===== isCredentialHeader / defaultSecrets ===========================
    chk("isCredentialHeader: Cookie", isCredentialHeader("Cookie"));
    chk("isCredentialHeader: Authorization", isCredentialHeader("authorization"));
    chk("isCredentialHeader: X-Auth-Token (contains auth/token)", isCredentialHeader("X-Auth-Token"));
    chk("isCredentialHeader: X-Trace -> false", !isCredentialHeader("X-Trace"));
    chk("defaultSecrets: non-empty + includes 'secret'", defaultSecrets().contains("secret"));

    std::fprintf(stderr, "jwt_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

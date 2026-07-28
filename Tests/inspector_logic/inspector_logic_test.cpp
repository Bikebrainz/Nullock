// Tests for the request/response Inspector
// (Src/Core/Networking/inspector_logic.cpp). Invariants:
//   * request line / status line, headers, cookies, query + body params parse
//     and URL-decode correctly (form + JSON bodies);
//   * a JWT in an Authorization/Bearer header or a cookie is detected and its
//     header + payload decoded;
//   * Set-Cookie name/value/attributes split out on responses;
//   * malformed / empty input is default-safe (no crash), huge input is bounded.
//
// Run via:  ctest -R inspector_logic -V

#include "inspector_logic.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core::Inspector;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

QString b64url(const QByteArray &b) {
    return QString::fromLatin1(
        b.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}
QString makeJwt(const QJsonObject &h, const QJsonObject &p) {
    return b64url(QJsonDocument(h).toJson(QJsonDocument::Compact)) + "."
         + b64url(QJsonDocument(p).toJson(QJsonDocument::Compact)) + ".sig_abc123";
}

// Find a name/value pair in an array-of-{name,value}.
QString findVal(const QJsonArray &a, const QString &name) {
    for (const QJsonValue &v : a)
        if (v.toObject().value("name").toString() == name)
            return v.toObject().value("value").toString();
    return QStringLiteral("\x01<absent>");
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QString jwt = makeJwt(
        QJsonObject{ { "alg", "HS256" }, { "typ", "JWT" } },
        QJsonObject{ { "sub", "alice" }, { "role", "admin" } });

    // ----- inspectRequest: form body + query + cookies + JWT header -----
    {
        const QByteArray raw = QString(
            "POST /search?q=hello+world&n=2 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer " + jwt + "\r\n"
            "Cookie: sid=abc123; theme=dark\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "user=alice&pass=p%40ss+word").toUtf8();
        const QJsonObject r = inspectRequest(raw);

        chk("req method", r.value("method").toString() == "POST");
        chk("req path", r.value("path").toString() == "/search");
        chk("req version", r.value("version").toString() == "HTTP/1.1");
        chk("req query param decoded (+->space)",
            findVal(r.value("queryParams").toArray(), "q") == "hello world");
        chk("req query param n", findVal(r.value("queryParams").toArray(), "n") == "2");
        chk("req cookie sid", findVal(r.value("cookies").toArray(), "sid") == "abc123");
        chk("req cookie theme", findVal(r.value("cookies").toArray(), "theme") == "dark");
        chk("req contentType", r.value("contentType").toString().contains("form-urlencoded"));
        chk("req bodyKind form", r.value("bodyKind").toString() == "form");
        chk("req form param user", findVal(r.value("bodyParams").toArray(), "user") == "alice");
        chk("req form param pass decoded (%40->@, +->space)",
            findVal(r.value("bodyParams").toArray(), "pass") == "p@ss word");
        // JWT from the Authorization: Bearer header.
        const QJsonArray jwts = r.value("jwts").toArray();
        chk("req found 1 jwt", jwts.size() == 1);
        chk("req jwt alg", jwts.size() == 1 && jwts[0].toObject().value("alg").toString() == "HS256");
        chk("req jwt where", jwts.size() == 1 && jwts[0].toObject().value("where").toString() == "header:Authorization");
        chk("req jwt payload role", jwts.size() == 1
            && jwts[0].toObject().value("payload").toObject().value("role").toString() == "admin");
    }

    // ----- decodeJwt guards (both previously untested) -------------------
    {
        // (a) alg-gate: an x.y.z whose header decodes to a JSON object WITHOUT "alg"
        // is NOT a JWT (stops flagging arbitrary structured header/cookie values).
        const QString noAlg =
            b64url(QJsonDocument(QJsonObject{{"foo", 1}}).toJson(QJsonDocument::Compact)) + "."
          + b64url(QJsonDocument(QJsonObject{{"bar", 2}}).toJson(QJsonDocument::Compact)) + ".sig_abc123";
        const QByteArray raw =
            ("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + noAlg + "\r\n\r\n").toUtf8();
        chk("jwt alg-gate: an x.y.z header JSON with no 'alg' is NOT a JWT",
            inspectRequest(raw).value("jwts").toArray().isEmpty());

        // (b) a valid JOSE header with a NON-JSON payload is still reported, with
        // payload:null (graceful partial decode -- not dropped, not a crash).
        const QString nullPay =
            b64url(QJsonDocument(QJsonObject{{"alg", "none"}}).toJson(QJsonDocument::Compact)) + "."
          + b64url(QByteArray("notjson")) + ".sig_abc123";
        const QByteArray raw2 =
            ("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + nullPay + "\r\n\r\n").toUtf8();
        const QJsonArray j2 = inspectRequest(raw2).value("jwts").toArray();
        chk("jwt payload:null: valid header + non-JSON payload -> one jwt, alg=none, payload null",
            j2.size() == 1 && j2[0].toObject().value("alg").toString() == "none"
            && j2[0].toObject().value("payload").isNull());
    }

    // ----- inspectRequest: JSON body -----
    {
        const QByteArray raw =
            "PUT /api/user HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "{\"name\":\"bob\",\"age\":30,\"admin\":true}";
        const QJsonObject r = inspectRequest(raw);
        chk("req json bodyKind", r.value("bodyKind").toString() == "json");
        chk("req json param name", findVal(r.value("bodyParams").toArray(), "name") == "bob");
        chk("req json param age", findVal(r.value("bodyParams").toArray(), "age") == "30");
        chk("req json param admin", findVal(r.value("bodyParams").toArray(), "admin") == "true");
    }

    // ----- audit-12: a '{'-sniffed body that is NOT json and NOT declared json ----
    // The bodyKind sniff accepts any body starting with '{'. When such a body fails
    // to parse AND the Content-Type never says json, the classifier used to fall out
    // of the branch leaving bodyKind EMPTY -- the same value the Inspector uses for
    // "no body at all" -- even though bodySize is non-zero. It must degrade to the
    // ordinary opaque-body label instead.
    {
        const QByteArray raw =
            "POST /tmpl HTTP/1.1\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "{{ user.name }} is not json";
        const QJsonObject r = inspectRequest(raw);
        chk("req sniffed-but-invalid json body -> bodyKind 'other', not empty",
            r.value("bodyKind").toString() == "other");
        chk("req sniffed-but-invalid json body still reports its size",
            r.value("bodySize").toInt() == 27);
        chk("req sniffed-but-invalid json body yields no bodyParams",
            r.value("bodyParams").toArray().isEmpty());
        // The neighbouring branches must not shift: a body that does NOT start with
        // '{' is still "other", and a DECLARED-json body that fails to parse is
        // still "json" (the operator needs to see the server was promised JSON).
        const QByteArray plain =
            "POST /t HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nnot json at all";
        chk("req non-'{' opaque body still 'other'",
            inspectRequest(plain).value("bodyKind").toString() == "other");
        const QByteArray badJson =
            "POST /t HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"a\":";
        chk("req DECLARED json that fails to parse is still 'json'",
            inspectRequest(badJson).value("bodyKind").toString() == "json");
        const QByteArray noBody = "GET /t HTTP/1.1\r\nHost: x\r\n\r\n";
        chk("req with no body still has an EMPTY bodyKind (the distinction restored)",
            inspectRequest(noBody).value("bodyKind").toString().isEmpty());
    }

    // ----- audit-3: large JSON integers render EXACTLY (no scientific notation) -
    {
        const QByteArray raw =
            "PUT /api/user HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "{\"user_id\":1234567890123,\"exp\":1719446400}";
        const QJsonObject r = inspectRequest(raw);
        chk("req json 64-bit id exact (not 1.23457e+12)",
            findVal(r.value("bodyParams").toArray(), "user_id") == "1234567890123");
        chk("req json epoch exact (not 1.71945e+09)",
            findVal(r.value("bodyParams").toArray(), "exp") == "1719446400");
    }

    // ----- audit-3: RFC 6265 cookie '+' is literal, NOT form '+'->space --------
    {
        const QByteArray raw =
            "GET / HTTP/1.1\r\n"
            "Host: h\r\n"
            "Cookie: t=YQ+Yg==\r\n"
            "\r\n";
        const QJsonObject r = inspectRequest(raw);
        chk("req cookie '+' preserved (opaque octet, not form-decoded to space)",
            findVal(r.value("cookies").toArray(), "t") == "YQ+Yg==");
    }

    // ----- inspectResponse: status + Set-Cookie + JWT in cookie -----
    {
        const QByteArray raw = QString(
            "HTTP/1.1 302 Found\r\n"
            "Location: /home\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Set-Cookie: session=" + jwt + "; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"
            "\r\n"
            "<html>redirecting</html>").toUtf8();
        const QJsonObject r = inspectResponse(raw);

        chk("resp status", r.value("status").toInt() == 302);
        chk("resp reason", r.value("reason").toString() == "Found");
        chk("resp contentType", r.value("contentType").toString().contains("text/html"));
        const QJsonArray sc = r.value("setCookies").toArray();
        chk("resp setCookie name", sc.size() == 1 && sc[0].toObject().value("name").toString() == "session");
        chk("resp setCookie attributes",
            sc.size() == 1 && sc[0].toObject().value("attributes").toString().contains("HttpOnly")
            && sc[0].toObject().value("attributes").toString().contains("SameSite=Lax"));
        chk("resp bodyPreview", r.value("bodyPreview").toString().contains("redirecting"));
        const QJsonArray jwts = r.value("jwts").toArray();
        chk("resp found jwt in cookie", jwts.size() == 1
            && jwts[0].toObject().value("where").toString() == "cookie:session");
    }

    // ----- non-JWT values are not mis-detected -----
    {
        const QByteArray raw =
            "GET / HTTP/1.1\r\n"
            "Authorization: Bearer not.a.jwt\r\n"
            "X-Api-Key: abcdef0123456789abcdef0123456789\r\n"
            "\r\n";
        const QJsonObject r = inspectRequest(raw);
        chk("non-jwt not detected", r.value("jwts").toArray().isEmpty());
    }

    // ----- default-safe on empty / garbage -----
    {
        const QJsonObject r = inspectRequest(QByteArray());
        chk("empty request -> no crash, empty method", r.value("method").toString().isEmpty());
        const QJsonObject rr = inspectResponse(QByteArray("garbage with no structure"));
        chk("garbage response -> no crash, status 0", rr.value("status").toInt() == 0);
    }
    {
        // headers with no body separator still parse the start line + headers.
        const QJsonObject r = inspectRequest("GET /x HTTP/1.1\r\nHost: h\r\nA: b");
        chk("no-body message parses headers", findVal(r.value("headers").toArray(), "Host") == "h");
        chk("no-body message method", r.value("method").toString() == "GET");
    }

    // ----- bounded: huge body doesn't blow up, preview is capped -----
    {
        QByteArray raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        raw += QByteArray(3 * 1024 * 1024, 'A');       // 3 MiB body
        const QJsonObject r = inspectResponse(raw);
        chk("huge body: status parsed", r.value("status").toInt() == 200);
        chk("huge body: preview capped", r.value("bodyPreview").toString().size() <= kBodyPreview);
    }

    std::fprintf(stderr, "inspector_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

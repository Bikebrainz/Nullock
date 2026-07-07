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

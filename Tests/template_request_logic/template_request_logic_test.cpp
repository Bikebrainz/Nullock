// Tests for the template HTTP request builder
// (Src/Core/Networking/template_request_logic.cpp). Invariants:
//   * {{BaseURL}}/{{Hostname}}/{{payload}}/{{payloadN}} substitution;
//   * payload expansion: cluster (cartesian) and pitchfork (zip), HARD-CAPPED;
//   * CRLF in a substituted value is stripped from the request-line/headers
//     (no header smuggling) but preserved in the length-delimited body;
//   * Host/Content-Length/Connection auto-added when absent; CL is correct;
//   * parseRequest is default-safe (defaults, headers object|array, payloads
//     nested|flat).
//
// Run via:  ctest -R template_request_logic -V

#include "template_request_logic.hpp"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core::TemplateRequest;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool contains(const QByteArray &hay, const char *needle) { return hay.contains(needle); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    Vars v; v.baseUrl = "http://127.0.0.1:39876"; v.hostname = "127.0.0.1";

    // ----- basic GET, no payloads -----
    {
        RequestSpec s; s.method = "GET"; s.path = "/health";
        const auto r = buildRequests(s, v);
        chk("no payloads -> 1 request", r.size() == 1);
        chk("request line", contains(r[0].bytes, "GET /health HTTP/1.1\r\n"));
        chk("auto Host header", contains(r[0].bytes, "Host: 127.0.0.1\r\n"));
        chk("auto Connection close", contains(r[0].bytes, "Connection: close\r\n"));
        chk("ends headers with blank line", contains(r[0].bytes, "\r\n\r\n"));
    }

    // ----- variable substitution -----
    {
        RequestSpec s; s.path = "/x?u={{BaseURL}}&h={{Hostname}}";
        const auto r = buildRequests(s, v);
        chk("BaseURL substituted", contains(r[0].bytes, "u=http://127.0.0.1:39876"));
        chk("Hostname substituted", contains(r[0].bytes, "h=127.0.0.1"));
    }

    // ----- single payload var expansion -----
    {
        RequestSpec s; s.path = "/q={{payload}}";
        s.payloads = { QStringList{ "a", "b", "c" } };
        const auto r = buildRequests(s, v);
        chk("single var -> N requests", r.size() == 3);
        chk("payload a", contains(r[0].bytes, "/q=a "));
        chk("payload c", contains(r[2].bytes, "/q=c "));
        chk("usedPayloads recorded", r[1].usedPayloads == QStringList{ "b" });
    }

    // ----- two vars: cluster (cartesian) vs pitchfork (zip) -----
    {
        RequestSpec s; s.path = "/a={{payload1}}&b={{payload2}}";
        s.payloads = { QStringList{ "1", "2" }, QStringList{ "x", "y" } };
        s.pitchfork = false;
        const auto cb = buildRequests(s, v);
        chk("cluster 2x2 -> 4", cb.size() == 4);
        // Odometer DIRECTION is a behavioral contract, not just a count: the LAST
        // payload var varies FASTEST. A reversed carry would still produce 4
        // requests but reorder them, silently mislabeling which payload produced
        // which request (the usedPayloads the user sees). Lock the exact order.
        chk("cluster order r0 = 1,x", contains(cb[0].bytes, "/a=1&b=x "));
        chk("cluster order r1 = 1,y (last var fastest)", contains(cb[1].bytes, "/a=1&b=y "));
        chk("cluster order r2 = 2,x", contains(cb[2].bytes, "/a=2&b=x "));
        chk("cluster order r3 = 2,y", contains(cb[3].bytes, "/a=2&b=y "));
        chk("cluster usedPayloads track the combo", cb[2].usedPayloads == (QStringList{ "2", "x" }));
        s.pitchfork = true;
        const auto z = buildRequests(s, v);
        chk("pitchfork zip -> 2", z.size() == 2);
        chk("pitchfork pairs 1/x", contains(z[0].bytes, "/a=1&b=x "));
        chk("pitchfork pairs 2/y", contains(z[1].bytes, "/a=2&b=y "));
    }

    // ----- {{payload}} aliases {{payload1}} -----
    {
        RequestSpec s; s.path = "/p={{payload1}}";
        s.payloads = { QStringList{ "z" } };
        chk("{{payload1}} == first var", contains(buildRequests(s, v)[0].bytes, "/p=z "));
    }

    // ----- cap -----
    {
        QStringList big;
        for (int i = 0; i < kMaxRequests + 50; ++i) big << QString::number(i);
        RequestSpec s; s.path = "/q={{payload}}"; s.payloads = { big };
        chk("expansion capped at kMaxRequests", buildRequests(s, v).size() == kMaxRequests);
    }

    // ----- empty payload set -> 0 requests -----
    {
        RequestSpec s; s.path = "/q={{payload}}"; s.payloads = { QStringList{} };
        chk("empty payload set -> 0 requests", buildRequests(s, v).isEmpty());
    }

    // ----- CRLF safety: a payload's CR/LF can't create a new header line -----
    {
        RequestSpec s; s.method = "POST"; s.path = "/q={{payload}}";
        s.headers = { { "X-Test", "{{payload}}" } };   // no body payload here
        s.payloads = { QStringList{ QStringLiteral("v\r\nEvil-Header: 1") } };
        const auto r = buildRequests(s, v);
        // The smuggled header would be a NEW line "\r\nEvil-Header". After
        // stripping CR/LF the text collapses into the X-Test value, so it is
        // never a separate header -- the security property.
        chk("no smuggled header line", !contains(r[0].bytes, "\r\nEvil-Header"));
        chk("payload folded into header value", contains(r[0].bytes, "X-Test: vEvil-Header: 1\r\n"));
        chk("CRLF stripped from path", !contains(r[0].bytes, "/q=v\r\nEvil"));
    }
    // ----- CRLF safety: a template's OWN literal CR/LF (no {{token}}) is stripped
    //       too, not only substituted values -- a hostile nuclei template can't
    //       smuggle a header or split the request line from its authored text. -----
    {
        RequestSpec s; s.method = "GET";
        s.path = QStringLiteral("/a\r\nX-Path-Inject: 1");              // CRLF in path
        s.headers = { { QStringLiteral("X-Foo"),
                        QStringLiteral("bar\r\nX-Injected: evil") } };  // CRLF in header value
        const auto r = buildRequests(s, v);
        chk("literal CRLF in header value not a new header line",
            !contains(r[0].bytes, "\r\nX-Injected: evil"));
        chk("literal CRLF header value folded",
            contains(r[0].bytes, "X-Foo: barX-Injected: evil\r\n"));
        chk("literal CRLF in path not splitting request line",
            !contains(r[0].bytes, "/a\r\nX-Path-Inject"));
    }
    {
        // CRLF in a header NAME must not create a new line either.
        RequestSpec s; s.path = "/";
        s.headers = { { QStringLiteral("X-A\r\nX-B"), QStringLiteral("v") } };
        const auto r = buildRequests(s, v);
        chk("literal CRLF in header name not a new header line",
            !contains(r[0].bytes, "\r\nX-B: v"));
        chk("header name CRLF folded", contains(r[0].bytes, "X-AX-B: v\r\n"));
    }
    // ----- body: length-delimited, so payload CR/LF is preserved (harmless) -----
    {
        RequestSpec s; s.method = "POST"; s.path = "/"; s.body = "data={{payload}}";
        s.payloads = { QStringList{ QStringLiteral("v\r\nX") } };
        const auto r = buildRequests(s, v);
        const int split = r[0].bytes.indexOf("\r\n\r\n");
        const QByteArray body = split >= 0 ? r[0].bytes.mid(split + 4) : QByteArray();
        chk("body keeps payload CRLF verbatim", body == QByteArray("data=v\r\nX"));
        // Content-Length is computed from the FINAL body (9 bytes incl. the CRLF).
        chk("Content-Length counts substituted body", contains(r[0].bytes, "Content-Length: 9\r\n"));
    }

    // ----- Content-Length correct for body -----
    {
        RequestSpec s; s.method = "POST"; s.path = "/"; s.body = "hello world";
        const auto r = buildRequests(s, v);
        chk("Content-Length added + correct", contains(r[0].bytes, "Content-Length: 11\r\n"));
        chk("POST method", contains(r[0].bytes, "POST / HTTP/1.1\r\n"));
    }

    // ----- author-supplied headers win over auto -----
    {
        RequestSpec s; s.path = "/"; s.headers = { { "Connection", "keep-alive" } };
        const auto r = buildRequests(s, v);
        chk("explicit Connection kept", contains(r[0].bytes, "Connection: keep-alive\r\n"));
        chk("no duplicate Connection", r[0].bytes.count("Connection:") == 1);
    }

    // ----- parseRequest default-safe -----
    {
        const RequestSpec s = parseRequest(QJsonObject{});
        chk("parse empty -> GET /", s.method == "GET" && s.path == "/");
    }
    {
        const QJsonObject o = QJsonDocument::fromJson(QByteArray(
            "{\"method\":\"POST\",\"path\":\"/api\",\"headers\":{\"X-A\":\"1\"},"
            "\"body\":\"b={{payload}}\",\"payloads\":[\"p1\",\"p2\"],\"attack\":\"pitchfork\"}"
        )).object();
        const RequestSpec s = parseRequest(o);
        chk("parse method/path", s.method == "POST" && s.path == "/api");
        chk("parse headers object", s.headers.size() == 1 && s.headers[0].first == "X-A");
        chk("parse flat payloads -> 1 var", s.payloads.size() == 1 && s.payloads[0].size() == 2);
        chk("parse attack pitchfork", s.pitchfork);
    }
    {
        const QJsonObject o = QJsonDocument::fromJson(QByteArray(
            "{\"headers\":[{\"name\":\"A\",\"value\":\"1\"},{\"name\":\"B\",\"value\":\"2\"}],"
            "\"payloads\":[[\"a\",\"b\"],[\"c\",\"d\"]]}"
        )).object();
        const RequestSpec s = parseRequest(o);
        chk("parse headers array", s.headers.size() == 2 && s.headers[1].first == "B");
        chk("parse nested payloads -> 2 vars", s.payloads.size() == 2);
    }

    std::fprintf(stderr, "template_request_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

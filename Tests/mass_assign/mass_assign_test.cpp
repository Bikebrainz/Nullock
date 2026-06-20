// Regression corpus for the mass-assignment probe's pure logic (no network):
//   - acceptedStatus: the 2xx gate (a marker echoed in a 4xx error is not a
//     bind -- the headline false-positive fix).
//   - looksJson: JSON vs form-urlencoded sniffing.
//   - buildRequest: CR/LF guards on method / host / path / carried headers,
//     Content-Type framing, and body inclusion.
//
// Run via:  ctest -R mass_assign -V

#include "mass_assign.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::MassAssign;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- acceptedStatus: the 2xx gate (FP fix) --------------------------
    chk("accepted: 200/201/204 -> yes",
        acceptedStatus(200) && acceptedStatus(201) && acceptedStatus(204));
    chk("accepted: 422 validation error -> NO (echo != bind)", !acceptedStatus(422));
    chk("accepted: 400/403 -> NO", !acceptedStatus(400) && !acceptedStatus(403));
    chk("accepted: 3xx -> NO", !acceptedStatus(302));
    chk("accepted: 500 -> NO", !acceptedStatus(500));

    // ---- looksJson ------------------------------------------------------
    chk("json: content-type json", looksJson(QByteArray("x=1"), "application/json"));
    chk("json: form content-type -> false",
        !looksJson(QByteArray("{\"a\":1}"), "application/x-www-form-urlencoded"));
    chk("json: sniff leading brace", looksJson(QByteArray("  {\"a\":1}"), ""));
    chk("json: sniff leading bracket", looksJson(QByteArray("[1,2]"), ""));
    chk("json: form sniffed when no brace", !looksJson(QByteArray("a=1&b=2"), ""));

    // ---- buildRequest: CR/LF guards + framing ---------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "POST"; req.basePath = "/api/users";
        const QByteArray body = "{\"name\":\"x\"}";
        const QByteArray ok = buildRequest(req, true, body);
        chk("build: request line", ok.startsWith("POST /api/users HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));
        chk("build: default Content-Type json", ok.contains("Content-Type: application/json\r\n"));
        chk("build: Content-Length", ok.contains("Content-Length: " + QByteArray::number(body.size()) + "\r\n"));
        chk("build: body appended", ok.endsWith(body));
        const QByteArray form = buildRequest(req, false, "a=1");
        chk("build: default Content-Type form",
            form.contains("Content-Type: application/x-www-form-urlencoded\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header",
            !buildRequest(injHdr, true, body).contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "POST\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, true, body).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, true, body).isEmpty());
        Request badPath = req; badPath.basePath = "/api\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, true, body).isEmpty());
    }

    std::fprintf(stderr, "mass_assign_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

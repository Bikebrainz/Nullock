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

    // ---- reflectionControlUsable: fail-closed control (audit-5) ----------
    // A control that failed at transport is inconclusive -> not usable, so the
    // probe bails instead of fabricating finds on a raw-echo endpoint.
    chk("reflectionControl: transport failure -> NOT usable (fail-closed)",
        !reflectionControlUsable(/*controlOk=*/false, /*junkEchoed=*/false));
    chk("reflectionControl: ok + junk NOT echoed -> usable",
        reflectionControlUsable(true, false));
    chk("reflectionControl: ok + junk echoed (raw-echo endpoint) -> NOT usable",
        !reflectionControlUsable(true, true));

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
        // A carried Accept-Encoding must be dropped so only the forced "identity"
        // survives -- else the server may gzip and the raw-byte marker scan misses a
        // real privileged-field bind (false clean). Mirrors the Host/Content-Length drops.
        Request ae = req;
        ae.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray aeb = buildRequest(ae, true, body);
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            aeb.count("Accept-Encoding:") == 1
            && aeb.contains("Accept-Encoding: identity\r\n") && !aeb.contains("gzip"));
        // Carried Host / Content-Length are dropped (we emit our own once each) and a
        // carried Content-Type wins over the default (deduped): each MUST appear
        // exactly once, else a duplicate Host/Content-Length enables request smuggling
        // and a duplicate Content-Type is ambiguous framing. (Above only locked A-E.)
        Request dup = req;
        dup.headers.append(qMakePair(QString("Host"), QString("attacker.tld")));
        dup.headers.append(qMakePair(QString("Content-Length"), QString("999999")));
        dup.headers.append(qMakePair(QString("Content-Type"), QString("application/xml")));
        const QByteArray db = buildRequest(dup, true, body);
        chk("build: carried Host dropped -> exactly one, victim only",
            db.count("Host:") == 1 && !db.contains("attacker.tld"));
        chk("build: carried Content-Length dropped -> exactly one, real length",
            db.count("Content-Length:") == 1
            && db.contains("Content-Length: " + QByteArray::number(body.size()) + "\r\n"));
        chk("build: carried Content-Type wins + deduped -> exactly one",
            db.count("Content-Type:") == 1 && db.contains("Content-Type: application/xml\r\n"));
    }

    std::fprintf(stderr, "mass_assign_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

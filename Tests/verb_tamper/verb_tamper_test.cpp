// Regression corpus for the verb-tampering probe's pure logic (no network):
//   - overrideAddedNothing: suppress an override identical to the plain carrier.
//   - headIsBypass: HEAD corroboration via Content-Length difference.
//   - caseVariants: the case-variation technique (was advertised but missing).
//   - isDenied / isAllowed: status classification.
//   - buildRequest: CR/LF guards on method / host / path / carried+extra headers.
//
// Run via:  ctest -R verb_tamper -V

#include "verb_tamper.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::VerbTamper;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- status classification ------------------------------------------
    chk("denied: 401/403/404/405", isDenied(401) && isDenied(403) && isDenied(404) && isDenied(405));
    chk("denied: 200/500 not denied", !isDenied(200) && !isDenied(500));
    chk("allowed: 2xx", isAllowed(200) && isAllowed(204) && !isAllowed(301) && !isAllowed(403));

    // ---- overrideAddedNothing: de-dup the ignored override (FP fix) ------
    chk("override: identical to carrier -> added nothing (suppress)",
        overrideAddedNothing(200, QByteArray("data"), 200, QByteArray("data")));
    chk("override: different body -> override mattered",
        !overrideAddedNothing(200, QByteArray("secret"), 200, QByteArray("denied")));
    chk("override: different status -> override mattered",
        !overrideAddedNothing(200, QByteArray("x"), 403, QByteArray("x")));

    // ---- headIsBypass: corroborate HEAD via Content-Length (FP fix) ------
    chk("head: 200 with CL differing from denial -> bypass",
        headIsBypass(200, /*headCL*/ 4096, /*denialCL*/ 128));
    chk("head: 200 with SAME CL as denial -> NOT a bypass (generic HEAD)",
        !headIsBypass(200, 128, 128));
    chk("head: 200 with CL absent -> NOT a bypass",
        !headIsBypass(200, -1, 128));
    chk("head: 200 with zero CL -> NOT a bypass",
        !headIsBypass(200, 0, 128));
    chk("head: non-2xx -> NOT a bypass",
        !headIsBypass(403, 4096, 128));

    // ---- caseVariants: the documented-but-missing technique (FN fix) -----
    {
        const QStringList v = caseVariants("GET");
        chk("case: GET -> get", v.contains("get"));
        chk("case: GET -> Get", v.contains("Get"));
        chk("case: GET not echoed verbatim", !v.contains("GET"));
        const QStringList vp = caseVariants("POST");
        chk("case: POST -> post / Post", vp.contains("post") && vp.contains("Post"));
        chk("case: already-lower 'get' yields capitalized only",
            caseVariants("get").contains("Get") && !caseVariants("get").contains("get"));
    }

    // ---- buildRequest: CR/LF guards (parity hardening) ------------------
    {
        Request req;
        req.host = "victim.tld"; req.basePath = "/admin";
        const QByteArray ok = buildRequest(req, "POST", {});
        chk("build: request line", ok.startsWith("POST /admin HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));
        chk("build: POST frames Content-Length", ok.contains("Content-Length: 0\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header",
            !buildRequest(injHdr, "GET", {}).contains("X-Smuggled"));
        chk("build: drops CRLF extra (override) header value",
            !buildRequest(req, "POST", {{ "X-HTTP-Method-Override", "GET\r\nX-Smuggled: 1" }})
                 .contains("X-Smuggled"));

        Request badMethod = req;
        chk("build: CRLF method -> empty", buildRequest(badMethod, "GET\r\nX: y", {}).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "GET", {}).isEmpty());
        Request badPath = req; badPath.basePath = "/admin\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "GET", {}).isEmpty());
    }

    std::fprintf(stderr, "verb_tamper_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

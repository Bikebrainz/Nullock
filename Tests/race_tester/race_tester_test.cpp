// Regression corpus for the race-condition tester's pure logic (no network):
//   - classify(): the burst verdict -- raceSuspected needs >1 win + a 409/422
//     CONTENTION rejection (unrelated 4xx is noise, NOT a race); over-grant on
//     a write method when all win; inconclusive when noise dominates.
//   - isSafeMethod / buildRequest CR/LF guards.
//
// Run via:  ctest -R race_tester -V

#include "race_tester.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::RaceTester;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// classify(count, success, rejection(409/422/423), otherClientError,
//          rateLimited, serverError, transportFail, safeMethod)
Verdict V(int c, int s, int rej, int other = 0, int r429 = 0, int s5xx = 0, int tf = 0, bool safe = false) {
    return classify(c, s, rej, other, r429, s5xx, tf, safe);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- raceSuspected: split + genuine 409/422 contention ---------------
    chk("race: 3 wins + 7x409 -> suspected", V(10, 3, 7).raceSuspected);
    chk("race: exactly 1 win + 9x409 -> atomic, NOT suspected", !V(10, 1, 9).raceSuspected);
    chk("race: all win -> NOT split-suspected", !V(10, 10, 0).raceSuspected);

    // ---- the #2 FP fix: unrelated 4xx must NOT gate a race ---------------
    chk("FPfix: 3 wins + 7x403(other) -> NOT a race (unrelated 4xx)",
        !V(10, 3, /*rej*/0, /*other*/7).raceSuspected);
    chk("FPfix: 5 wins + 5x400(other) -> NOT a race",
        !V(10, 5, 0, 5).raceSuspected);
    chk("FPfix: unrelated-4xx-dominated -> inconclusive",
        V(10, 3, 0, 7).inconclusive);

    // ---- the #6 over-grant FN fix: all wins on a WRITE method -----------
    chk("overgrant: all 10 win on POST (write) -> suspected", V(10, 10, 0, 0, 0, 0, 0, /*safe*/false).overGrantSuspected);
    chk("overgrant: all 10 win on GET (safe) -> NOT suspected (normal read)",
        !V(10, 10, 0, 0, 0, 0, 0, /*safe*/true).overGrantSuspected);
    chk("overgrant: partial win on POST -> not over-grant (that's the split path)",
        !V(10, 4, 6).overGrantSuspected);

    // ---- inconclusive: infra noise dominates ----------------------------
    chk("inconc: 6x429 of 10 -> inconclusive", V(10, 2, 1, 0, 6).inconclusive);
    chk("inconc: 6x5xx of 10 -> inconclusive", V(10, 2, 1, 0, 0, 6).inconclusive);
    chk("inconc: light noise -> not inconclusive", !V(10, 3, 5, 0, 1, 1).inconclusive);
    chk("inconc race suppressed when noisy", !V(10, 3, 1, 0, 6, 0).raceSuspected);

    // ---- isSafeMethod ---------------------------------------------------
    chk("safe: GET/HEAD/OPTIONS", isSafeMethod("GET") && isSafeMethod("head") && isSafeMethod("OPTIONS"));
    chk("safe: POST/PUT/PATCH/DELETE are not safe",
        !isSafeMethod("POST") && !isSafeMethod("PUT") && !isSafeMethod("PATCH") && !isSafeMethod("DELETE"));

    // ---- buildRequest: CR/LF guards ------------------------------------
    {
        Request req; req.host = "victim.tld"; req.method = "POST"; req.basePath = "/redeem";
        req.body = "code=ABC"; req.contentType = "application/x-www-form-urlencoded";
        const QByteArray ok = buildRequest(req);
        chk("build: request line", ok.startsWith("POST /redeem HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));
        chk("build: Content-Length + body", ok.contains("Content-Length: 8\r\n") && ok.endsWith("code=ABC"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Tok"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr).contains("X-Smuggled"));
        Request badMethod = req; badMethod.method = "POST\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost).isEmpty());
        Request badPath = req; badPath.basePath = "/redeem\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath).isEmpty());
        // audit-3: contentType is spliced into a Content-Type header -> guard it.
        Request badCt = req; badCt.contentType = "application/x-www-form-urlencoded\r\nX-Injected: 1";
        chk("build: CRLF contentType -> empty", buildRequest(badCt).isEmpty());
    }

    std::fprintf(stderr, "race_tester_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

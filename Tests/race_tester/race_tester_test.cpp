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
        // guard-half: the CR/LF cases all carry BOTH chars, so the LF half is unpinned.
        Request badMethodLF = req; badMethodLF.method = "POST\nX: y";
        chk("build: bare-LF method -> empty", buildRequest(badMethodLF).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost).isEmpty());
        Request badPath = req; badPath.basePath = "/redeem\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath).isEmpty());
        // audit-3: contentType is spliced into a Content-Type header -> guard it.
        Request badCt = req; badCt.contentType = "application/x-www-form-urlencoded\r\nX-Injected: 1";
        chk("build: CRLF contentType -> empty", buildRequest(badCt).isEmpty());

        // Carried framing/encoding headers must be dropped so the ones we force stand
        // alone (prior tests never carried them):
        //  - Accept-Encoding: else the server gzips and the raw-byte successMatch scan
        //    misses the marker -> a real double-spend/over-grant race reads CLEAN.
        Request aeReq = req;
        aeReq.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray ae = buildRequest(aeReq);
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            ae.count("Accept-Encoding:") == 1
            && ae.contains("Accept-Encoding: identity\r\n") && !ae.contains("gzip"));
        //  - Transfer-Encoding: coexisting with the computed Content-Length is a CL.TE
        //    ambiguity an intermediary can desync.
        Request teReq = req;
        teReq.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray te = buildRequest(teReq);
        chk("build: carried Transfer-Encoding dropped -> only computed Content-Length",
            !te.contains("Transfer-Encoding") && te.contains("Content-Length: 8\r\n"));
        //  - Connection: we force "close"; a carried "keep-alive" would let the target
        //    reuse the socket and SERIALIZE the burst, hiding the very race.
        Request coReq = req;
        coReq.headers.append(qMakePair(QString("Connection"), QString("keep-alive")));
        const QByteArray co = buildRequest(coReq);
        chk("build: carried Connection dropped -> exactly one, close",
            co.count("Connection:") == 1 && !co.contains("keep-alive"));
    }

    // ---- raceIsWin: the atomic per-response win verdict (was inline) ---
    {
        chk("raceIsWin: 200 in [200,299], no match -> win",
            raceIsWin(200, 200, 299, QByteArray(), QString()));
        chk("raceIsWin: 299 upper-inclusive -> win", raceIsWin(299, 200, 299, QByteArray(), QString()));
        chk("raceIsWin: 300 above range -> not win", !raceIsWin(300, 200, 299, QByteArray(), QString()));
        chk("raceIsWin: 199 below range -> not win", !raceIsWin(199, 200, 299, QByteArray(), QString()));
        chk("raceIsWin: in range + body contains marker -> win",
            raceIsWin(200, 200, 299, QByteArray("... granted: ok ..."), QStringLiteral("granted")));
        chk("raceIsWin: in range but marker absent -> not win",
            !raceIsWin(200, 200, 299, QByteArray("denied"), QStringLiteral("granted")));
    }

    // ---- raceBucketOf: status -> bucket, incl. the 3xx-as-noise fix ----
    {
        chk("bucket: transport fail", raceBucketOf(false, false, 0) == RaceBucket::TransportFail);
        chk("bucket: success", raceBucketOf(true, true, 200) == RaceBucket::Success);
        chk("bucket: 429 rate-limited", raceBucketOf(true, false, 429) == RaceBucket::RateLimited);
        chk("bucket: 503 server error", raceBucketOf(true, false, 503) == RaceBucket::ServerError);
        chk("bucket: 409 contention rejection", raceBucketOf(true, false, 409) == RaceBucket::Rejection);
        chk("bucket: 422 contention rejection", raceBucketOf(true, false, 422) == RaceBucket::Rejection);
        chk("bucket: 423 contention rejection", raceBucketOf(true, false, 423) == RaceBucket::Rejection);
        chk("bucket: 404 unrelated 4xx -> noise", raceBucketOf(true, false, 404) == RaceBucket::OtherClientError);
        // THE FIX: 3xx redirects are noise, not an untracked dead-zone.
        chk("bucket: 302 redirect -> noise (fix, was uncounted)",
            raceBucketOf(true, false, 302) == RaceBucket::OtherClientError);
        chk("bucket: 301 redirect -> noise", raceBucketOf(true, false, 301) == RaceBucket::OtherClientError);
        // A 2xx that didn't meet the success criteria stays ambiguous/uncounted.
        chk("bucket: 204 non-success 2xx -> uncounted", raceBucketOf(true, false, 204) == RaceBucket::Uncounted);
    }

    // ---- FP fix end-to-end: a redirect-heavy burst is inconclusive -----
    // 3 wins + 1x409 + 6x302. Before the fix the 6 redirects were uncounted, so
    // infraNoise=0 -> not inconclusive -> raceSuspected TRUE (a false positive).
    // Now the 6x302 count as otherClientError noise -> inconclusive -> NOT a race.
    {
        chk("race: 3 wins + 1x409 + 6x302(noise) -> inconclusive, NOT suspected",
            V(10, 3, 1, /*other=*/6).inconclusive && !V(10, 3, 1, 6).raceSuspected);
        // Sanity: the SAME shape with the redirects replaced by more wins/rejects
        // (no noise) still reads as a race, so the guard only suppresses noise.
        chk("race: 3 wins + 7x409 (no noise) -> still suspected", V(10, 3, 7, 0).raceSuspected);
    }

    std::fprintf(stderr, "race_tester_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

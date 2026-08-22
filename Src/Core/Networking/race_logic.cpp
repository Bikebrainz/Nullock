// Pure (no-network) logic for the race-condition tester: the request builder's
// CR/LF guards and the burst-verdict classifier. Split out of race_tester.cpp
// so Tests/race_tester links Qt6::Core alone (no HttpClient / Network / GUI).

#include "race_tester.hpp"

namespace Nullock::Core::RaceTester {

bool isSafeMethod(const QString &method) {
    return method.compare("GET", Qt::CaseInsensitive) == 0
        || method.compare("HEAD", Qt::CaseInsensitive) == 0
        || method.compare("OPTIONS", Qt::CaseInsensitive) == 0;
}

Verdict classify(int count, int successCount, int rejectionCount, int otherClientError,
                 int rateLimited, int serverError, int transportFail, bool safeMethod) {
    Verdict v;
    // Noise = anything that means the burst didn't cleanly exercise contention:
    // transport drops, 429 rate-limits, 5xx overload, AND unrelated 4xx
    // (400/401/403/404) -- the latter are NOT race-lost signals, so a burst
    // dominated by them is inconclusive, not a race.
    const int infraNoise = transportFail + rateLimited + serverError + otherClientError;
    v.inconclusive = (infraNoise * 2 > count);
    v.allSucceeded = (successCount == count);
    // A real limited-use race: MULTIPLE wins alongside genuine contention
    // rejections (409 Conflict / 422 / 423 Locked) -- an atomic endpoint would
    // grant exactly one and 409 the rest. Unrelated 4xx no longer qualify.
    v.raceSuspected = !v.inconclusive
                   && successCount > 1
                   && successCount < count
                   && rejectionCount > 0;
    // Over-grant: every concurrent WRITE request won. An atomic single-use
    // action should grant one and reject the rest; all-N-win on a non-safe
    // method is a possible unguarded over-grant the split heuristic misses.
    // (On a safe method, all-win is just a normal idempotent read.)
    v.overGrantSuspected = !v.inconclusive && v.allSucceeded && !safeMethod && count >= 2;
    return v;
}

bool raceIsWin(int status, int successMin, int successMax,
               const QByteArray &body, const QString &successMatch) {
    const bool matchOk = successMatch.isEmpty()
        || QString::fromUtf8(body.left(256 * 1024)).contains(successMatch);
    return status >= successMin && status <= successMax && matchOk;
}

RaceBucket raceBucketOf(bool ok, bool success, int status) {
    if (!ok)                     return RaceBucket::TransportFail;
    if (success)                 return RaceBucket::Success;
    if (status == 429)           return RaceBucket::RateLimited;
    if (status >= 500)           return RaceBucket::ServerError;
    // Genuine CONTENTION rejections only: 409 Conflict / 422 / 423 Locked.
    if (status == 409 || status == 422 || status == 423)
                                 return RaceBucket::Rejection;
    // Noise: unrelated 4xx AND 3xx redirects -- neither cleanly exercised the
    // contended resource, so both must count toward the inconclusive guard.
    if (status >= 300)           return RaceBucket::OtherClientError;
    // A 2xx that didn't match the success criteria: ambiguous, count nothing.
    return RaceBucket::Uncounted;
}

QByteArray buildRequest(const Request &req) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // method/host/path flow raw from the deep-audit / fromHistory path; a CR/LF
    // in any would smuggle a second request line or header -- refuse to build.
    if (crlf(req.method) || crlf(req.host) || crlf(req.basePath) || crlf(req.contentType)) return {};

    const bool hasBody = !req.body.isEmpty();
    QByteArray out;
    out  = req.method.toUtf8() + " " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/race-tester\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    bool haveCt = false;
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers that would fight the ones we force:
        //  - Accept-Encoding: line 52 forces "identity" so the raw-byte successMatch
        //    scan sees a PLAINTEXT body; a surviving "gzip,.." combines (RFC 7230
        //    3.2.2), the server compresses, the client never inflates -> a real race
        //    win (2xx + marker) is scored non-success (false clean).
        //  - Transfer-Encoding: coexisting with the computed Content-Length (line 64)
        //    is a CL.TE-ambiguous request an intermediary can desync.
        //  - Connection: line 65 forces "close"; a carried "keep-alive" would let the
        //    target reuse the socket and SERIALIZE the burst, hiding the very race.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) haveCt = true;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (hasBody && !haveCt && !req.contentType.isEmpty())
        out += "Content-Type: " + req.contentType.toUtf8() + "\r\n";
    if (hasBody)
        out += "Content-Length: " + QByteArray::number(req.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += req.body;
    return out;
}

} // namespace Nullock::Core::RaceTester

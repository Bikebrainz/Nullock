#include "race_tester.hpp"
#include "networking.hpp"

#include <QFuture>
#include <QSemaphore>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core::RaceTester {

// (buildRequest, classify, isSafeMethod live in race_logic.cpp so the
// regression test can exercise the verdict + builder without the network.)

Result test(const Request &req, int count, int successMin, int successMax,
            const QString &successMatch) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (count < 2)   count = 2;
    // Cap at 100: every worker must fit in the synchronized burst (the pool
    // is sized to `count`), so a request can't be left trickling out behind
    // the pool's thread cap with a much wider, race-defeating window.
    if (count > 100) count = 100;
    result.count = count;

    const QByteArray bytes = buildRequest(req);
    const QString host = req.host;
    const quint16 port = static_cast<quint16>(req.port);
    const bool tls = req.tls;

    // Dedicated pool sized to `count` so all sends run at once, plus a gate
    // semaphore so every worker blocks until all are scheduled, then
    // releases together -- as close to simultaneous as portable Qt gets
    // without raw-socket single-packet control.
    QThreadPool pool;
    pool.setMaxThreadCount(count);
    QSemaphore gate(0);

    QList<QFuture<Outcome>> futures;
    futures.reserve(count);
    for (int i = 0; i < count; ++i) {
        futures << QtConcurrent::run(&pool, [&]() -> Outcome {
            Outcome o;
            gate.acquire();              // wait for the synchronized release
            HttpClient client;
            const auto r = client.send(host, port, tls, bytes);
            o.ok = r.ok;
            if (r.ok) {
                o.status = r.parsed.statusCode;
                o.success = raceIsWin(o.status, successMin, successMax,
                                      r.parsed.body, successMatch);
            }
            return o;
        });
    }
    gate.release(count);               // fire them all together

    for (auto &f : futures) {
        const Outcome o = f.result();  // blocks until finished
        // Bucketing is the pure, unit-tested raceBucketOf (incl. the 3xx-as-noise
        // fix); the counters below mirror its enum one-to-one.
        const RaceBucket b = raceBucketOf(o.ok, o.success, o.status);
        if (b == RaceBucket::TransportFail) { ++result.transportFail; continue; }
        result.statusHistogram[o.status]++;
        switch (b) {
            case RaceBucket::Success:          ++result.successCount;     break;
            case RaceBucket::RateLimited:      ++result.rateLimited;      break;
            case RaceBucket::ServerError:      ++result.serverError;      break;
            case RaceBucket::Rejection:        ++result.rejectionCount;   break;
            case RaceBucket::OtherClientError: ++result.otherClientError; break;
            case RaceBucket::Uncounted:        /* 2xx-non-success: count nothing */ break;
            case RaceBucket::TransportFail:    /* handled above */        break;
        }
    }

    const Verdict v = classify(count, result.successCount, result.rejectionCount,
                               result.otherClientError, result.rateLimited,
                               result.serverError, result.transportFail,
                               isSafeMethod(req.method));
    result.inconclusive       = v.inconclusive;
    result.allSucceeded       = v.allSucceeded;
    result.raceSuspected      = v.raceSuspected;
    result.overGrantSuspected = v.overGrantSuspected;
    return result;
}

} // namespace Nullock::Core::RaceTester

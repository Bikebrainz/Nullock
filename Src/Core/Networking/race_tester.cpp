#include "race_tester.hpp"
#include "networking.hpp"

#include <QFuture>
#include <QSemaphore>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core::RaceTester {

namespace {

QByteArray buildRequest(const Request &req) {
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

} // namespace

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
                const bool matchOk = successMatch.isEmpty()
                    || QString::fromUtf8(r.parsed.body.left(256 * 1024)).contains(successMatch);
                o.success = (o.status >= successMin && o.status <= successMax) && matchOk;
            }
            return o;
        });
    }
    gate.release(count);               // fire them all together

    for (auto &f : futures) {
        const Outcome o = f.result();  // blocks until finished
        if (!o.ok) { ++result.transportFail; continue; }
        result.statusHistogram[o.status]++;
        if (o.success)               ++result.successCount;
        else if (o.status == 429)    ++result.rateLimited;
        else if (o.status >= 500)    ++result.serverError;
        else if (o.status >= 400)    ++result.rejectionCount;   // app "already used"
    }

    // Verdict. A real limited-use race shows MULTIPLE wins alongside
    // application-level rejections ("already redeemed", 409/422) -- not
    // just a rate-limit or overload split, which we must not misread as a
    // vuln. If infra noise (drops / 429 / 5xx) dominated, the test didn't
    // actually exercise contention -> inconclusive, not "clean".
    const int infraNoise = result.transportFail + result.rateLimited + result.serverError;
    result.inconclusive  = (infraNoise * 2 > count);
    result.allSucceeded  = (result.successCount == count);
    result.raceSuspected = !result.inconclusive
                        && result.successCount > 1
                        && result.successCount < count
                        && result.rejectionCount > 0;
    return result;
}

} // namespace Nullock::Core::RaceTester

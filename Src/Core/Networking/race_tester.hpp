#pragma once

// Race-condition tester. Fires N copies of one request as close to
// simultaneously as the thread pool allows and looks for the signature
// of a broken limited-use operation: more than one request "succeeds"
// when exactly one should. That's the class behind coupon/gift-card
// double-spend, one-time-token reuse, balance over-withdrawal, and
// vote/like stuffing -- the bugs James Kettle's single-packet research
// put on the map, and which Burp only addresses via the Turbo Intruder
// extension.
//
// Success is defined by the caller: a status range (default 2xx) and/or
// a body substring. The verdict:
//   - successes == 1                -> atomic, safe.
//   - 1 < successes < count         -> RACE: a limited resource was
//                                      consumed more than once under
//                                      concurrency (some won, some lost).
//   - successes == count            -> every request succeeded; likely an
//                                      idempotent/normal endpoint, not a
//                                      limited-use race -> not flagged.
//
// v1 fires via the thread pool (good enough to win most application-layer
// races); true last-byte / single-packet synchronization is a future
// raw-socket iteration.

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QPair>
#include <QString>

namespace Nullock::Core::RaceTester {

struct Request {
    QString    host;
    int        port = 443;
    bool       tls  = true;
    QString    method = QStringLiteral("POST");
    QString    basePath;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
    QString    contentType;
};

struct Outcome {
    bool    ok = false;       // transport succeeded
    int     status = 0;
    bool    success = false;  // matched the caller's success criteria
};

struct Result {
    QMap<int, int> statusHistogram;   // status -> count (transport-ok responses)
    int     count = 0;
    int     successCount = 0;          // matched the success criteria
    int     rejectionCount = 0;       // app-level "lost the race": 4xx except 429
    int     rateLimited = 0;          // 429
    int     serverError = 0;          // 5xx
    int     transportFail = 0;        // connection failed / dropped
    bool    raceSuspected = false;    // multiple wins + real contention, not infra noise
    bool    inconclusive = false;     // infra noise (rate-limit/5xx/drops) dominated
    bool    allSucceeded = false;     // every request won (idempotent OR unguarded race)
    QString error;
};

// Fire `count` concurrent copies (capped at 100 so they all fit in the
// synchronized burst). success = status in [successMin, successMax] AND
// (successMatch empty OR body contains it).
Result test(const Request &req, int count,
            int successMin = 200, int successMax = 299,
            const QString &successMatch = QString());

} // namespace Nullock::Core::RaceTester

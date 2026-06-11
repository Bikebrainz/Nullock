#pragma once

// Parameter mining -- hidden parameter / input discovery. The thing
// Burp ships only as the third-party "param-miner" extension and that
// tools like Arjun do standalone. Given a URL, fire requests adding
// batches of candidate parameter names and response-diff against a
// baseline to find the ones the server actually reacts to:
//
//   * reflected   -- the param's value comes back in the response
//                    (a candidate XSS / injection sink)
//   * status flip -- adding the param changes the HTTP status (e.g.
//                    ?debug=1 -> 500, ?admin=1 -> 200 instead of 403)
//
// We deliberately don't flag pure length deltas: reflection inflates
// length and many pages are mildly dynamic, so length-only signals are
// noisy. Reflection + status are high-signal, low-false-positive.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::ParamMiner {

struct Found {
    QString name;
    QString signal;          // "reflected" | "status-change"
    bool    reflected = false;
    int     baselineStatus = 0;
    int     observedStatus = 0;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");   // GET (query) or POST (form body)
    QString basePath;                         // path, may already carry a query
    QList<QPair<QString, QString>> headers;   // extra headers (auth/cookies)
};

struct Result {
    QList<Found> found;
    int     requestsSent = 0;
    int     candidatesTried = 0;
    // A control probe disables a signal when the target reacts to a junk
    // param (would otherwise flag the whole wordlist). Surfaced so callers
    // can tell "found nothing" from "couldn't trust this signal here".
    bool    statusSignalUsable = true;
    bool    reflectionSignalUsable = true;
    QString error;
};

// Mine candidate names against the target. Batches names to cut request
// count; binary-searches a batch that flips the status to isolate the
// responsible param. batchSize caps how many names ride in one request.
Result mine(const Request &req, const QStringList &candidates,
            int batchSize = 25);

// Curated default list of commonly-hidden parameter names.
QStringList defaultWordlist();

} // namespace Nullock::Core::ParamMiner

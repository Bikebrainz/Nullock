#include "smuggling.hpp"
#include "networking.hpp"

#include <QElapsedTimer>

namespace Nullock::Core::Smuggling {

// The byte-exact probe builders (baselineRequest, clteProbe, teclProbe,
// ambiguousControl) live in smuggling_logic.cpp so they can be unit-tested
// against Qt6::Core alone. This TU keeps test(), which pulls in HttpClient (the
// Qt6::Network chain) and is therefore I/O.

namespace {

// A response delayed by at least this much over baseline is a desync signal --
// a vulnerable back-end blocks on its socket read timeout (typically >= 5-30s)
// waiting for body bytes the front-end never forwarded.
constexpr int kDelayThresholdMs = 4000;

} // namespace

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto timeSend = [&](const QByteArray &raw) -> int {
        QElapsedTimer t; t.start();
        ++result.requestsSent;
        client.send(req.host, port, req.tls, raw);   // ok/err irrelevant -- we time it
        return static_cast<int>(t.elapsed());
    };

    // Baseline: the faster of two well-formed POSTs (the server's quick path).
    const int b1 = timeSend(baselineRequest(req));
    const int b2 = timeSend(baselineRequest(req));
    result.baselineMs = qMin(b1, b2);
    // If even a well-formed request is slow, we can't time a desync reliably.
    if (result.baselineMs >= kDelayThresholdMs) {
        result.error = "baseline too slow to time a desync reliably";
        return result;
    }

    // Tarpit guard: if a valid-ambiguous request (both headers, complete body)
    // also stalls, the server delays on ambiguous input generally -- a probe
    // delay then isn't desync-specific, so we suppress to avoid a false
    // critical. Conservative: this can miss a desync on a tarpitting front end.
    //
    // Measure the control with the SAME min-of-two robustness as the baseline:
    // a single transient-slow control sample must NOT veto a confirmed,
    // twice-reproduced hit (the suppression side has to be as flap-resistant as
    // the detection side, else one unlucky control turns a real desync into a
    // silent false negative). Suppress only when the control is RELIABLY slow.
    const int c1 = timeSend(ambiguousControl(req));
    const int c2 = timeSend(ambiguousControl(req));
    const bool ambiguousSlow = (qMin(c1, c2) - result.baselineMs >= kDelayThresholdMs);

    struct Variant { const char *name; QByteArray (*build)(const Request &); };
    const Variant variants[] = {
        { "CL.TE", clteProbe },
        { "TE.CL", teclProbe },
    };

    for (const Variant &v : variants) {
        const int d1 = timeSend(v.build(req));
        if (d1 - result.baselineMs < kDelayThresholdMs) continue;
        // Confirm: a one-off slow response isn't a desync. Require the delay to
        // reproduce on a re-send before reporting.
        const int d2 = timeSend(v.build(req));
        if (d2 - result.baselineMs < kDelayThresholdMs) continue;
        // ...and only if the server doesn't just tarpit ambiguous requests.
        if (ambiguousSlow) continue;
        result.hits.append({ QString::fromUtf8(v.name), qMin(d1, d2) - result.baselineMs });
        result.vulnerable = true;
    }

    return result;
}

} // namespace Nullock::Core::Smuggling

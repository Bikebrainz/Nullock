#include "smuggling.hpp"
#include "networking.hpp"

#include <QElapsedTimer>

namespace Nullock::Core::Smuggling {

// The byte-exact probe builders (baselineRequest, clteProbe, teclProbe,
// ambiguousControl) live in smuggling_logic.cpp so they can be unit-tested
// against Qt6::Core alone. This TU keeps test(), which pulls in HttpClient (the
// Qt6::Network chain) and is therefore I/O.

// kDelayThresholdMs now lives in smuggling.hpp (shared with confirmsSmuggle in
// smuggling_logic.cpp, which the unit test links).

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    // We grade on TWO axes per send: the elapsed time AND how the transport leg
    // ended. The delay alone is ambiguous -- a genuine desync (back-end blocks
    // on its own read, socket held OPEN and silent) and a hold-then-RST WAF
    // (buffers the probe, quarantines it for seconds, then RSTs/500s) produce
    // the SAME delay shape. Only the desync ends in SocketOutcome::Timeout; the
    // quarantine ends in Reset/ConnectError. So we keep the outcome, not just
    // the stopwatch.
    struct Sample { int ms; Nullock::Core::SocketOutcome outcome; };
    auto timeSend = [&](const QByteArray &raw) -> Sample {
        QElapsedTimer t; t.start();
        ++result.requestsSent;
        const HttpClient::SendResult r = client.send(req.host, port, req.tls, raw);
        return { static_cast<int>(t.elapsed()), r.outcome };
    };

    // Baseline: the faster of two well-formed POSTs (the server's quick path).
    const int b1 = timeSend(baselineRequest(req)).ms;
    const int b2 = timeSend(baselineRequest(req)).ms;
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
    const int c1 = timeSend(ambiguousControl(req)).ms;
    const int c2 = timeSend(ambiguousControl(req)).ms;
    const bool ambiguousSlow = (qMin(c1, c2) - result.baselineMs >= kDelayThresholdMs);

    // Second tarpit guard, keyed on body CONTENT. A WAF that tarpits on the
    // probes' trailing-junk-after-chunk body PATTERN (rather than on a CL/TE
    // header disagreement) would stall the probes -- looking like a desync --
    // while leaving the valid-ambiguous control above fast. tarpitControl is a
    // well-formed request carrying that same junk body, so it stalls too and
    // lets us suppress. Same min-of-two flap resistance as the other controls.
    const int t1 = timeSend(tarpitControl(req)).ms;
    const int t2 = timeSend(tarpitControl(req)).ms;
    const bool tarpitSlow = (qMin(t1, t2) - result.baselineMs >= kDelayThresholdMs);

    // Either control being RELIABLY slow means a probe delay isn't attributable
    // to a framing desync -- suppress to avoid a false critical.
    const bool controlSlow = ambiguousSlow || tarpitSlow;

    struct Variant { const char *name; QByteArray (*build)(const Request &); };
    const Variant variants[] = {
        { "CL.TE", clteProbe },
        { "TE.CL", teclProbe },
    };

    for (const Variant &v : variants) {
        // First send establishes the candidate delay; the second re-sends to
        // require the delay to REPRODUCE. The whole FP-guard gauntlet (threshold,
        // reproduce, tarpit veto, transport-outcome gate) is confirmsSmuggle().
        const Sample d1 = timeSend(v.build(req));
        // Skip the (costly) re-send when the first is already fast enough that no
        // verdict could pass -- a pure optimisation; confirmsSmuggle re-checks it.
        if (d1.ms - result.baselineMs < kDelayThresholdMs) continue;
        const Sample d2 = timeSend(v.build(req));
        if (!confirmsSmuggle(d1.ms, d1.outcome, d2.ms, d2.outcome,
                             controlSlow, result.baselineMs))
            continue;
        result.hits.append({ QString::fromUtf8(v.name), qMin(d1.ms, d2.ms) - result.baselineMs });
        result.vulnerable = true;
    }

    return result;
}

} // namespace Nullock::Core::Smuggling

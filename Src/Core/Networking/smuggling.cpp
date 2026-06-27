#include "smuggling.hpp"
#include "networking.hpp"

#include <QElapsedTimer>

namespace Nullock::Core::Smuggling {

// The byte-exact probe builders (baselineRequest, clteProbe, teclProbe,
// ambiguousControl) live in smuggling_logic.cpp so they can be unit-tested
// against Qt6::Core alone. This TU keeps test(), which pulls in HttpClient (the
// Qt6::Network chain) and is therefore I/O.

namespace {

// A response delayed by at least this much over baseline is a CANDIDATE desync
// signal -- a vulnerable back-end blocks on its socket read timeout (typically
// >= 5-30s) waiting for body bytes the front-end never forwarded. Necessary but
// not sufficient: the delay must also reproduce, survive the tarpit controls,
// and end in a read TIMEOUT (socket open, silent) rather than a reset -- see the
// transport gate in test().
constexpr int kDelayThresholdMs = 4000;

} // namespace

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
        const Sample d1 = timeSend(v.build(req));
        if (d1.ms - result.baselineMs < kDelayThresholdMs) continue;
        // Confirm: a one-off slow response isn't a desync. Require the delay to
        // reproduce on a re-send before reporting.
        const Sample d2 = timeSend(v.build(req));
        if (d2.ms - result.baselineMs < kDelayThresholdMs) continue;
        // ...and only if the server doesn't just tarpit ambiguous/junk requests.
        if (controlSlow) continue;
        // Transport gate -- the false-positive fix. A genuine CL.TE/TE.CL desync
        // leaves the socket OPEN and silent: the back-end blocks on its OWN read
        // of body bytes the front-end never forwarded, so OUR response read
        // times out with the connection still up (SocketOutcome::Timeout). A
        // hold-then-RST middlebox/WAF that buffers the malformed probe,
        // quarantines it for seconds, then RSTs or 500s produces the SAME delay
        // but ends in Reset/ConnectError. Grade a CRITICAL only on the timeout
        // shape, on BOTH confirming sends -- per this probe's stated stance,
        // prefer a false negative over a false critical.
        const auto Timeout = Nullock::Core::SocketOutcome::Timeout;
        if (d1.outcome != Timeout || d2.outcome != Timeout) continue;
        result.hits.append({ QString::fromUtf8(v.name), qMin(d1.ms, d2.ms) - result.baselineMs });
        result.vulnerable = true;
    }

    return result;
}

} // namespace Nullock::Core::Smuggling

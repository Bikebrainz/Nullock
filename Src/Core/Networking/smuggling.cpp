#include "smuggling.hpp"
#include "networking.hpp"

#include <QElapsedTimer>

namespace Nullock::Core::Smuggling {

namespace {

// A response delayed by at least this much over baseline is a desync signal --
// a vulnerable back-end blocks on its socket read timeout (typically >= 5-30s)
// waiting for body bytes the front-end never forwarded.
constexpr int kDelayThresholdMs = 4000;

QByteArray commonHeaders(const Request &req) {
    QByteArray h;
    h += "Host: " + req.host.toUtf8() + "\r\n";
    h += "User-Agent: Nullock/smuggling\r\n";
    h += "Accept: */*\r\n";
    for (const auto &kv : req.headers) {
        if (kv.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.contains('\r') || kv.first.contains('\n')) continue;
        if (kv.second.contains('\r') || kv.second.contains('\n')) continue;
        h += kv.first.toUtf8() + ": " + kv.second.toUtf8() + "\r\n";
    }
    return h;
}

// A normal, well-formed POST: the timing reference.
QByteArray baselineRequest(const Request &req) {
    const QByteArray body = "x=1";
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Type: application/x-www-form-urlencoded\r\n";
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

// CL.TE: front-end uses Content-Length (forwards the first 6 bytes "1\r\nA\r\n"
// -- a complete 1-byte chunk), back-end uses Transfer-Encoding and blocks
// waiting for the NEXT chunk-size line (the trailing "X" was never forwarded).
QByteArray clteProbe(const Request &req) {
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Length: 6\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out += "Connection: close\r\n\r\n";
    out += "1\r\nA\r\nX";
    return out;
}

// Valid-ambiguous control: BOTH framing headers, but a complete body that
// strands neither parser (CL=5 forwards exactly "0\r\n\r\n"; TE reads it as the
// terminating chunk). A server that delays on THIS is tarpitting ambiguous
// requests in general, not desyncing -- so a probe delay isn't attributable to
// a framing disagreement and must not be reported.
QByteArray ambiguousControl(const Request &req) {
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Length: 5\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out += "Connection: close\r\n\r\n";
    out += "0\r\n\r\n";
    return out;
}

// TE.CL: front-end uses Transfer-Encoding (forwards "0\r\n\r\n"), back-end uses
// Content-Length=6 and blocks waiting for the remaining byte.
QByteArray teclProbe(const Request &req) {
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Length: 6\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out += "Connection: close\r\n\r\n";
    out += "0\r\n\r\nX";
    return out;
}

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
    const int ctrl = timeSend(ambiguousControl(req));
    const bool ambiguousSlow = (ctrl - result.baselineMs >= kDelayThresholdMs);

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

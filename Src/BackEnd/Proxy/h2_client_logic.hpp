#pragma once

// Pure decision/transform logic for the HTTP/2 upstream client, split out of
// http2_client.cpp so it links against Qt6::Core alone (http2_client.cpp pulls
// nghttp2 + QSslSocket). No nghttp2, no sockets, no proxy_server.hpp -- it
// operates on neutral fields so a ctest binary can drive it with zero I/O.
//
// Everything here is deterministic and the load-bearing correctness for the
// multi-stream rework: the request-header build (pseudo-header order +
// hop-by-hop stripping), the exhaustion caps (concurrent-stream + per-stream
// body), and the pump-loop decision (whose interleave rule prevents a
// second stream's data from deadlocking behind a blocking read).

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Proxy::H2ClientLogic {

// A single HTTP/2 header name/value, ready to hand to nghttp2 (names are already
// lowercased; pseudo-headers keep their leading ':').
struct HeaderNV {
    QByteArray name;
    QByteArray value;
};

// Build the h2 request header list: the four pseudo-headers (:method, :scheme,
// :authority, :path) in the spec-required order, then the caller's headers
// lowercased with hop-by-hop / connection-control headers dropped (host,
// connection, proxy-connection, transfer-encoding, upgrade, keep-alive, te).
// Empty method -> GET, empty path -> "/". scheme is always https (the proxy
// only speaks h2 over TLS). A header whose name is empty is skipped.
QList<HeaderNV> buildRequestHeaders(const QString &method,
                                    const QString &authority,
                                    const QString &path,
                                    const QList<QPair<QString, QString>> &headers);

// True if `name` is a header the h2 layer must not forward (case-insensitive).
bool isHopByHopHeader(const QString &lowerName);

// Reason phrase for a status code (mirrors the HTTP/1.1 side so the synthesized
// HttpResponse reads naturally in the UI).
const char *reasonFor(int status);

// Exhaustion guards -- enforced locally, never trusting the peer's advertised
// limits. shouldRejectSubmit: refuse to open another stream once `currentOpen`
// has reached `cap`. bodyOverBudget: true once a stream's accumulated response
// body exceeds `cap` bytes (a malicious origin can otherwise stream unbounded
// DATA into one stream).
bool shouldRejectSubmit(int currentOpen, int cap);
bool bodyOverBudget(qint64 accumulated, qint64 cap);

// The pump loop's next action given session state, extracted so the
// deadlock-avoidance ordering is unit-testable without a live socket.
//   Fatal          -> a connection-level failure; tear everything down.
//   Done           -> no streams still open; assemble results.
//   WriteThenRead  -> outbound bytes are queued; flush them, THEN read.
//   ReadOnly       -> nothing to send; block for inbound.
// Precedence is fatal > done > write > read: a fatal always wins, and we never
// report Done while a stream is still open.
enum class PumpAction { WriteThenRead, ReadOnly, Done, Fatal };
PumpAction nextPumpAction(int openStreams, bool wrotePending, bool fatal);

// How to turn a finished stream's state into a Result. Extracted so the exact
// outcome for each state is unit-tested and can't silently drift between the
// one-shot (sendConcurrent) and persistent (send) paths.
//   Success     -> a usable response (either fully closed, OR :status received
//                  but END_STREAM never arrived -- a truncated body we still
//                  serve, matching the original behavior).
//   Fatal       -> a connection-level failure (the whole session is unusable).
//   StreamError -> a per-stream failure (RST, local body-budget) -- this stream
//                  only; the connection itself is fine.
//   NoStatus    -> nothing usable arrived (no :status at all).
enum class AssembleOutcome { Success, Fatal, StreamError, NoStatus };
AssembleOutcome assembleOutcome(bool done, int statusCode, bool hadError, bool fatal);

} // namespace Nullock::Proxy::H2ClientLogic

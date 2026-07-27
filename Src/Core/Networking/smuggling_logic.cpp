// Pure request-builders for the HTTP request-smuggling probe, split out of
// smuggling.cpp so a unit test can link them against Qt6::Core alone and assert
// the EXACT probe bytes -- byte-exactness is load-bearing here: a wrong
// Content-Length or chunk encoding silently turns the probe inert (a permanent
// false negative). test() and its HttpClient (the timing send) stay in
// smuggling.cpp. Mirrors the established sibling pattern (cors_origin.cpp, ...).

#include "smuggling.hpp"

#include <QByteArray>

namespace Nullock::Core::Smuggling {

namespace {

// A CR/LF in the request line / Host of a SMUGGLING probe is itself a framing
// hazard (it could split the request independently of the intended CL/TE
// ambiguity), so a tainted basePath/host ABORTS the build -- the caller sends
// nothing and the timing probe simply records no delay. (method is the fixed
// literal "POST".)
bool reqTainted(const Request &req) {
    return req.basePath.contains('\r') || req.basePath.contains('\n')
        || req.host.contains('\r')     || req.host.contains('\n');
}

QByteArray commonHeaders(const Request &req) {
    QByteArray h;
    h += "Host: " + req.host.toUtf8() + "\r\n";
    h += "User-Agent: Nullock/smuggling\r\n";
    h += "Accept: */*\r\n";
    for (const auto &kv : req.headers) {
        if (kv.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        // Strip a caller Connection too: every builder appends its own
        // "Connection: close" as a load-bearing SAFETY invariant (the torn-down
        // connection is what stops stranded smuggling bytes from prepending onto a
        // real user's request on a pooled connection). A surviving caller
        // "Connection: keep-alive" -- honored by a front-end that reads the first
        // token -- would defeat that guarantee and fail OPEN into production traffic.
        if (kv.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (kv.first.contains('\r') || kv.first.contains('\n')) continue;
        if (kv.second.contains('\r') || kv.second.contains('\n')) continue;
        h += kv.first.toUtf8() + ": " + kv.second.toUtf8() + "\r\n";
    }
    return h;
}

} // namespace

// A normal, well-formed POST: the timing reference.
QByteArray baselineRequest(const Request &req) {
    if (reqTainted(req)) return {};
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
    if (reqTainted(req)) return {};
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
    if (reqTainted(req)) return {};
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Length: 5\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out += "Connection: close\r\n\r\n";
    out += "0\r\n\r\n";
    return out;
}

// Body-content tarpit control: a WELL-FORMED request -- ONE framing header
// (Content-Length only, NO Transfer-Encoding), so it strands neither parser and
// a normal server reads exactly the declared bytes and replies fast. But its
// BODY is the CL.TE probe's body verbatim ("1\r\nA\r\nX"), trailing junk and
// all. A WAF that tarpits on the suspicious body PATTERN (chunk-shaped data
// with bytes after it) rather than on a CL/TE disagreement will stall on this
// too -- letting the suppressor veto a probe delay that is really content-based
// tarpitting, not a framing desync. CL = 7 = the full body length (1 0D 0A A
// 0D 0A X), so there is genuinely no ambiguity for a conformant peer to act on.
QByteArray tarpitControl(const Request &req) {
    if (reqTainted(req)) return {};
    const QByteArray body = "1\r\nA\r\nX";   // == clteProbe body, but as plain CL-framed content
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Type: application/octet-stream\r\n";
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

// TE.CL: front-end uses Transfer-Encoding (forwards "0\r\n\r\n"), back-end uses
// Content-Length=6 and blocks waiting for the remaining byte.
QByteArray teclProbe(const Request &req) {
    if (reqTainted(req)) return {};
    QByteArray out = "POST " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += commonHeaders(req);
    out += "Content-Length: 6\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    out += "Connection: close\r\n\r\n";
    out += "0\r\n\r\nX";
    return out;
}

} // namespace Nullock::Core::Smuggling

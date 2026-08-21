#include "takeover_scan.hpp"
#include "networking.hpp"

namespace Nullock::Core::TakeoverScan {

// (The fingerprint table, match(), and buildGet() live in takeover_logic.cpp so
// the regression test can exercise them without the network stack.)

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = "request failed: " + r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    // Status-aware: a branded phrase on a live 2xx/3xx page is demoted to
    // "possible" (a real dangling service serves a 4xx/5xx). maybefix #10.
    result.hits = match(QString::fromUtf8(r.parsed.body), result.status);
    return result;
}

} // namespace Nullock::Core::TakeoverScan

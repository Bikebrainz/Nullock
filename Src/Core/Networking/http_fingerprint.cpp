#include "http_fingerprint.hpp"
#include "networking.hpp"

namespace Nullock::Core::HttpFingerprint {

// (The detection table (detect()) and buildGet() live in
// http_fingerprint_logic.cpp so the regression test can exercise the whole
// fingerprint table without the network stack.)

Result fingerprint(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = "request failed: " + r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    result.tech = detect(r.parsed.headers, r.parsed.body);
    return result;
}

} // namespace Nullock::Core::HttpFingerprint

#include "waf_detect.hpp"
#include "networking.hpp"

// The pure matcher (sigs() + detectFromHeaders) and buildGet live in
// waf_detect_logic.cpp so they can be unit-tested against Qt6::Core alone.
// This TU keeps only detect(), which pulls in HttpClient (the Qt6::Network
// chain) and is therefore I/O and not unit-tested directly.

namespace Nullock::Core::WafDetect {

Result detect(const Request &req) {
    Result result;
    result.host = req.host;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    result.detections = detectFromHeaders(r.parsed.headers);
    return result;
}

} // namespace Nullock::Core::WafDetect

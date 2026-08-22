#include "exposure_scan.hpp"
#include "networking.hpp"

namespace Nullock::Core::ExposureScan {

// (The signature table, matchSignature(), looksHtml(), randTok() and buildGet()
// live in exposure_logic.cpp so the regression test can exercise them without
// the network stack.)

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto get = [&](const QString &path) {
        return client.send(req.host, port, req.tls, buildGet(req, path));
    };

    // Soft-404 calibration: fetch a known-bogus path. If it returns 2xx the
    // server may 200 everything (catch-all / SPA fallback / soft-404), so we
    // capture its body and later suppress any signature that ALSO matches it --
    // such a signature isn't file-specific on this host.
    QByteArray controlBody;
    bool controlIs2xx = false;
    {
        const QString bogus = req.basePrefix + "/" + randTok() + "-" + randTok();
        const auto c = get(bogus);
        if (c.ok && c.parsed.statusCode >= 200 && c.parsed.statusCode < 300) {
            controlIs2xx = true;
            controlBody = c.parsed.body;
            result.catchAll = true;
        }
    }

    for (const Signature &sig : signatures()) {
        ++result.probed;
        const QString path = req.basePrefix + sig.path;
        const auto r = get(path);
        if (!r.ok) continue;
        if (r.parsed.statusCode < 200 || r.parsed.statusCode >= 300) continue;
        const QString ev = matchSignature(r.parsed.body, sig);
        if (ev.isEmpty()) continue;
        // The same signature firing on the bogus control => the host serves it
        // for any path => not a real exposure of this file (pure, unit-tested).
        if (suppressAsCatchAll(controlIs2xx, controlBody, sig)) continue;
        result.hits.append({ sig.path, sig.severity, sig.summary, r.parsed.statusCode, ev });
    }
    return result;
}

} // namespace Nullock::Core::ExposureScan

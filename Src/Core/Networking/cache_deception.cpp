#include "cache_deception.hpp"
#include "cache_poison.hpp"   // reuse the hardened looksCacheable (ccSeconds + Vary)
#include "networking.hpp"

namespace Nullock::Core::CacheDeception {

// (Pure helpers -- randTok, lenSimilar, isCatchAll, buildGet -- live in
// cache_deception_logic.cpp so the regression test can exercise them without
// the network stack. Cacheability reuses the sibling cache-poison probe's
// hardened looksCacheable, which rejects max-age=0 and honors Vary/s-maxage.)

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    const quint16 port = static_cast<quint16>(req.port);
    HttpClient client;
    auto send = [&](const QString &path) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildGet(req, path));
    };
    // Carry the original query onto every probe so we compare the same page the
    // baseline saw (a sensitive page may require its query); without it a no-
    // query probe could fetch a different page -> mismatched comparison.
    const QString qs = req.query.isEmpty() ? QString() : QStringLiteral("?") + req.query;

    const QString pathOnly = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    const auto baseResp = send(pathOnly + qs);
    if (!baseResp.ok) { result.error = "baseline failed: " + baseResp.errorMessage; return result; }
    result.baselineStatus = baseResp.parsed.statusCode;
    const QByteArray baseBody = baseResp.parsed.body;
    result.baselineLen = baseBody.size();
    // A non-2xx baseline (login redirect / 404) has no sensitive page to leak.
    if (baseResp.parsed.statusCode < 200 || baseResp.parsed.statusCode >= 300) {
        result.error = "baseline not a 2xx page (nothing to deceive)";
        return result;
    }

    // INERT CONTROL: a bogus, non-existent sibling base at the same depth with a
    // static suffix. If the app serves a length-similar 2xx for THAT too, every
    // path routes to one page (catch-all / SPA fallback) -- a static-suffix
    // "hit" would be route-everything-to-index, not path confusion. Suppress.
    QString stem = pathOnly;
    if (stem.size() > 1 && stem.endsWith('/')) stem.chop(1);  // so /account/ behaves like /account
    const int lastSlash = stem.lastIndexOf('/');
    const QString parent = (lastSlash <= 0) ? QString() : stem.left(lastSlash);
    const QString bogusBase = parent + "/nlk-noexist-" + randTok();
    const auto ctrl = send(bogusBase + "/" + randTok() + ".css" + qs);
    if (isCatchAll(ctrl.ok, ctrl.parsed.statusCode, ctrl.parsed.body.size(), baseBody.size())) {
        result.catchAll = true;
        result.error = "suppressed: a bogus base returns a length-similar 2xx "
            "(catch-all / SPA history fallback) -- every path serves the same "
            "page, so the static-suffix match is not path confusion";
        return result;
    }

    static const QStringList exts = { ".css", ".js", ".jpg", ".png", ".ico" };
    for (const QString &ext : exts) {
        // /<path>/<random>.css -- a suffix a cache treats as static.
        const QString sep = pathOnly.endsWith('/') ? QString() : QStringLiteral("/");
        const QString probe = pathOnly + sep + randTok() + ext + qs;
        const auto r = send(probe);
        if (!r.ok) continue;
        if (r.parsed.statusCode < 200 || r.parsed.statusCode >= 300) continue;
        // Path confusion: the dynamic page is echoed at the static URL (the app
        // ignored the suffix) rather than returning a 404 or a real asset.
        if (!lenSimilar(r.parsed.body.size(), baseBody.size())) continue;
        const bool cacheable = CachePoison::looksCacheable(r.parsed.headers);
        result.hits.append({ ext, probe, cacheable,
            QString("dynamic page served at static URL %1%2")
                .arg(probe, cacheable ? " AND response is cacheable" : "") });
    }
    return result;
}

} // namespace Nullock::Core::CacheDeception

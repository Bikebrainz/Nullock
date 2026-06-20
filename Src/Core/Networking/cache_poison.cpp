#include "cache_poison.hpp"
#include "networking.hpp"

namespace Nullock::Core::CachePoison {

namespace {

// The unkeyed-header probes worth trying, with the shape of value each one
// takes. Host-class headers reflect into absolute URLs / Host-derived links;
// path-class headers reflect into routing / Location.
struct Probe {
    const char *header;
    bool        pathLike;   // value is a "/..." path rather than a host
};
const QList<Probe> &probes() {
    static const QList<Probe> p = {
        { "X-Forwarded-Host",   false },
        { "X-Host",             false },
        { "X-Forwarded-Server", false },
        { "X-Forwarded-Prefix", true  },
        { "X-Original-URL",     true  },
        { "X-Rewrite-URL",      true  },
        { "X-Original-Host",    false },
    };
    return p;
}

} // namespace

// (Pure helpers -- randTok, reflectionSite, cacheHitSignal, looksCacheable,
// buildRequest, withBuster, gateDecision -- live in cache_poison_logic.cpp so
// the regression test can exercise them without the network stack.)

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query, const QString &hdr, const QString &val) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, query, hdr, val));
    };

    // SAFETY GATE (fail-closed). We inject a poison ONLY after positively
    // proving the buster is part of the cache key -- otherwise the poison could
    // land on the real key and be served to actual users. Probe: two requests
    // with the SAME buster (the repeat must come back a cache HIT), then one
    // with a DIFFERENT buster (it must MISS). Any other outcome -- no hit
    // signal at all (a silent cache), a failed confirmation, or the different
    // buster also hitting (unkeyed) -- aborts WITHOUT injecting. All requests
    // here are clean (no injected header). This doubles as the baseline.
    const QString k1 = randTok();
    const auto a = send(withBuster(req.query, k1), QString(), QString());
    if (!a.ok) { result.error = "baseline failed: " + a.errorMessage; return result; }
    result.baselineStatus = a.parsed.statusCode;

    const auto b = send(withBuster(req.query, k1), QString(), QString());
    const bool bHit = b.ok && cacheHitSignal(b.parsed.headers);
    // Only spend the different-buster confirmation request if the same-buster
    // repeat actually hit; otherwise the decision is already an abort.
    bool cOk = false, cHit = false;
    if (bHit) {
        const auto c = send(withBuster(req.query, randTok()), QString(), QString());
        cOk = c.ok;
        cHit = c.ok && cacheHitSignal(c.parsed.headers);
    }

    switch (gateDecision(b.ok, bHit, cOk, cHit)) {
    case Gate::AbortNoHitSignal:
        result.error = "aborted: could not confirm the cache serves a hit for "
            "the buster (no observable cache-hit signal) -- refusing to inject, "
            "since the buster's keying can't be proven and a poison could reach "
            "real users";
        return result;
    case Gate::AbortConfirmFailed:
        result.error = "aborted: the buster-keying confirmation request failed "
            "-- refusing to inject without proof the cache keys on the buster";
        return result;
    case Gate::AbortUnkeyed:
        result.error = "aborted: the cache ignores the buster parameter "
            "(unkeyed) -- injecting here could poison the response served to "
            "real users, so no header was injected";
        return result;
    case Gate::Inject:
        break;  // keying proven -- safe to inject against a throwaway key
    }

    for (const Probe &p : probes()) {
        const QString header = QString::fromUtf8(p.header);
        const QString tok = randTok();
        const QString cb = randTok();
        const QString value = p.pathLike ? "/" + tok
                                          : tok + QStringLiteral(".nullock-poison.test");
        const QString query = withBuster(req.query, cb);

        // 1) Poison our own throwaway key.
        const auto pr = send(query, header, value);
        if (!pr.ok) continue;
        const QString site = reflectionSite(pr.parsed.body, pr.parsed.headers, tok);
        if (site.isEmpty()) continue;          // not reflected -> no poisoning vector
        // A path-class header (X-Original-URL: /<tok>) the server *routes* to
        // typically yields a 404 page echoing the path -- that's routing, not
        // a cacheable poisoning vector. Don't count a 404 body reflection.
        if (p.pathLike && pr.parsed.statusCode == 404 && site == QStringLiteral("body"))
            continue;

        Hit hit;
        hit.header = header;
        hit.sentValue = value;
        hit.where = site;
        hit.reflected = true;
        hit.cacheable = looksCacheable(pr.parsed.headers, header);

        // 2) Re-request the SAME key with NO header. The server cannot reflect
        //    a header it never received, so a surviving token served *from the
        //    cache* (a hit signal on this clean response) proves the poisoning
        //    end to end. Requiring the hit signal -- not just token survival --
        //    rejects servers that merely echo the last-seen header from app
        //    state rather than a shared cache. (The fail-closed gate above has
        //    already proven the buster keys the cache, which also rules out a
        //    per-IP/session cache faking this hit -- it would have hit on the
        //    different buster and aborted.)
        const auto clean = send(query, QString(), QString());
        if (clean.ok && !reflectionSite(clean.parsed.body, clean.parsed.headers, tok).isEmpty()
                     && cacheHitSignal(clean.parsed.headers))
            hit.cacheConfirmed = true;

        if (hit.cacheConfirmed) result.anyConfirmed = true;
        if (hit.cacheable)      result.anyCacheable = true;
        result.hits.append(hit);
    }

    return result;
}

} // namespace Nullock::Core::CachePoison

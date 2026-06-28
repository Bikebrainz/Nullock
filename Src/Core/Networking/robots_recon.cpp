#include "robots_recon.hpp"
#include "networking.hpp"

namespace Nullock::Core::RobotsRecon {

namespace {

constexpr int kMaxBody = 512 * 1024;
constexpr int kMaxRedirectHops    = 3;    // per fetch, same-host only
constexpr int kMaxSitemapFetches  = 12;   // total child-sitemap GETs (loop/SSRF bound)

QString originUrl(const QString &host, int port, bool tls, const QString &path) {
    QString u = (tls ? QStringLiteral("https://") : QStringLiteral("http://")) + host;
    if (port > 0 && port != (tls ? 443 : 80)) u += QLatin1Char(':') + QString::number(port);
    return u + path;
}

QString locationHeader(const Proxy::HttpResponse &r) {
    for (const auto &h : r.headers)
        if (h.first.compare(QLatin1String("Location"), Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// looksLikeRobots(), parseRobots(), parseSitemapLocs() and isSitemapIndex() are
// pure and live in robots_logic.cpp so they can be unit-tested against Qt6::Core
// alone. This TU keeps buildGet()/scan() (the HttpClient I/O).

QByteArray buildGet(const Request &req, const QString &path) {
    // Request-line / Host injection guard: path can be reassigned from a server
    // Location redirect (resolveRedirect -> t.path, response-controlled), and
    // host is written RAW -- a CR/LF in either injects a header / splits the line.
    if (req.host.contains('\r') || req.host.contains('\n')) return {};
    if (path.contains('\r')     || path.contains('\n'))     return {};
    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/robots-recon\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace

Result scan(const Request &req) {
    Result result;
    result.host = req.host;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;

    // Fetch `path` on (tls, port) of the SCANNED host, following up to
    // kMaxRedirectHops redirects -- but ONLY same-host http(s) ones (resolveRedirect
    // drops a foreign scheme; sameHost drops a host-jump, so an open redirect can't
    // pivot the scan onto another origin). Returns the final 2xx body or "".
    auto fetchFollowing = [&](bool tls, int port, QString path) -> QString {
        for (int hop = 0; hop <= kMaxRedirectHops; ++hop) {
            const auto r = client.send(req.host, static_cast<quint16>(port), tls, buildGet(req, path));
            if (!r.ok) return QString();
            const int sc = r.parsed.statusCode;
            if (sc >= 200 && sc < 300) return QString::fromUtf8(r.parsed.body.left(kMaxBody));
            if (!(sc >= 300 && sc < 400) || hop == kMaxRedirectHops) return QString();
            const QString target = resolveRedirect(locationHeader(r.parsed),
                                                   originUrl(req.host, port, tls, path));
            const FetchTarget t = parseFetchTarget(target);
            // No host-jump, and no port/scheme pivot off the request origin (an
            // attacker-controlled Location must not steer us to :6379/:9200/... on
            // the in-scope host); a canonical http<->https upgrade still follows.
            if (!t.valid || !sameHost(t.host, req.host)
                || !portInScope(t.port, t.tls, req.port, req.tls)) return QString();
            tls = t.tls; port = t.port; path = t.path;
        }
        return QString();
    };

    // 1) robots.txt (following redirects, e.g. http->https or /robots.txt -> CDN).
    {
        const QString body = fetchFollowing(req.tls, req.port, QStringLiteral("/robots.txt"));
        if (!body.isEmpty() && looksLikeRobots(body)) {
            result.robotsFound = true;
            parseRobots(body, result.disallowed, result.disallowedPatterns,
                        result.sitemapRefs, result.disallowTruncated);
        }
    }

    // 2) sitemaps: BFS the conventional /sitemap.xml PLUS every Sitemap: ref from
    //    robots.txt, FETCHING child sitemaps of an index (one or more levels) so
    //    their page <loc>s actually land in sitemapUrls -- not just a "fetch these"
    //    lead. Bounded by a global fetch budget + a visited set (loop/SSRF guard),
    //    and same-host only.
    {
        QStringList worklist;
        worklist << originUrl(req.host, req.port, req.tls, QStringLiteral("/sitemap.xml"));
        for (const QString &ref : result.sitemapRefs) worklist << ref;   // robots Sitemap: refs

        QSet<QString> visited;
        QSet<QString> seenPages;          // dedup sitemapUrls across all fetched sitemaps
        for (const QString &u : result.sitemapUrls) seenPages.insert(u);
        int fetches = 0;

        while (!worklist.isEmpty()) {
            const QString url = worklist.takeFirst();
            const FetchTarget t = parseFetchTarget(url);
            // http(s) + no host-jump + no port/scheme pivot off the request origin.
            if (!t.valid || !sameHost(t.host, req.host)
                || !portInScope(t.port, t.tls, req.port, req.tls)) continue;
            const QString key = QString::number(t.tls) + QLatin1Char('|')
                              + QString::number(t.port) + QLatin1Char('|') + t.path;
            if (visited.contains(key)) continue;
            visited.insert(key);
            if (fetches >= kMaxSitemapFetches) { result.sitemapFetchTruncated = true; break; }
            ++fetches;

            const QString body = fetchFollowing(t.tls, t.port, t.path);
            if (body.isEmpty()) continue;
            if (!(body.contains(QLatin1String("<loc"), Qt::CaseInsensitive)
                  || body.contains(QLatin1String("<urlset"), Qt::CaseInsensitive)
                  || body.contains(QLatin1String("<sitemapindex"), Qt::CaseInsensitive)))
                continue;                                                  // not a sitemap

            result.sitemapFound = true;
            bool trunc = false;
            const QStringList locs = parseSitemapLocs(body, trunc);
            if (trunc) result.sitemapTruncated = true;

            if (isSitemapIndex(body)) {
                // <loc>s are CHILD SITEMAPS: resolve each against the parent sitemap
                // URL (a relative / protocol-relative child would otherwise be
                // dropped by parseFetchTarget), record as refs AND enqueue to fetch.
                for (const QString &l : locs) {
                    const QString childUrl = resolveRedirect(l, url);   // absolute, http(s)-only
                    if (childUrl.isEmpty()) continue;
                    if (!result.sitemapRefs.contains(childUrl)) result.sitemapRefs.append(childUrl);
                    worklist << childUrl;
                }
            } else {
                // <loc>s are page URLs.
                for (const QString &l : locs)
                    if (!seenPages.contains(l)) { seenPages.insert(l); result.sitemapUrls.append(l); }
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::RobotsRecon

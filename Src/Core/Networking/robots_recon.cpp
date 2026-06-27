#include "robots_recon.hpp"
#include "networking.hpp"

namespace Nullock::Core::RobotsRecon {

namespace {

constexpr int kMaxBody = 512 * 1024;

// looksLikeRobots(), parseRobots(), parseSitemapLocs() and isSitemapIndex() are
// pure and live in robots_logic.cpp so they can be unit-tested against Qt6::Core
// alone. This TU keeps buildGet()/scan() (the HttpClient I/O).

QByteArray buildGet(const Request &req, const QString &path) {
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
    const quint16 port = static_cast<quint16>(req.port);

    // 1) robots.txt
    {
        const auto r = client.send(req.host, port, req.tls, buildGet(req, "/robots.txt"));
        if (r.ok && r.parsed.statusCode >= 200 && r.parsed.statusCode < 300) {
            const QString body = QString::fromUtf8(r.parsed.body.left(kMaxBody));
            if (looksLikeRobots(body)) {
                result.robotsFound = true;
                parseRobots(body, result.disallowed, result.disallowedPatterns,
                            result.sitemapRefs, result.disallowTruncated);
            }
        }
    }

    // 2) sitemap.xml (the conventional location).
    {
        const auto r = client.send(req.host, port, req.tls, buildGet(req, "/sitemap.xml"));
        if (r.ok && r.parsed.statusCode >= 200 && r.parsed.statusCode < 300) {
            const QString body = QString::fromUtf8(r.parsed.body.left(kMaxBody));
            if (body.contains(QLatin1String("<loc"), Qt::CaseInsensitive)
                || body.contains(QLatin1String("<urlset"), Qt::CaseInsensitive)
                || body.contains(QLatin1String("<sitemapindex"), Qt::CaseInsensitive)) {
                result.sitemapFound = true;
                const QStringList locs = parseSitemapLocs(body, result.sitemapTruncated);
                if (isSitemapIndex(body)) {
                    // The <loc>s are CHILD SITEMAPS, not pages -- route them to
                    // sitemapRefs (a fetch-these lead) instead of mislabeling them
                    // as page URLs. (Fetching/recursing the children is follow-up
                    // I/O; here we at least classify them correctly.)
                    for (const QString &l : locs)
                        if (!result.sitemapRefs.contains(l)) result.sitemapRefs.append(l);
                } else {
                    result.sitemapUrls = locs;
                }
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::RobotsRecon

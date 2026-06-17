#include "robots_recon.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QSet>

namespace Nullock::Core::RobotsRecon {

namespace {

constexpr int kMaxBody     = 512 * 1024;
constexpr int kMaxLocs     = 500;
constexpr int kMaxDisallow = 200;

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

// A body is robots.txt-ish if it carries any of the directives -- guards against
// a catch-all server that 200s an HTML page for /robots.txt.
bool looksLikeRobots(const QString &body) {
    static const QRegularExpression re(
        QStringLiteral("(?im)^\\s*(user-agent|disallow|allow|sitemap|crawl-delay)\\s*:"));
    return re.match(body).hasMatch();
}

} // namespace

void parseRobots(const QString &body, QStringList &disallowed, QStringList &sitemapRefs) {
    QSet<QString> seenDis, seenSm;
    const QStringList lines = body.split('\n');
    for (QString line : lines) {
        const int hash = line.indexOf('#');          // strip trailing comment
        if (hash >= 0) line = line.left(hash);
        line = line.trimmed();
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        const QString key = line.left(colon).trimmed().toLower();
        const QString val = line.mid(colon + 1).trimmed();
        if (val.isEmpty()) continue;
        if (key == QLatin1String("disallow")) {
            // "/" alone means the whole site -- not a specific lead; skip it.
            if (val == QLatin1String("/")) continue;
            if (!seenDis.contains(val) && disallowed.size() < kMaxDisallow) {
                seenDis.insert(val);
                disallowed.append(val);
            }
        } else if (key == QLatin1String("sitemap")) {
            if (!seenSm.contains(val)) { seenSm.insert(val); sitemapRefs.append(val); }
        }
    }
}

QStringList parseSitemapLocs(const QString &body) {
    QStringList out;
    QSet<QString> seen;
    static const QRegularExpression re(QStringLiteral("(?is)<loc>\\s*(.*?)\\s*</loc>"));
    auto it = re.globalMatch(body);
    while (it.hasNext() && out.size() < kMaxLocs) {
        const QString loc = it.next().captured(1).trimmed();
        if (loc.isEmpty() || seen.contains(loc)) continue;
        seen.insert(loc);
        out.append(loc);
    }
    return out;
}

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
                parseRobots(body, result.disallowed, result.sitemapRefs);
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
                result.sitemapUrls = parseSitemapLocs(body);
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::RobotsRecon

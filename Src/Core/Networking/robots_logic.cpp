// Pure robots.txt / sitemap parsing, split out of robots_recon.cpp so a unit test
// can link it against Qt6::Core alone -- scan()'s HttpClient I/O stays in
// robots_recon.cpp. Everything here is a deterministic function of the response
// body text.

#include "robots_recon.hpp"

#include <QRegularExpression>
#include <QSet>

namespace Nullock::Core::RobotsRecon {

namespace {
constexpr int kMaxLocs     = 500;
constexpr int kMaxDisallow = 200;

// A Disallow value is a MATCH PATTERN (not a fetchable path) when it carries the
// RFC 9309 wildcard '*' or the end-anchor '$' -- e.g. "*", "/*.php$", "/search?*".
bool isDisallowPattern(const QString &val) {
    return val.contains(QLatin1Char('*')) || val.endsWith(QLatin1Char('$'));
}
} // namespace

bool looksLikeRobots(const QString &body) {
    // The first non-whitespace token ON A LINE must be a robots directive (the
    // ^\s* anchor means arbitrary HTML like "<p>disallow:</p>" does NOT match).
    static const QRegularExpression re(
        QStringLiteral("(?im)^\\s*(user-agent|disallow|allow|sitemap|crawl-delay)\\s*:"));
    return re.match(body).hasMatch();
}

void parseRobots(const QString &body, QStringList &disallowed, QStringList &disallowedPatterns,
                 QStringList &sitemapRefs, bool &truncated) {
    truncated = false;
    QSet<QString> seenDis, seenPat, seenSm;
    const QStringList lines = body.split('\n');
    for (QString line : lines) {
        const int hash = line.indexOf('#');          // strip trailing comment (RFC 9309)
        if (hash >= 0) line = line.left(hash);
        line = line.trimmed();
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        const QString key = line.left(colon).trimmed().toLower();
        const QString val = line.mid(colon + 1).trimmed();  // value NOT lower-cased (paths are case-sensitive)
        if (val.isEmpty()) continue;
        if (key == QLatin1String("disallow")) {
            if (val == QLatin1String("/")) continue;        // whole-site, not a specific lead
            // An absolute-URL Disallow value is malformed (RFC 9309 values are
            // same-authority paths) -- not a path lead on the scanned host. Drop.
            if (val.contains(QLatin1String("://"))) continue;
            const bool pattern = isDisallowPattern(val);
            QStringList &bucket = pattern ? disallowedPatterns : disallowed;
            QSet<QString> &seen = pattern ? seenPat : seenDis;
            if (seen.contains(val)) continue;
            if (bucket.size() >= kMaxDisallow) { truncated = true; continue; }
            seen.insert(val);
            bucket.append(val);
        } else if (key == QLatin1String("sitemap")) {
            if (!seenSm.contains(val)) { seenSm.insert(val); sitemapRefs.append(val); }
        }
        // 'allow' and 'crawl-delay' are intentionally ignored (not recon leads);
        // User-agent grouping is intentionally flattened (a path any UA is told to
        // avoid is still a path worth probing).
    }
}

QStringList parseSitemapLocs(const QString &body, bool &truncated) {
    truncated = false;
    QStringList out;
    QSet<QString> seen;
    // Tolerate an optional namespace prefix and attributes on <loc>, e.g.
    // "<image:loc>", "<loc xml:lang=\"en\">" -- the bare-literal "<loc>" form
    // silently dropped image/video-extension and attributed URLs. \b after loc
    // keeps it from matching <location>.
    static const QRegularExpression re(QStringLiteral(
        "(?is)<(?:[A-Za-z][\\w.\\-]*:)?loc\\b[^>]*>\\s*(.*?)\\s*</(?:[A-Za-z][\\w.\\-]*:)?loc\\s*>"));
    auto it = re.globalMatch(body);
    while (it.hasNext()) {
        const QString loc = it.next().captured(1).trimmed();
        if (loc.isEmpty() || seen.contains(loc)) continue;
        if (out.size() >= kMaxLocs) { truncated = true; break; }
        seen.insert(loc);
        out.append(loc);
    }
    return out;
}

bool isSitemapIndex(const QString &body) {
    // A sitemap index nests child-sitemap <loc>s inside <sitemap> wrappers under a
    // <sitemapindex> root (possibly namespace-prefixed, e.g. <sm:sitemapindex>).
    return body.contains(QLatin1String("<sitemapindex"), Qt::CaseInsensitive)
        || body.contains(QLatin1String(":sitemapindex"), Qt::CaseInsensitive);
}

} // namespace Nullock::Core::RobotsRecon

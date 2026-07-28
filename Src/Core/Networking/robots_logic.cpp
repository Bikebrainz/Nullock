// Pure robots.txt / sitemap parsing, split out of robots_recon.cpp so a unit test
// can link it against Qt6::Core alone -- scan()'s HttpClient I/O stays in
// robots_recon.cpp. Everything here is a deterministic function of the response
// body text.

#include "robots_recon.hpp"

#include <QRegularExpression>
#include <QSet>
#include <QUrl>

namespace Nullock::Core::RobotsRecon {

namespace {
constexpr int kMaxLocs     = 500;
constexpr int kMaxDisallow = 200;
// Sitemap: refs were the ONE output of this parser with no ceiling, while Disallow
// values and <loc> URLs were both capped. The body is attacker-controlled and
// bounded only by the 128 MB response cap, so a robots.txt of nothing but distinct
// "Sitemap:" lines (~14 bytes each) yielded millions of retained QStrings -- and
// scan() then copies every one into its BFS worklist AND, for each child <loc> it
// resolves, does a LINEAR sitemapRefs.contains() scan over the whole list. That is
// quadratic in a number the target chooses. Real robots.txt files carry a handful
// of Sitemap: lines; 100 is far above legitimate use.
constexpr int kMaxSitemapRefs = 100;

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
                 QStringList &sitemapRefs, bool &truncated, bool *sitemapRefsTruncated) {
    truncated = false;
    if (sitemapRefsTruncated) *sitemapRefsTruncated = false;
    QSet<QString> seenDis, seenPat, seenSm;
    // Split on ANY line terminator. RFC 9309 accepts CR, LF or CRLF, so a bare-CR
    // robots.txt is legal -- and splitting on '\n' alone collapsed the whole file
    // into ONE line, yielding zero Disallow leads and zero Sitemap refs. Worse, it
    // failed SILENTLY in the shape that looks like success: looksLikeRobots() still
    // matches (its ^ anchor hits at offset 0), so the scan reports robotsFound=true
    // and then finds nothing -- indistinguishable from a site with an empty
    // robots.txt. A target can serve bare-CR deliberately to hide paths from this
    // scanner while every RFC-conformant crawler still reads them.
    static const QRegularExpression lineBreak(QStringLiteral("\r\n|\r|\n"));
    const QStringList lines = body.split(lineBreak);
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
            // same-authority paths) -- not a path lead on the scanned host. Reject
            // only a value that IS an absolute URL (scheme at the START); a path
            // whose query merely contains "://" (e.g. /go?url=http://x) is a lead.
            static const QRegularExpression absRx(QStringLiteral("^[a-zA-Z][a-zA-Z0-9+.-]*://"));
            if (absRx.match(val).hasMatch()) continue;
            const bool pattern = isDisallowPattern(val);
            QStringList &bucket = pattern ? disallowedPatterns : disallowed;
            QSet<QString> &seen = pattern ? seenPat : seenDis;
            if (seen.contains(val)) continue;
            if (bucket.size() >= kMaxDisallow) { truncated = true; continue; }
            seen.insert(val);
            bucket.append(val);
        } else if (key == QLatin1String("sitemap")) {
            if (seenSm.contains(val)) continue;
            if (sitemapRefs.size() >= kMaxSitemapRefs) {
                if (sitemapRefsTruncated) *sitemapRefsTruncated = true;
                continue;                 // cap the list AND the dedupe set with it
            }
            seenSm.insert(val);
            sitemapRefs.append(val);
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
    // Decide index-vs-urlset from the ROOT element, not a free substring: a bare
    // contains("<sitemapindex"/":sitemapindex") misclassifies a page <urlset>
    // whose <loc> merely carries that text (e.g. ".../x?ref=:sitemapindex") or
    // that buries it in a comment -- dropping every real page URL. Strip comments,
    // then take whichever of <sitemapindex>/<urlset> START TAG appears first
    // (namespace-prefix tolerant, with a real tag boundary like parseSitemapLocs).
    QString b = body;
    b.remove(QRegularExpression(QStringLiteral("(?s)<!--.*?-->")));
    static const QRegularExpression idxRe(
        QStringLiteral("(?is)<\\s*(?:[A-Za-z][\\w.\\-]*:)?sitemapindex[\\s/>]"));
    static const QRegularExpression setRe(
        QStringLiteral("(?is)<\\s*(?:[A-Za-z][\\w.\\-]*:)?urlset[\\s/>]"));
    const auto mi = idxRe.match(b);
    if (!mi.hasMatch()) return false;
    const auto ms = setRe.match(b);
    return !ms.hasMatch() || mi.capturedStart() < ms.capturedStart();
}

FetchTarget parseFetchTarget(const QString &url) {
    FetchTarget t;
    const QUrl u(url.trimmed());
    if (!u.isValid() || u.host().isEmpty()) return t;
    const QString scheme = u.scheme().toLower();
    if (scheme != QLatin1String("http") && scheme != QLatin1String("https")) return t;
    t.valid = true;
    t.tls   = (scheme == QLatin1String("https"));
    t.host  = u.host();
    t.port  = u.port(t.tls ? 443 : 80);          // -1 (absent) -> scheme default
    QString path = u.path(QUrl::FullyEncoded);
    if (path.isEmpty()) path = QStringLiteral("/");
    const QString q = u.query(QUrl::FullyEncoded);
    if (!q.isEmpty()) path += QLatin1Char('?') + q;
    t.path = path;
    return t;
}

QString resolveRedirect(const QString &location, const QString &baseUrl) {
    const QString loc = location.trimmed();
    if (loc.isEmpty()) return QString();
    const QUrl abs = QUrl(baseUrl).resolved(QUrl(loc));
    if (!abs.isValid() || abs.host().isEmpty()) return QString();
    const QString scheme = abs.scheme().toLower();
    if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
        return QString();                        // never follow javascript:/data:/mailto: ...
    return abs.toString();
}

bool sameHost(const QString &a, const QString &b) {
    return !a.isEmpty() && a.compare(b, Qt::CaseInsensitive) == 0;
}

bool portInScope(int targetPort, bool targetTls, int reqPort, bool reqTls) {
    // The request's own port is always in scope; otherwise allow ONLY a canonical
    // http<->https hop where BOTH endpoints sit on their scheme's default port
    // (so a tested http:80 -> https:443 upgrade still follows). This refuses an
    // attacker-controlled sitemap/redirect from steering a fetch to an unrelated
    // service port (:6379 / :9200 / :22 / :8080 ...) on the in-scope host.
    if (targetPort == reqPort) return true;
    const int targetDefault = targetTls ? 443 : 80;
    const int reqDefault    = reqTls    ? 443 : 80;
    return targetPort == targetDefault && reqPort == reqDefault;
}

} // namespace Nullock::Core::RobotsRecon

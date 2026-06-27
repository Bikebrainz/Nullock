#pragma once

// robots.txt + sitemap recon. Fetches /robots.txt and /sitemap.xml and surfaces
// the paths the owner asked crawlers to avoid (Disallow) -- a classic source of
// unlinked / sensitive endpoints worth probing -- plus sitemap-listed URLs, as
// recon leads. Read-only GETs; identification only (it names paths, doesn't
// fetch them). Complements js_recon (JS endpoint mining) and exposure_scan.

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::RobotsRecon {

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QString     host;
    bool        robotsFound = false;
    bool        sitemapFound = false;
    QStringList disallowed;          // concrete Disallow PATHS (a "/..." lead)
    QStringList disallowedPatterns;  // Disallow MATCH PATTERNS ("*", "/*.php$") --
                                     // NOT fetchable paths; kept distinct so a
                                     // consumer doesn't GET a literal "/*.php$".
    QStringList sitemapRefs;         // Sitemap: URLs (robots.txt) + child sitemaps
                                     // from a <sitemapindex> (NOT page leads).
    QStringList sitemapUrls;         // <loc> page URLs from a <urlset> sitemap.xml
    bool        disallowTruncated = false;  // the Disallow cap was hit (more existed)
    bool        sitemapTruncated  = false;  // the <loc> cap was hit (more existed)
    QString     error;
};

Result scan(const Request &req);

// --- Pure parsing, exposed for the unit test (no I/O; in robots_logic.cpp, links
//     Qt6::Core alone -- scan()'s HttpClient work stays in robots_recon.cpp).
//
//   looksLikeRobots  -- the body's first non-whitespace token on some line is a
//                       robots directive (guards an HTML catch-all 200).
//   parseRobots      -- classify Disallow values into concrete PATHS vs match
//                       PATTERNS (and drop absolute-URL values, which aren't a
//                       same-host path lead); collect Sitemap: refs. Sets
//                       `truncated` when the cap is reached.
//   parseSitemapLocs -- extract <loc> URLs, tolerant of a namespace prefix /
//                       attributes (<image:loc>, <loc xml:lang=...>). Sets
//                       `truncated` when the cap is reached.
//   isSitemapIndex   -- the body is a <sitemapindex> (its <loc>s are CHILD
//                       sitemaps, not pages) rather than a <urlset>.
bool looksLikeRobots(const QString &body);
void parseRobots(const QString &body, QStringList &disallowed, QStringList &disallowedPatterns,
                 QStringList &sitemapRefs, bool &truncated);
QStringList parseSitemapLocs(const QString &body, bool &truncated);
bool isSitemapIndex(const QString &body);

} // namespace Nullock::Core::RobotsRecon

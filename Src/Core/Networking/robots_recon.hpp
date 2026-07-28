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
    bool        sitemapFetchTruncated = false; // the child-sitemap FETCH budget was hit
                                               // (more child sitemaps existed unfetched)
    bool        sitemapRefsTruncated  = false; // the robots.txt "Sitemap:" cap was hit
    QString     error;
};

Result scan(const Request &req);

// A parsed, fetchable sitemap/redirect target (http(s) only). Used by scan() to
// decide whether to follow a child sitemap / Sitemap: ref / redirect. Pure data.
struct FetchTarget {
    bool    valid = false;
    bool    tls   = false;
    QString host;
    int     port  = 0;
    QString path;        // path (+ "?query" when present); never empty ("/" minimum)
};

// --- Pure parsing, exposed for the unit test (no I/O; in robots_logic.cpp, links
//     Qt6::Core alone -- scan()'s HttpClient work stays in robots_recon.cpp).
//
//   looksLikeRobots  -- the body's first non-whitespace token on some line is a
//                       robots directive (guards an HTML catch-all 200).
//   parseRobots      -- classify Disallow values into concrete PATHS vs match
//                       PATTERNS (and drop absolute-URL values, which aren't a
//                       same-host path lead); collect Sitemap: refs. Sets
//                       `truncated` when the DISALLOW cap is reached, and
//                       `sitemapRefsTruncated` (when supplied) when the Sitemap:
//                       cap is reached. Both lists are capped: the body is
//                       attacker-controlled, and sitemapRefs used to be the one
//                       output with no ceiling at all.
//   parseSitemapLocs -- extract <loc> URLs, tolerant of a namespace prefix /
//                       attributes (<image:loc>, <loc xml:lang=...>). Sets
//                       `truncated` when the cap is reached.
//   isSitemapIndex   -- the body is a <sitemapindex> (its <loc>s are CHILD
//                       sitemaps, not pages) rather than a <urlset>.
bool looksLikeRobots(const QString &body);
void parseRobots(const QString &body, QStringList &disallowed, QStringList &disallowedPatterns,
                 QStringList &sitemapRefs, bool &truncated,
                 bool *sitemapRefsTruncated = nullptr);
QStringList parseSitemapLocs(const QString &body, bool &truncated);
bool isSitemapIndex(const QString &body);

//   parseFetchTarget -- parse a sitemap/child/redirect URL into a fetchable
//                       target (http(s) + host required); invalid otherwise. The
//                       port defaults to the scheme's (443/80); the path keeps its
//                       query and is never empty.
//   resolveRedirect  -- resolve a Location value against the current URL (relative
//                       or absolute) into an absolute http(s) URL string, or ""
//                       for a non-http(s) / unparseable target (so an open-redirect
//                       to javascript:/data:/another scheme is not followed).
//   sameHost         -- case-insensitive host equality, used as the no-host-jump
//                       guard so following a child/redirect can't pivot to a
//                       different host (an SSRF / scope-escape hazard).
//   portInScope      -- gate the target's port/scheme to the request origin: the
//                       request's own port, or a canonical http<->https hop on the
//                       schemes' default ports. Refuses an attacker-steered fetch
//                       to an unrelated service port (:6379/:9200/...) on the host.
FetchTarget parseFetchTarget(const QString &url);
QString     resolveRedirect(const QString &location, const QString &baseUrl);
bool        sameHost(const QString &a, const QString &b);
bool        portInScope(int targetPort, bool targetTls, int reqPort, bool reqTls);

} // namespace Nullock::Core::RobotsRecon

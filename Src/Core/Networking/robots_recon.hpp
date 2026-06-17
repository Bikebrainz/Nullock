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
    QStringList disallowed;    // Disallow paths from robots.txt
    QStringList sitemapRefs;   // Sitemap: URLs declared in robots.txt
    QStringList sitemapUrls;   // <loc> URLs from sitemap.xml
    QString     error;
};

Result scan(const Request &req);

// Exposed for tests: parse robots.txt body -> disallowed paths + sitemap refs.
void parseRobots(const QString &body, QStringList &disallowed, QStringList &sitemapRefs);
// Exposed for tests: extract <loc> URLs from a sitemap.xml body.
QStringList parseSitemapLocs(const QString &body);

} // namespace Nullock::Core::RobotsRecon

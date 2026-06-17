#pragma once

// Web cache deception (CWE-525). Distinct from cache *poisoning*: here the app
// serves the SAME dynamic/sensitive page at a URL with a static-looking suffix
// (e.g. /account/profile.css), and a cache keyed on the extension stores that
// per-user response -- so an attacker requests the static URL and reads the
// victim's cached data. We detect the path-confusion precondition: request
// /<path>/<random>.css and flag when the response is the same dynamic content
// as /<path> (the app ignored the suffix) rather than a 404 or a real asset,
// raising severity when the response also looks cacheable. Read-only.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CacheDeception {

struct Hit {
    QString extension;   // ".css", ".js", ...
    QString probePath;
    bool    cacheable = false;
    QString detail;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath = QStringLiteral("/");
    QString query;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    int     baselineStatus = 0;
    int     baselineLen = 0;
    QList<Hit> hits;
    int     requestsSent = 0;
    QString error;
};

// Probe static-extension variants of basePath and flag path-confusion where the
// dynamic page is echoed under a cacheable static URL.
Result test(const Request &req);

} // namespace Nullock::Core::CacheDeception

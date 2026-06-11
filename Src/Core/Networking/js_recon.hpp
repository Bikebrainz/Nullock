#pragma once

// JavaScript recon: endpoint extraction + source-map exposure. Modern
// SPAs ship their entire client in bundled JS -- which means the JS also
// names every API the app talks to, and (if source maps are left on in
// prod) leaks the original, un-minified source. This scanner:
//
//   1. fetches a page (or a JS file directly), pulls out the same-origin
//      <script src> bundles,
//   2. extracts API endpoint paths / URLs referenced in each bundle
//      (fetch/axios calls, "/api/..."-shaped strings, absolute URLs) --
//      the real attack surface, including routes never linked in the UI,
//   3. follows each bundle's //# sourceMappingURL and, if the .map is
//      reachable, flags it and lists the original source files it exposes.
//
// Burp surfaces JS in the sitemap but doesn't mine endpoints or confirm
// source-map exposure; this does both in one call.

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::JsRecon {

struct SourceMap {
    QString jsUrl;            // the bundle that referenced it
    QString mapUrl;          // resolved .map URL
    bool    accessible = false;
    QStringList sources;     // original source paths from the map
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;                         // page or .js path
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QStringList scripts;          // same-origin bundles found
    QStringList crossOriginScripts;   // bundles on other hosts (listed, not fetched)
    QStringList endpoints;        // deduped API paths / URLs discovered
    QList<SourceMap> sourceMaps;
    int     requestsSent = 0;
    QString error;
};

// Scan the target. maxScripts bounds how many same-origin bundles we
// fetch + mine (a page can reference dozens).
Result scan(const Request &req, int maxScripts = 20);

} // namespace Nullock::Core::JsRecon

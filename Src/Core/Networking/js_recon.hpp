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
#include <QSet>
#include <QString>
#include <QStringList>

namespace Nullock::Core::JsRecon {

struct SourceMap {
    QString jsUrl;            // the bundle that referenced it
    QString mapUrl;          // resolved .map URL
    bool    accessible = false;
    QStringList sources;     // original source paths from the map
};

// A credential SHAPE found hardcoded in a bundle. The value is REDACTED (prefix
// + length only) so the finding never leaks/persists the secret itself.
struct JsSecret {
    QString kind;            // "aws-access-key", "google-api-key", "jwt", "generic-secret", ...
    QString severity;        // critical | high | medium | low | info
    QString redacted;        // e.g. "AKIA...[20 chars]" -- never the full value
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
    QList<JsSecret> secrets;      // hardcoded credential shapes (redacted)
    int     requestsSent = 0;
    QString error;
};

// Scan the target. maxScripts bounds how many same-origin bundles we
// fetch + mine (a page can reference dozens).
Result scan(const Request &req, int maxScripts = 20);

// --- Pure extraction, exposed for the unit test (no I/O; in js_recon_logic.cpp,
//     links Qt6::Core alone -- scan()'s HttpClient work stays in js_recon.cpp).
//   extractEndpoints  -- mine API endpoint paths / URLs from a JS (or inline
//                        script) body into `out`. API-token matching is
//                        path-segment-anchored (so "/therapist/" is NOT an "api"
//                        path); covers fetch/axios/xhr-open/import/Worker/
//                        sendBeacon/EventSource/WebSocket and http(s)/ws(s) URLs;
//                        keeps a template literal's static prefix; filters
//                        third-party CDNs by HOST suffix, not raw substring.
//   sourceMappingUrl  -- the EFFECTIVE //# sourceMappingURL (the LAST one wins).
void    extractEndpoints(const QString &js, QSet<QString> &out);
QString sourceMappingUrl(const QString &js);

// Mine hardcoded credential SHAPES (cloud/VCS/SaaS keys, JWTs, private-key
// headers, high-entropy api_key/secret/token assignments) from a JS body. The
// stored value is REDACTED -- the finding never carries the secret itself.
// Deduped within a body. Generic high-entropy hits are graded info (LEADs).
void    extractSecrets(const QString &js, QList<JsSecret> &out);

} // namespace Nullock::Core::JsRecon

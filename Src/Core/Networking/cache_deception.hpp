#pragma once

// Web cache deception (CWE-525). Distinct from cache *poisoning*: here the app
// serves the SAME dynamic/sensitive page at a URL with a static-looking suffix
// (e.g. /account/profile.css), and a cache keyed on the extension stores that
// per-user response -- so an attacker requests the static URL and reads the
// victim's cached data. We detect the path-confusion precondition: request
// /<path>/<random>.css and flag when the response is the same dynamic content
// as /<path> (the app ignored the suffix) rather than a 404 or a real asset,
// raising severity when the response also looks cacheable. Read-only.
//
// FALSE-POSITIVE GUARD: a catch-all / history-fallback SPA (React Router, Vue
// history mode, Next.js fallback, S3+CloudFront error->/index.html) serves a
// byte-identical shell at EVERY unmatched path, which would otherwise look like
// path confusion at every static suffix. So before trusting a hit we send an
// inert control to a bogus, non-existent sibling base with the same suffix; if
// THAT also returns a length-similar 2xx, the app routes everything to one page
// and there is nothing per-user to leak -- we suppress all hits (catchAll).

#include <QByteArray>
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
    bool    catchAll = false;   // app serves a length-similar 2xx at a bogus base -> hits suppressed
    QString error;
};

// Probe static-extension variants of basePath and flag path-confusion where the
// dynamic page is echoed under a cacheable static URL.
Result test(const Request &req);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// detection + control logic against Qt6::Core alone.

// 9-char sentinel: literal "nlk" + 6 random hex.
QString randTok();

// Are two body lengths close enough to be "the same page"? Tightened from the
// old 40-byte floor: small relative drift, with a modest absolute floor for the
// inevitable per-request variance (CSRF tokens etc.) on real pages.
bool lenSimilar(int a, int b);

// The inert-control decision: did the bogus, non-existent base ALSO return a
// length-similar 2xx? If so the app is a catch-all and any static-suffix "hit"
// is route-everything-to-index, not path confusion -> suppress.
bool isCatchAll(bool controlOk, int controlStatus, int controlLen, int baselineLen);

// Build a raw GET. Returns empty if host or path carries a CR/LF, or drops a
// carried header that does (request-line / header-injection guard).
QByteArray buildGet(const Request &req, const QString &path);

} // namespace Nullock::Core::CacheDeception

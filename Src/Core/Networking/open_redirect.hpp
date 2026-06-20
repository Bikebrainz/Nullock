#pragma once

// Open redirect (CWE-601: URL Redirection to Untrusted Site). A redirect
// target taken from user input lets an attacker bounce victims to a phishing
// / token-stealing page that looks like it came from the trusted origin --
// and it's a frequent OAuth/SSO token-leak primitive (redirect_uri abuse).
//
// The naive way to test this -- "does my payload string appear in the
// response?" -- false-positives constantly on same-origin reflections AND on
// error pages that merely ECHO the rejected payload. We confirm the robust way
// instead: fire a battery of parser-confusion payloads (scheme-relative //,
// backslashes, missing scheme, userinfo @, whitelist-prefix) at a sentinel
// host, then for every redirect sink -- the Location header, the Refresh
// RESPONSE header, and client-side <meta http-equiv=refresh> / JS
// location.{href,replace,assign} navigations -- RESOLVE the target URL against
// the request URL (RFC-3986, browser-style) and confirm only when the
// effective host is the sentinel. A relative or same-origin target never
// matches; a reflected payload sitting as inert page text never matches
// (client-side detection requires a real tag / quoted JS assignment, then
// host resolution -- not a substring). Burp Community has no confirming
// open-redirect scanner.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QUrl>

namespace Nullock::Core::OpenRedirect {

struct Hit {
    QString technique;     // "scheme-relative", "backslash", "userinfo", ...
    QString payload;       // the value injected
    QString via;           // "Location" | "refresh-header" | "meta-refresh" | "js-location"
    QString resolvedHost;  // the host the redirect actually resolves to
    QString param;         // the parameter the payload was injected into
    int     status = 0;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QString param;                              // the redirect param to test ("" = sweep all known)
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QString     testedParam;                    // first param tested (back-compat)
    QStringList testedParams;                    // every param the battery was run against
    bool    vulnerable = false;
    QList<Hit> hits;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Test `param` with the bypass battery; if empty, auto-detect and sweep EVERY
// likely redirect parameter in the query string. Confirmation is by resolved
// host of the Location header, the Refresh response header, or a client-side
// <meta refresh> / JS location navigation in the body.
// Note: the payload is injected into the query string only, so a sink that
// reads the redirect target from a POST body isn't covered.
Result test(const Request &req);

// The query keys we treat as likely redirect parameters when auto-detecting.
QStringList knownRedirectParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// The external sentinel host every payload aims at; a redirect that resolves
// here (or to a subdomain of it) left the trusted origin.
QString sentinelHost();
bool    isSentinelHost(const QString &host);
// Resolve a Location/redirect value against the request URL the way a browser
// would (backslashes as slashes, scheme with too-few-slashes normalized),
// returning the effective host. Only the authority/path head is touched.
QString resolvedRedirectHost(const QUrl &base, QString loc);
// The host a client-side redirect in the body would navigate to (real <meta
// http-equiv=refresh> tag or a quoted JS location.{href,replace,assign}=),
// resolved against base; "" if none. *via (optional) gets "meta-refresh" or
// "js-location".
QString clientSideRedirectHost(const QByteArray &body, const QUrl &base, QString *via = nullptr);
// Build the raw request, CR/LF-guarding the method/host/path (returns {} if any
// is tainted) and dropping any CR/LF-bearing header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::OpenRedirect

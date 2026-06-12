#pragma once

// Open redirect (CWE-601: URL Redirection to Untrusted Site). A redirect
// target taken from user input lets an attacker bounce victims to a phishing
// / token-stealing page that looks like it came from the trusted origin --
// and it's a frequent OAuth/SSO token-leak primitive (redirect_uri abuse).
//
// The naive way to test this -- "does my payload string appear in the
// response?" -- false-positives constantly on same-origin reflections. We
// confirm the robust way instead: fire a battery of parser-confusion
// payloads (scheme-relative //, backslashes, missing scheme, userinfo @,
// whitelist-prefix) at a sentinel host, then RESOLVE the Location header
// against the request URL (RFC-3986) and confirm only when the effective
// host is the sentinel. A relative or same-origin Location never matches.
// Burp Community has no confirming open-redirect scanner.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::OpenRedirect {

struct Hit {
    QString technique;     // "scheme-relative", "backslash", "userinfo", ...
    QString payload;       // the value injected
    QString via;           // "Location" | "meta-refresh" | "js-location"
    QString resolvedHost;  // the host the redirect actually resolves to
    int     status = 0;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QString param;                              // the redirect param to test
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QString testedParam;
    bool    vulnerable = false;
    QList<Hit> hits;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Test `param` with the bypass battery; if empty, auto-detect a likely
// redirect parameter from the query string. Confirmation is by resolved
// Location host, with a secondary lower-confidence meta-refresh / JS check.
// Note: the payload is injected into the query string only, so a sink that
// reads the redirect target from a POST body isn't covered.
Result test(const Request &req);

// The query keys we treat as likely redirect parameters when auto-detecting.
QStringList knownRedirectParams();

} // namespace Nullock::Core::OpenRedirect

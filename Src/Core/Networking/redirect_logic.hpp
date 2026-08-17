#pragma once

// Pure redirect-following logic for Repeater (and, later, Intruder). Decides
// WHETHER, WHERE, and HOW to follow a 3xx, plus the cookie threading Burp calls
// "Process cookies in redirections". No sockets -- the QObject send-loop drives
// these. URL resolution uses QUrl (RFC 3986), the same idiom crawler_logic uses.

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QPair>
#include <QString>
#include <QUrl>

namespace Nullock::Core::RedirectLogic {

// Burp's four "Follow redirections" modes.
enum FollowPolicy {
    FollowNever   = 0,
    FollowOnSite  = 1,   // only to the SAME host
    FollowInScope = 2,   // only to a host the engagement scope allows
    FollowAlways  = 3,
};
FollowPolicy parseFollowPolicy(const QString &s);   // "never"/"on-site"/"in-scope"/"always"
QString      followPolicyName(FollowPolicy p);

// The statuses that carry a Location to follow. (300 Multiple Choices has no
// single target; 304 Not Modified is not a redirect.)
bool isRedirectStatus(int status);

// Resolve a Location header value against the request's current absolute URL.
// Handles absolute ("https://x/y"), absolute-path ("/y"), relative ("y"), and
// protocol-relative ("//x/y") forms. Returns an empty QUrl when unresolvable.
QUrl resolveRedirect(const QUrl &current, const QString &location);

// The method for the followed request, matching browser/Burp behavior:
//   303        -> GET (a HEAD stays HEAD)
//   301 / 302  -> a POST becomes GET (the ubiquitous login POST->GET); other
//                 methods are preserved
//   307 / 308  -> the method is preserved
QString methodAfterRedirect(int status, const QString &currentMethod);

// Whether the original request body is carried to the follow-up. Only the
// method-preserving 307/308 keep the body; 301/302/303 drop it.
bool redirectPreservesBody(int status);

// Policy gate. never -> false; always -> true; on-site -> nextHost == originHost
// (case-insensitive); in-scope -> nextInScope (the caller supplies
// isInScope(nextHost) since scope lives in the proxy).
bool followAllowed(FollowPolicy policy, const QString &originHost,
                   const QString &nextHost, bool nextInScope);

// --- cookie threading ("Process cookies in redirections") -------------------
// Merge the name=value pair of each Set-Cookie in `headers` into `jar` (first
// segment only -- Path/Domain/etc. attributes are not values), so a session
// cookie set on hop 1 rides along on hop 2. Later Set-Cookie wins (last write).
void mergeSetCookies(QHash<QString, QString> &jar,
                     const QList<QPair<QString, QString>> &headers);
// Render the accumulated jar as a "Cookie:" header VALUE ("a=1; b=2"), keys
// sorted for determinism. Empty jar -> empty string.
QString renderCookieHeader(const QHash<QString, QString> &jar);

// --- follow-up request building ---------------------------------------------
// Build the raw follow-up request bytes for `url` using `method`, carrying the
// given Cookie header VALUE (may be empty) and optional `body` (caller passes it
// only when redirectPreservesBody(status) is true). Emits request-line + Host +
// Accept + Connection: close (+ Cookie, + Content-Length when a body is present).
QByteArray buildFollowRequest(const QUrl &url, const QString &method,
                              const QString &cookieHeader,
                              const QByteArray &body = {});

// Pull the method (first request-line token, upper-cased) and request-target
// (second token, e.g. "/path?q") out of a raw HTTP/1.1 request. Empty on a
// malformed request line.
QString requestMethod(const QByteArray &rawRequest);
QString requestTarget(const QByteArray &rawRequest);

// The absolute URL a request was sent to, from the transport (scheme from tls,
// host, port) + the request-target. Used as the base for resolving a Location.
QUrl requestUrl(bool tls, const QString &host, int port, const QByteArray &rawRequest);

} // namespace Nullock::Core::RedirectLogic

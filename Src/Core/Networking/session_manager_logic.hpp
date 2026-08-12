#pragma once

// Pure cookie-jar logic for the session manager, in a header that does NOT pull
// proxy_server.hpp (Qt Network) so the unit test links it against Qt6::Core alone.
// session_manager.hpp includes this for CapturedCookie; the I/O class
// (onResponseReceived/injectInto + the QObject/mutex) stays in session_manager.*.

#include <QString>

namespace Nullock::Core {

// One captured cookie. Holds the raw Set-Cookie value plus the parsed name=value
// pair and attributes so it can be displayed and re-injected on outgoing requests.
struct CapturedCookie {
    QString name;
    QString value;
    QString raw;          // full Set-Cookie value (everything after the colon)
    QString path;
    QString expires;
    bool    httpOnly = false;
    bool    secure   = false;
    QString sameSite;
    QString domain;       // the Domain attribute, lowercased, leading '.' stripped.
                          // Empty => host-only cookie (matches its origin host exactly).
};

namespace SessionLogic {

// Strip CR / LF / NUL and other C0 control bytes. A hostile upstream that embeds
// \r\n in a Set-Cookie could otherwise make us write split headers on the next
// request (HTTP request smuggling / header injection).
QString stripCtrl(const QString &s);

// Parse a Set-Cookie header VALUE (everything after "Set-Cookie:") into a
// CapturedCookie. The name/value are control-stripped; a name that isn't a valid
// token (contains '='/space/tab) is cleared so the caller drops the cookie.
CapturedCookie parseSetCookie(const QString &raw);

// RFC 6265 §5.1.4 path-match: does a cookie scoped to `cookiePath` apply to a
// request for `reqPath`? An empty/relative cookie path defaults to "/" (matches
// all). True iff cookiePath == reqPath, or cookiePath is a prefix of reqPath at a
// "/" boundary. Used to stop a Path-scoped cookie (e.g. Path=/admin) being
// over-injected onto an unrelated path (e.g. /public).
bool pathMatches(const QString &cookiePath, const QString &reqPath);

// May a captured cookie ride a request whose transport port is `port`? A Secure
// cookie must NEVER ride a non-TLS request -- that leaks the session token in
// cleartext to a passive observer. HttpRequest carries no scheme flag, so we fail
// CLOSED: a Secure cookie is injectable only on the standard TLS port (443); a
// non-Secure cookie is always injectable.
bool injectableOverTransport(const CapturedCookie &c, bool tls);

// RFC 6265 5.1.3 domain-match: does a Domain-scoped cookie for `cookieDomain`
// (already lowercased, leading '.' stripped) apply to request host `reqHost`?
// True iff reqHost == cookieDomain, or reqHost is a subdomain of it (ends with
// "." + cookieDomain) -- with a proper label boundary so "evil-example.com" does
// NOT match "example.com". Never matches when reqHost is an IP literal (a Domain
// cookie cannot broaden an IP host) or when cookieDomain is empty (host-only).
// This is the pure scoping predicate for the cookie jar (roadmap #194); wiring it
// into domain-aware injection is a separate step.
bool domainMatches(const QString &cookieDomain, const QString &reqHost);

} // namespace SessionLogic
} // namespace Nullock::Core

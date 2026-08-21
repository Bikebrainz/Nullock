#pragma once

// Pure cookie-jar logic for the session manager, in a header that does NOT pull
// proxy_server.hpp (Qt Network) so the unit test links it against Qt6::Core alone.
// session_manager.hpp includes this for CapturedCookie; the I/O class
// (onResponseReceived/injectInto + the QObject/mutex) stays in session_manager.*.

#include <QJsonObject>
#include <QList>
#include <QString>

namespace Nullock::Core {

// One captured cookie. Holds the raw Set-Cookie value plus the parsed name=value
// pair and attributes so it can be displayed and re-injected on outgoing requests.
// Sentinel: no Max-Age attribute was present on the Set-Cookie.
constexpr long long kNoMaxAge = (-9223372036854775807LL - 1);   // LLONG_MIN

struct CapturedCookie {
    QString name;
    QString value;
    QString raw;          // full Set-Cookie value (everything after the colon)
    QString path;
    QString expires;      // raw Expires attribute value (unparsed HTTP-date string)
    long long maxAge = kNoMaxAge;   // raw Max-Age delta-seconds; kNoMaxAge if absent
    bool    httpOnly = false;
    bool    secure   = false;
    QString sameSite;
    QString domain;       // the Domain attribute, lowercased, leading '.' stripped.
                          // Empty => host-only cookie (matches its origin host exactly).
    // Resolved lifetime (filled by resolveCookieExpiry at capture time). A cookie
    // with neither Max-Age nor a parseable Expires is a SESSION cookie
    // (persistent=false): it never time-expires and is dropped when the session ends.
    bool      persistent   = false;
    long long expiresEpoch = 0;     // absolute expiry (unix seconds); valid iff persistent
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

// Parse a Set-Cookie "Expires" HTTP-date to unix seconds, or -1 if unparseable.
// Cookie dates are lenient (RFC 6265 §5.1.1); we accept the RFC 1123 / RFC 2822
// forms Set-Cookie uses in practice ("Wed, 21 Oct 2015 07:28:00 GMT"), always in
// the C locale + UTC so a non-English system locale can't break parsing. An
// unparseable date returns -1 -> treated as a session cookie (never wrongly
// expired), which is the safe default.
long long parseCookieExpires(const QString &httpDate);

// Resolve a cookie's absolute lifetime from its Max-Age / Expires attributes,
// given the epoch at which it was CAPTURED. RFC 6265 §5.3: Max-Age takes
// precedence over Expires; a Max-Age <= 0 (or a past Expires) yields an expiry at
// or before capture time (an immediate deletion / logout). Sets c.persistent and
// c.expiresEpoch in place; leaves persistent=false (session cookie) when neither
// attribute is present or the Expires date is unparseable.
void resolveCookieExpiry(CapturedCookie &c, long long capturedAtEpoch);

// Has a (resolved) cookie expired as of `nowEpoch`? A session cookie
// (persistent=false) never time-expires. This is the pure lifetime predicate for
// the cookie jar (roadmap: cookie expiry handling); wiring it into capture-side
// deletion and inject-side skipping is a separate step.
bool cookieExpired(const CapturedCookie &c, long long nowEpoch);

// Serialize a captured cookie to/from JSON, for persisting the cookie jar in the
// project file. Full round-trip of the resolved lifetime (persistent +
// expiresEpoch) so a restored jar can drop already-expired cookies without
// re-parsing. Pure, so it is unit-tested against Qt6::Core alone.
QJsonObject    cookieToJson(const CapturedCookie &c);
CapturedCookie cookieFromJson(const QJsonObject &o);

// Validate a hand-typed cookie name against the same RFC 6265 token rule
// parseSetCookie enforces on the wire: non-empty, no '='/space, no C0 control
// byte. Guards the Cookie jar's manual add/edit path (roadmap: "add a cookie
// obtained out-of-band") so a crafted name can't smuggle a second cookie via
// header injection the next time this jar is injected into a request.
bool isValidCookieName(const QString &name);

// Upsert a cookie by name into a jar (the Cookie jar's manual add/edit): replaces
// an existing same-name cookie IN PLACE (keeping its position in the list, so
// row order in the UI doesn't jump around on edit); appends a new one otherwise.
// Pure list operation, no I/O. Caller validates the name first.
void upsertCookie(QList<CapturedCookie> &cookies, const CapturedCookie &c);

// Remove exactly one cookie by name (the Cookie jar's per-cookie delete) --
// distinct from clearing the whole host jar. Returns true iff a cookie was
// found and removed.
bool removeCookieByName(QList<CapturedCookie> &cookies, const QString &name);

} // namespace SessionLogic
} // namespace Nullock::Core

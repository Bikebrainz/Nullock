#pragma once

// Web cache poisoning (CWE-349: Acceptance of Extraneous Untrusted Data
// With Trusted Data). A cache keys entries on a subset of the request --
// typically method + path + a few headers -- and serves the stored response
// to everyone who matches that key. If an *unkeyed* input (X-Forwarded-Host,
// X-Forwarded-Scheme, X-Original-URL, ...) is reflected into the response,
// an attacker poisons the cache once and every subsequent user is served the
// attacker's content: a hijacked script src, a redirect, an XSS payload.
//
// We confirm the way PortSwigger's Param Miner does, but FAIL CLOSED: a probe
// only injects after it has POSITIVELY proven the cache-buster query param
// partitions the cache key (a same-buster repeat returns a cache HIT *and* a
// different buster returns a MISS). If that can't be shown -- no observable
// cache-hit signal at all (a "silent" cache), a failed confirmation request,
// or a buster the cache ignores -- the probe ABORTS without injecting, because
// the alternative is poisoning the key real users are served. Absence of proof
// blocks injection; it never permits it. Detection is then two-step -- inject
// an unkeyed header with a random sentinel, then re-request the same key with
// NO header; if the sentinel is still served *from cache* (a hit signal), the
// poisoning is proven end to end. No free-tool equivalent.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CachePoison {

struct Hit {
    QString header;          // the unkeyed header that reflected
    QString sentValue;       // value we injected
    QString where;           // "body" | "header:Location" | ...
    bool    reflected = false;
    bool    cacheable = false;       // response carried cache-hit / public-cache signals
    bool    cacheConfirmed = false;  // a clean re-request served the sentinel from cache
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded), may be empty
    QList<QPair<QString, QString>> headers;     // carried headers (cookies, auth)
};

struct Result {
    QList<Hit> hits;          // headers that reflected (any confidence)
    bool    anyConfirmed = false;
    bool    anyCacheable = false;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Probe a focused set of unkeyed headers; for each that reflects a random
// sentinel, attempt to prove the poisoning survives in the cache. Refuses to
// inject (Result::error set) unless it positively confirms the cache-buster
// param is part of the cache key, so a live run can't poison the key real
// users are served.
Result test(const Request &req);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// detection + safety logic against Qt6::Core alone. All operate on already-
// parsed primitives (a header list / body) rather than a live response.
using Headers = QList<QPair<QString, QString>>;

// 12-char sentinel: literal "np" prefix + 10 random hex (~40 bits of entropy).
QString randTok();

// First header value matching `name` (case-insensitive), or empty.
QString headerValue(const Headers &headers, const QString &name);

// ALL values of a (possibly duplicated) header, joined with ", " -- so parsing
// Cache-Control / Vary sees no-store and every Vary token even when a server
// splits them across multiple header lines. Empty if the header is absent.
QString headerValueAll(const Headers &headers, const QString &name);

// Where, if anywhere, a SHARED cache would serve `tok` back to other users:
// the body, or one of the few headers a compliant cache stores and replays
// (Location / Content-Location / Link). Per-response / hop-by-hop headers
// (notably Set-Cookie) are excluded -- a token landing only there is a cookie-
// scoping / header-injection issue, not cross-user cache poisoning. Empty if
// not reflected in a poisonable position.
QString reflectionSite(const QByteArray &body, const Headers &headers, const QString &tok);

// A response that demonstrably came from / lives in a shared cache: it carries
// an Age, or a "hit" verdict from a recognized cache front-end.
bool cacheHitSignal(const Headers &headers);

// Parse a Cache-Control directive's seconds value; -1 if the directive is
// absent. Tells a shareable fresh lifetime (>0) from max-age=0 (revalidate).
// qlonglong so a huge (>INT_MAX) max-age isn't truncated to 0 and mis-read as
// non-cacheable; a value beyond qlonglong saturates to LLONG_MAX (still huge).
qlonglong ccSeconds(const QString &cc, const QString &directive);

// Would a shared cache store and re-serve this response to OTHER users?
// `injectedHeader` is the unkeyed header we set: if the response Varys on it
// (or "*"), the cache keys a separate entry per value, so it is NOT cross-user
// poisonable and we report it as not-cacheable.
bool looksCacheable(const Headers &headers, const QString &injectedHeader = QString());

// Build the raw HTTP request bytes. Returns empty if method/host/basePath or a
// carried/extra header carries a CR/LF (request-line / header injection guard).
QByteArray buildRequest(const Request &req, const QString &query,
                        const QString &extraHeader, const QString &extraValue);

// Replace/add the `ncb` cache-buster on an existing (encoded) query string.
QString withBuster(const QString &query, const QString &cb);

// The fail-closed safety decision. Given the outcomes of the same-buster
// repeat (b) and the different-buster probe (c), decide whether the cache has
// been PROVEN to key on the buster (so injecting lands on a throwaway key).
enum class Gate {
    Inject,             // b hit on the buster AND a different buster missed -> keyed
    AbortNoHitSignal,   // b showed no cache-hit signal -> keying unprovable
    AbortConfirmFailed, // the different-buster confirmation request failed
    AbortUnkeyed,       // a different buster also hit -> cache ignores the buster
};
Gate gateDecision(bool bOk, bool bHit, bool cOk, bool cHit);

} // namespace Nullock::Core::CachePoison

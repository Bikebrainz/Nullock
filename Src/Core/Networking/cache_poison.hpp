#pragma once

// Web cache poisoning (CWE-349: Acceptance of Extraneous Untrusted Data
// With Trusted Data). A cache keys entries on a subset of the request --
// typically method + path + a few headers -- and serves the stored response
// to everyone who matches that key. If an *unkeyed* input (X-Forwarded-Host,
// X-Forwarded-Scheme, X-Original-URL, ...) is reflected into the response,
// an attacker poisons the cache once and every subsequent user is served the
// attacker's content: a hijacked script src, a redirect, an XSS payload.
//
// We confirm the way PortSwigger's Param Miner does. Each probe carries a
// unique cache-buster query value to isolate the test to a throwaway key --
// but only if the cache actually keys on that param, so we VERIFY that first
// (two same-buster requests for a miss->hit, then a different buster: still a
// hit means the cache ignores it) and ABORT without injecting if it doesn't,
// rather than risk poisoning a real user's response. Detection is two-step --
// inject an unkeyed header with a random sentinel, then re-request the same
// key with NO header; if the sentinel is still served *from cache* (a hit
// signal), the poisoning is proven end to end. No free-tool equivalent.

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
// inject (Result::error set) if the cache-buster param isn't part of the
// cache key, so a live run can't poison the key real users are served.
Result test(const Request &req);

} // namespace Nullock::Core::CachePoison

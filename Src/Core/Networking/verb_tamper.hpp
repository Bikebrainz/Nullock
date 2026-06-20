#pragma once

// HTTP verb-tampering / method-based access-control bypass (CWE-650:
// Trusting HTTP Permission Methods on the Server Side). A very common
// real bug: an access rule is enforced on GET/POST but the framework
// still routes -- and serves -- HEAD, an alternate verb, a lower-cased
// method, or an X-HTTP-Method-Override'd request. We take a request that
// is currently DENIED (401/403/404/405) and retry it a dozen ways, flagging
// any that flip to a 2xx -- a confirmed authorization bypass. Burp has
// no native check for this.
//
// Signal-quality guards: an XYZZY bogus-method control suppresses catch-all
// backends that 200 everything; body-carrying variants must differ from the
// denial page; HEAD (which has no body to compare) is only a bypass when its
// Content-Length differs from the denial's (a generic framework HEAD that just
// re-serves the denied response is not access); and a method-override finding
// is suppressed when the override response is identical to the plain carrier
// (the header changed nothing -- the carrier method was simply allowed).

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::VerbTamper {

struct Bypass {
    QString technique;   // "method:HEAD", "override:X-HTTP-Method-Override", "method-case:get"
    QString detail;
    int     status = 0;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
};

struct Result {
    int     baselineStatus = 0;
    bool    baselineDenied = false;   // baseline was 401/403/404/405
    QList<Bypass> bypasses;           // variants that flipped to 2xx
    int     requestsSent = 0;
    QString error;
};

// Probe the request with alternate methods, case-varied methods, and
// method-override headers. Only meaningful when the baseline is denied;
// otherwise there's no access control to bypass (baselineDenied=false,
// no bypasses).
Result test(const Request &req);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// build / classification logic against Qt6::Core alone.

bool isDenied(int status);     // 401/403/404/405
bool isAllowed(int status);    // 2xx

// Build the raw request. Returns empty if method/host/path or a carried/extra
// header carries a CR/LF (request-line / header injection guard).
QByteArray buildRequest(const Request &req, const QString &method,
                        const QList<QPair<QString, QString>> &extraHeaders);

// Case-varied forms of `method` worth trying (lowercase, capitalized), each
// distinct from the original -- the canonical front-end-denylist bypass.
QStringList caseVariants(const QString &method);

// True when a method-override response is identical to the plain carrier
// response (same status + body) -- the override header changed nothing, so the
// carrier method was simply allowed and no override finding should be emitted.
bool overrideAddedNothing(int overrideStatus, const QByteArray &overrideBody,
                          int carrierStatus, const QByteArray &carrierBody);

// HEAD has no body to compare, so it is a bypass only when it returns 2xx with
// a Content-Length that differs from the denial's (real content, not a generic
// framework HEAD re-serving the denied response). -1 = Content-Length absent.
bool headIsBypass(int status, int headContentLength, int denialContentLength);

} // namespace Nullock::Core::VerbTamper

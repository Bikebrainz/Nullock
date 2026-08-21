#pragma once

// Host-header injection (CWE-20: the app trusts an attacker-controlled Host /
// forwarded-host header when building absolute URLs or routing). The classic
// impact is password-reset poisoning -> account takeover: the reset email's
// link is built from the request Host, so an attacker who sets it to their own
// domain receives the victim's reset token. The same trust also enables
// redirect poisoning and routing-based SSRF.
//
// We confirm it benignly and with low false-positive risk: each probe carries a
// UNIQUE random sentinel hostname (e.g. nullock-hhi-ab12cd34.test) injected via
// one host-class header, then we look for that sentinel coming back in a URL
// context -- the Location header, or an absolute/protocol-relative URL in the
// body (//sentinel). Because the sentinel is random it can't occur naturally,
// so a URL-context reflection is a real signal that our header reached
// URL-generation. A bare body reflection (not in a URL) is reported separately
// at low confidence.
//
// This is distinct from web cache poisoning (cache_poison): there the question
// is "does an unkeyed header survive in a shared cache"; here it is "does the
// app build security-relevant URLs from the Host", which is a vuln even with no
// cache in front.
//
// Confidence tiers (the caller grades on these): a hit from the LITERAL Host
// line reaching a Location is the unambiguous reset/redirect vector (the
// victim's own browser sends Host) -> high. A forwarding-header (X-Forwarded-
// Host, ...) reaching a URL, or any body-url reflection, is "needs confirmation"
// (a fronting proxy may simply echo the forwarding header, and an attacker can't
// make a victim send it) -> medium. A bare reflection -> info.
//
// SCOPE: this is reflection-based -- it only fires when the sentinel comes back
// in THIS response. The headline impact, password-reset poisoning, is usually
// BLIND (the poisoned link is emailed, never reflected): a clean result does
// NOT rule it out. Pair with an OAST callback host for the blind case.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::HostHeader {

struct Hit {
    QString header;       // the header we injected (X-Forwarded-Host, Host, ...)
    QString sentinel;     // the random host we sent
    QString where;        // "Location" | "body-url" | "header:<name>" | "body"
    bool    fromHostLine = false;  // injected via the literal Host line (high) vs
                                   // a forwarding header (medium, not victim-sent)
    bool    inLocation = false;
    bool    inUrlContext = false;  // appeared as //sentinel (absolute/proto-rel URL)
    bool    reflected = false;     // appeared anywhere in the body
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;                           // defaults to "/"
    QString query;                              // optional encoded query
    QList<QPair<QString, QString>> headers;     // carried headers (cookies, auth)
};

struct Result {
    QList<Hit> hits;            // every header that reflected (any confidence)
    bool    anyInjection = false;  // any Location/url-context hit -- the real vuln
    bool    anyReflected = false;  // any bare body reflection
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Probe a focused set of host-class headers. For each, inject a unique sentinel
// and record where it reflects. Sets Result::error (leaving hits empty) only if
// the initial request fails outright.
Result test(const Request &req);

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// A Location value is itself a URL, so a bare //sentinel there counts.
bool locationIsUrl(const QString &location, const QString &s);
// The body must carry the sentinel as a real URL host: scheme, quoted //, or an
// unquoted attribute-position //, but NOT bare // in prose/comments/JSON.
bool bodyHasUrl(const QString &body, const QString &s);
// Build the raw request, CR/LF-guarding method/path/query/hostLine (returns {}
// if any is tainted) and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &hostLine,
                        const QString &extraHeader, const QString &extraValue);

// The per-probe reflection verdict: whether the sentinel came back (report), the
// Hit describing where + how, and the injection/reflected classification. Pure --
// the decision the network test() applies to each probe response, extracted so it
// can be unit-tested. `respHeaders` is the response's header list (a sentinel
// echoed ONLY into a header value, e.g. Set-Cookie Domain=, is a reflection a
// Location/body check would miss).
struct HostVerdict {
    bool report = false;        // false = sentinel didn't come back -> skip
    Hit  hit;
    bool anyInjection = false;  // a Location / url-context hit -> the real vuln
    bool anyReflected = false;  // a bare body/header reflection
};
HostVerdict classifyHostReflection(const QString &sentinel, const QString &header,
                                   bool fromHostLine, const QString &location,
                                   const QString &body,
                                   const QList<QPair<QString, QString>> &respHeaders);

} // namespace Nullock::Core::HostHeader

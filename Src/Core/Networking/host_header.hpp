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

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::HostHeader {

struct Hit {
    QString header;       // the header we injected (X-Forwarded-Host, Host, ...)
    QString sentinel;     // the random host we sent
    QString where;        // "Location" | "body-url" | "body"
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

} // namespace Nullock::Core::HostHeader

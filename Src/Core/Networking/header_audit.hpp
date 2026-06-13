#pragma once

// Response security-header audit, with a CSP analyzer that knows about bypass
// gadgets. Most tools tick a box for "has a CSP"; the interesting question is
// whether the CSP actually stops script execution. We flag the policies that
// don't: 'unsafe-inline' that isn't neutralized by a nonce/hash + strict-
// dynamic, 'unsafe-eval', wildcard / scheme sources, a missing object-src or
// base-uri, and -- the part real tools miss -- allow-listed hosts that serve
// JSONP or framework gadgets (Google's APIs, common CDNs) an attacker can use
// to run script under an otherwise-tight policy. Plus the usual HSTS / nosniff
// / clickjacking / Referrer-Policy / cookie-flag checks, scored in context.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::HeaderAudit {

struct Finding {
    QString key;        // enricher kind, e.g. "csp-unsafe-inline"
    QString severity;   // low | medium | high
    QString title;
    QString detail;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QString query;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    int        status = 0;
    bool       hasCsp = false;
    bool       reportOnlyOnly = false;
    QList<Finding> findings;
    int        requestsSent = 0;
    QString    error;
};

// Fetch the URL once and audit its response headers. TLS-only checks (HSTS,
// Secure cookies) are scored against whether the request itself was https.
Result test(const Request &req);

} // namespace Nullock::Core::HeaderAudit

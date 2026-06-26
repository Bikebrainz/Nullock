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
#include <QMap>
#include <QPair>
#include <QString>
#include <QStringList>

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

// --- Pure helpers, exposed for the unit test (no network I/O; in header_logic.cpp) ---
//   analyze      -- audit a fetched response's headers (CSP/HSTS/XFO/cookies).
//   auditCsp     -- the CSP sub-analysis (appends findings to a Result).
//   parseCsp     -- a CSP string -> directive -> token-list (first-occurrence).
//   hostOf       -- strip scheme/path/port from a CSP source to its host token.
//   hostMatches  -- does a CSP source host cover a gadget host (wildcards)?
//   buildRequest -- render the GET, stripping CR/LF from host/path/query.
void analyze(const QList<QPair<QString, QString>> &headers, bool effTls, Result &result);
void auditCsp(const QString &csp, bool reportOnly, Result &result);
QMap<QString, QStringList> parseCsp(const QString &csp);
QString hostOf(QString source);
bool hostMatches(const QString &cspHost, const QString &gadget);
QByteArray buildRequest(const Request &req);

} // namespace Nullock::Core::HeaderAudit

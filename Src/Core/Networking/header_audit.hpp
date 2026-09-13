#pragma once

// Response security-header audit. CSP checks distinguish script elements,
// inline handlers and eval, accounting for nonce/hash syntax and strict-dynamic.
// Findings cover permissive sources, missing object-src/base-uri restrictions
// and potential gadget hosts, alongside HSTS, nosniff, framing, referrer and
// cookie protections. Gadget-host findings require target-specific verification.

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QUrl>

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
//   isSameOriginRedirect -- may the redirect follower continue to `next`?
//     True ONLY when `next` is the SAME ORIGIN as (curTls, curHost, curPort):
//     an http(s) URL with the same scheme, host (case-insensitive), and
//     effective port. A scheme downgrade (https->http), host change, or port
//     change is a DIFFERENT origin -- following it would re-emit the captured
//     Cookie/Authorization to that origin (over cleartext on a downgrade) and
//     bind its verdicts to the original URL, so the chain must stop instead.
bool isSameOriginRedirect(bool curTls, const QString &curHost, int curPort,
                          const QUrl &next);

} // namespace Nullock::Core::HeaderAudit

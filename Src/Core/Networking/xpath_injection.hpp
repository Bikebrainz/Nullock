#pragma once

// XPath injection (CWE-643), error-based detection. When user input is
// concatenated into an XPath expression (often an XML-backed login or lookup),
// a stray quote or bracket breaks the expression and the backend leaks a
// distinctive error (javax.xml.xpath.XPathExpressionException, XPathEvalError,
// "Invalid predicate", DOMXPath, ...). We inject expression-breaking probes and
// flag only when an XPath error fingerprint appears that the baseline did NOT
// have -- and corroborate by checking that a benign (metacharacter-free) value
// does NOT trigger the same error, ruling out a page that always shows it. A
// GENERIC-family fingerprint (low-distinctiveness prose like "Error ... XPath")
// on a block-ish status (403/406/429/...) is rejected as a WAF/edge block rather
// than a backend break. The matched signature fingerprints the XPath engine.
//
// Scope: query-string params only (POST/form-body XML login forms -- a common
// XPathi surface -- are a follow-up). Blind/boolean XPath injection (inferring
// data from true/false predicate differentials) is out of scope for this
// error-based check.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::XpathInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString engine;      // "Java", ".NET", "PHP", "Python", "libxml2"
    QString payload;     // the expression-breaking probe that triggered it
    QString evidence;    // the matched error fragment
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;
    QString param;                              // param to test; empty => auto
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    QStringList testedParams;
    QStringList droppedParams;                  // candidates skipped past the cap
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject expression-breaking probes into the target parameter(s) and flag any
// that surface an XPath error absent from the baseline (and absent under a
// benign value). If `param` is empty, existing query params are tried (capped,
// overflow in droppedParams), else a default set of auth/lookup-shaped names.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// Match an XPath error signature in the body: {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body);
// A status that means an edge/WAF block rather than a backend error (a
// generic-family match on one of these is not credited).
bool isBlockStatus(int status);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::XpathInjection

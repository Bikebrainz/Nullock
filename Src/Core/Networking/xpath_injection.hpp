#pragma once

// XPath injection (CWE-643), error-based detection. When user input is
// concatenated into an XPath expression (often an XML-backed login or lookup),
// a stray quote or bracket breaks the expression and the backend leaks a
// distinctive error (javax.xml.xpath.XPathExpressionException, XPathEvalError,
// "Invalid predicate", DOMXPath, ...). We inject expression-breaking probes and
// flag only when an XPath error fingerprint appears that the baseline did NOT
// have -- and corroborate by checking that a benign (metacharacter-free) value
// does NOT trigger the same error, ruling out a page that always shows it. The
// matched signature fingerprints the XPath engine.
//
// (Blind/boolean XPath injection -- inferring data from true/false predicate
// differentials -- is out of scope for this error-based check.)

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
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject expression-breaking probes into the target parameter(s) and flag any
// that surface an XPath error absent from the baseline (and absent under a
// benign value). If `param` is empty, existing query params are tried (capped),
// else a small default set of auth/lookup-shaped names.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::XpathInjection

#pragma once

// Server-Side Template Injection (CWE-1336: Improper Neutralization of
// Special Elements Used in a Template Engine). When user input reaches a
// server-side template -- Jinja2, Twig, Freemarker, ERB, Smarty, Razor,
// ... -- an attacker controls template syntax, which is very frequently a
// straight line to RCE. We confirm injection the unambiguous way: inject
// an arithmetic expression wrapped in each engine's delimiter family and
// check whether the server returned the *product* (evaluated) while NOT
// echoing the literal expression (which would just be reflection). The
// operands are randomized per run so a confirmed hit can't be a cached or
// coincidental value. The delimiter that fired fingerprints the engine.
// Burp Community has no SSTI check at all; this rivals tplmap / Burp Pro.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::Ssti {

struct Hit {
    QString polyglot;   // delimiter family that evaluated, e.g. "{{ }}"
    QString engines;    // candidate engines for that family, comma-joined
    QString evidence;   // "evaluated 1337*73 to 97601"
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;                          // path only, e.g. "/greet"
    QString query;                             // raw query string (encoded), may be empty
    QByteArray body;
    QString contentType;                       // for body injection
    QList<QPair<QString, QString>> headers;
    QString paramName;                         // parameter to inject into
    QString paramIn = QStringLiteral("query"); // "query" | "form" | "json"
    quint32 seedA = 0;                         // operands; 0 => tester randomizes
    quint32 seedB = 0;
};

struct Result {
    bool    injected     = false;  // a usable injection point was exercised
    bool    confirmed    = false;  // arithmetic evaluated -> SSTI proven
    bool    engineLikely = false;  // a syntax break caused a 5xx the baseline didn't
    QString engines;               // best-guess engine list (from the first hit)
    QList<Hit> hits;
    int     requestsSent  = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject a TWO-expression polyglot per delimiter family into the named
// parameter and flag any the server evaluates. Confirmation requires both
// delimited expressions to evaluate with a literal separator preserved between
// them ("<productA><sep><productB>") -- which a template engine does but a
// single-expression calculator cannot -- so pure reflection, coincidental
// matches, and plain arithmetic/eval APIs are all suppressed.
Result test(const Request &req);

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// Remove every locale digit-grouping separator (, . ' space NBSP NNBSP).
QString stripGroupingDigits(const QString &s);
// All sentinel-bracketed regions (pre...suf, <= 64 chars) in the body.
QStringList renderedRegions(const QString &body, const QString &pre, const QString &suf);
// True iff some region shows both products bracketing the literal separator and
// echoes neither raw expression.
bool confirmsArithmetic(const QStringList &regions,
                        const QString &productA, const QString &sep,
                        const QString &productB,
                        const QString &exprA, const QString &exprB);
// The secondary "engine likely" decision (a syntax-break 5xx corroborated by a
// minimal-pair control). Fail-closed: a control that could not complete
// (ctrlOk=false) yields false, not "likely".
bool engineLikelyFrom(int baselineStatus, bool delimOk, int delimStatus,
                      bool ctrlOk, int ctrlStatus);
// Build the raw request, CR/LF-guarding method/host/path/Content-Type (returns
// {} if any is tainted) and dropping any CR/LF-bearing header.
QByteArray buildRequest(const Request &req, const QString &path,
                        const QString &query, const QByteArray &body);

} // namespace Nullock::Core::Ssti

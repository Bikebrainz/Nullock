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

// Inject an arithmetic-bearing polyglot per delimiter family into the named
// parameter and flag any that the server evaluates. Only a value the server
// computed -- present in the response, with the literal expression absent --
// counts; pure reflection and coincidental matches are suppressed.
Result test(const Request &req);

} // namespace Nullock::Core::Ssti

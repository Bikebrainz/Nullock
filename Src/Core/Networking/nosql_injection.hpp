#pragma once

// NoSQL injection (CWE-943: Improper Neutralization of Special Elements in a
// Data Query). Frameworks that parse nested query params (Express/qs, PHP) turn
// `user[$ne]=x` into the object {user: {$ne: "x"}}, and a Mongo-style backend
// treats $ne/$gt/$regex as OPERATORS -- so `password[$ne]=` matches any
// password (auth bypass), and `[$ne]` on a lookup returns every record. We
// confirm it by a three-way differential: a bogus LITERAL value (matches
// nothing), an always-true operator ($ne, should match much more), and an
// always-false operator ($eq, should match like the literal). When the $ne
// response diverges from the literal while $eq tracks it, the operator was
// interpreted -- real NoSQL injection, not a coincidental content change.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::NoSqlInjection {

struct Hit {
    QString param;       // parameter the operator was injected on
    QString detail;      // observed differential summary
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

// Probe each candidate parameter with literal / $ne / $eq variants and flag any
// where the operator was interpreted. If `param` is empty, existing query
// params are tried (capped), else a small default set.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::NoSqlInjection

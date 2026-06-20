#pragma once

// NoSQL injection (CWE-943: Improper Neutralization of Special Elements in a
// Data Query). Frameworks that parse nested query params (Express/qs, PHP) turn
// `user[$ne]=x` into the object {user: {$ne: "x"}}, and a Mongo-style backend
// treats $ne/$gt/$regex as OPERATORS -- so `password[$ne]=` matches any
// password (auth bypass), and `[$ne]` on a lookup returns every record. We
// confirm it with a 2x2 differential: TWO always-true operators ($ne and $gt)
// and an always-false one ($eq), against a bogus LITERAL. A real injection makes
// the two always-true operators behave the SAME (both over-match) while $eq
// tracks the literal (both match nothing) -- requiring the second always-true
// operator defeats a validator/router/redirect that merely keys on the "$ne"
// NAME (which would not affect $gt identically) and a 200-with-different-body
// auth bypass that a length-only test would miss.
//
// Scope: query-string params only. JSON-body NoSQLi -- the primary auth-bypass
// vector ({"pass":{"$ne":null}}) -- is a follow-up. $gt uses a low-sorting
// string ("!"), always-true for STRING fields, so a purely numeric field may
// not over-match.

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
    QStringList droppedParams;                  // candidates skipped past the cap
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Probe each candidate parameter with literal / $ne / $gt / $eq variants and
// flag any where the operators were interpreted. If `param` is empty, existing
// query params are tried (capped, overflow in droppedParams), else a default set.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
bool lenDiffers(int a, int b);
bool lenSimilar(int a, int b);
// The 2x2 differential: confirm only when the two always-true ops agree and
// over-match while $eq tracks the literal (see the header comment).
bool confirmsInjection(int litLen, int litStatus, int eqLen, int eqStatus,
                       int neLen, int neStatus, int gtLen, int gtStatus);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::NoSqlInjection

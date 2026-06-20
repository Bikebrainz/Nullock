#pragma once

// SQL injection (CWE-89). When user input is concatenated into a SQL statement,
// a stray quote breaks the syntax and the backend leaks a database error. The
// error-based phase injects syntax-breaking probes and flags only when a DBMS
// error fingerprint appears that the baseline did NOT have -- corroborated by a
// *balanced* quote payload that does NOT trigger it (ruling out a page that
// always shows it). A GENERIC-family fingerprint (low-distinctiveness prose like
// "SQL syntax error") on a block-ish status (403/406/429/...) is rejected as a
// WAF/edge block. The matched signature fingerprints the database.
//
// An opt-in (Request.timeBased) blind TIME-BASED phase also runs: SLEEP(N) /
// WAITFOR / pg_sleep with a SLEEP(0) control of the same shape and a reproduce
// send (a transport timeout never counts as a delay).
//
// Scope: query-string params only (POST/form-body login forms -- a top SQLi
// surface -- are a follow-up). Boolean-based blind SQLi (1=1 vs 1=2 content
// differential) is not implemented and is out of scope for this check.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::SqlInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString dbms;        // "MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite", "generic"
    QString technique;   // "error-based" | "time-based"
    QString payload;     // the probe that triggered it
    QString evidence;    // the matched error fragment, or the timing summary
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
    bool    timeBased = false;                  // also run blind time-based probes (slow)
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

// Inject syntax-breaking probes into the target parameter(s) and flag any that
// surface a DBMS error absent from the baseline (and absent under a balanced
// quote); optionally also run the blind time-based phase. If `param` is empty,
// existing query params are tried (capped, overflow in droppedParams), else a
// default set.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// Match a DBMS error signature in the body: {dbms, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body);
// A status that means an edge/WAF block rather than a backend error (a
// generic-family match on one of these is not credited).
bool isBlockStatus(int status);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::SqlInjection

#pragma once

// SQL injection (CWE-89), error-based detection. When user input is concatenated
// into a SQL statement, a stray quote breaks the syntax and the backend leaks a
// database error. We inject syntax-breaking probes and flag only when a DBMS
// error fingerprint appears that the baseline response did NOT have -- and we
// corroborate by checking that a *balanced* quote payload does NOT trigger the
// same error, ruling out a page that always shows it. The matched signature
// fingerprints the database. (Boolean/time-based blind SQLi is out of scope for
// this error-based check.)

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::SqlInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString dbms;        // "MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite", "generic"
    QString payload;     // the probe that triggered it
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

// Inject syntax-breaking probes into the target parameter(s) and flag any that
// surface a DBMS error absent from the baseline (and absent under a balanced
// quote). If `param` is empty, existing query params are tried (capped), else a
// small default set.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::SqlInjection

#pragma once

// LDAP injection (CWE-90), error-based detection. When user input is
// concatenated into an LDAP search filter, a stray parenthesis or filter
// metacharacter breaks the filter syntax and the backend leaks a distinctive
// error (javax.naming.directory.InvalidSearchFilterException, ldap_search(),
// "Bad search filter", ldap.FILTER_ERROR, ...). We inject filter-breaking
// probes and flag only when an LDAP error fingerprint appears that the baseline
// did NOT have -- and corroborate by checking that a benign (metacharacter-
// free) value does NOT trigger the same error, ruling out a page that always
// shows it. A GENERIC-family fingerprint on a block-ish status (403/406/429/...)
// is rejected as a WAF/edge block rather than a backend filter break. The
// matched signature fingerprints the LDAP stack.
//
// Scope: query-string params only (POST/form-body login forms -- the dominant
// LDAPi surface -- are a follow-up). Blind/boolean LDAP injection (inferring
// data from wildcard differentials) is out of scope for this error-based check.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::LdapInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString engine;      // "Java/JNDI", ".NET", "PHP", "Python", "generic"
    QString payload;     // the filter-breaking probe that triggered it
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

// Inject filter-breaking probes into the target parameter(s) and flag any that
// surface an LDAP error absent from the baseline (and absent under a benign
// value). If `param` is empty, existing query params are tried (capped, overflow
// in droppedParams), else a default set of auth/search-shaped names.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// Match an LDAP error signature in the body: {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body);
// A status that means an edge/WAF block rather than a backend error (a
// generic-family match on one of these is not credited).
bool isBlockStatus(int status);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::LdapInjection

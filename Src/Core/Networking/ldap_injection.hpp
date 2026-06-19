#pragma once

// LDAP injection (CWE-90), error-based detection. When user input is
// concatenated into an LDAP search filter, a stray parenthesis or filter
// metacharacter breaks the filter syntax and the backend leaks a distinctive
// error (javax.naming.directory.InvalidSearchFilterException, ldap_search(),
// "Bad search filter", ldap.FILTER_ERROR, ...). We inject filter-breaking
// probes and flag only when an LDAP error fingerprint appears that the baseline
// did NOT have -- and corroborate by checking that a benign (metacharacter-
// free) value does NOT trigger the same error, ruling out a page that always
// shows it. The matched signature fingerprints the LDAP stack.
//
// (Blind/boolean LDAP injection -- inferring data from wildcard differentials --
// is out of scope for this error-based check.)

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
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject filter-breaking probes into the target parameter(s) and flag any that
// surface an LDAP error absent from the baseline (and absent under a benign
// value). If `param` is empty, existing query params are tried (capped), else a
// small default set of auth/search-shaped names.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::LdapInjection

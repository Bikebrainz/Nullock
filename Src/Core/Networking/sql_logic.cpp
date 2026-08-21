// Pure, I/O-free helpers for the SQL injection probe: the DBMS error-signature
// matcher, the block-status classifier, and the CR/LF-guarded request builder.
// Kept in their OWN translation unit (separate from sql_injection.cpp's test(),
// which pulls HttpClient and the networking/GUI chain) so the unit test can link
// this logic against Qt6::Core alone. Mirrors the ldap_logic.cpp hardening.

#include "sql_injection.hpp"

#include <QRegularExpression>

namespace Nullock::Core::SqlInjection {

namespace {
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *dbms; QRegularExpression re; };

const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        // DBMS-specific class / driver / error-code fingerprints -- a WAF block
        // page won't carry these, so they are trusted on ANY status.
        { "MySQL",      QRegularExpression("SQL syntax.*MySQL|Warning.*\\bmysqli?_|MySqlException|"
                                           "valid MySQL result|com\\.mysql\\.jdbc|MySQLSyntaxErrorException", ci) },
        { "PostgreSQL", QRegularExpression("PostgreSQL.*ERROR|Warning.*\\bpg_|valid PostgreSQL result|"
                                           "PG::SyntaxError|org\\.postgresql\\.util\\.PSQLException", ci) },
        // Only the class/driver/error-CODE fingerprints stay here (a WAF page
        // won't carry those). The English PROSE "Unclosed quotation mark" /
        // "Incorrect syntax near" IS WAF-carryable -- a quote-selective block
        // page echoes it -- so it moved to the status-gated generic family
        // below, exactly as Oracle's prose was (a real System.Data.SqlClient
        // error still surfaces its distinctive fingerprint here).
        { "MSSQL",      QRegularExpression("Microsoft SQL (Server|Native)|ODBC SQL Server Driver|"
                                           "SqlException|System\\.Data\\.SqlClient", ci) },
        // ORA-##### / oracle.jdbc are true backend fingerprints a WAF page won't
        // carry. The prose "Oracle error" / "quoted string not properly
        // terminated" ARE WAF-carryable, so they live in the status-gated generic
        // family below (an unbalanced ORA-01756 still surfaces its ORA- code).
        { "Oracle",     QRegularExpression("\\bORA-[0-9]{4,5}|oracle\\.jdbc", ci) },
        // Distinctive class/driver/error-code only. "unrecognized token" is
        // WAF-carryable prose -> moved to the status-gated generic family (a real
        // SQLITE_ERROR / sqlite3.OperationalError still fingerprints here).
        { "SQLite",     QRegularExpression("SQLite/JDBCDriver|SQLite\\.Exception|System\\.Data\\.SQLite|"
                                           "SQLITE_ERROR|sqlite3\\.OperationalError", ci) },
        // GENERIC, low-distinctiveness phrasings a WAF/edge block page can also
        // carry ("SQL syntax error detected", "SQLSTATE[..]", and the MSSQL/SQLite
        // prose demoted from above). Gated on status (see isBlockStatus) so a 4xx
        // block page can't confirm.
        { "generic",    QRegularExpression("SQL syntax error|syntax error at or near|Oracle error|"
                                           "unterminated quoted string|quoted string not properly terminated|"
                                           "SQLSTATE\\[|Unclosed quotation mark|Incorrect syntax near|"
                                           "unrecognized token", ci) },
    };
    return s;
}
} // namespace

// Match a DBMS error in `body`; returns {dbms, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.dbms), m.captured(0) };
    }
    return {};
}

// A status that almost always means an edge/WAF block rather than a backend SQL
// error. A GENERIC-family match on one of these is rejected; a DBMS-specific
// fingerprint (which a block page won't carry) is trusted on any status.
bool isBlockStatus(int status) {
    return status == 403 || status == 406 || status == 429
        || status == 451 || status == 501 || status == 503;
}

// Build the raw request, CR/LF-guarding method/host/path (returns {} if any is
// tainted, e.g. an attacker-crafted method from a HAR import reaching the deep
// audit) and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    // The query is spliced into the request line below (basePath + "?" + query), so
    // a CR/LF in it is request-line/header injection just like a tainted path. The
    // baseline send passes req.query verbatim (only probe values are pre-encoded),
    // so guard it too -- a tainted query ABORTS the build (matches the sibling probes).
    if (query.contains('\r')        || query.contains('\n'))        return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/sqli\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::SqlInjection

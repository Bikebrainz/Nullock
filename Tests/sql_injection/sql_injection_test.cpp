// Regression corpus for the SQL injection probe's pure logic (no network):
//   - matchError: DBMS-specific fingerprints (trusted on any status) vs the
//     low-distinctiveness "generic" family (prose a WAF block page can also
//     carry -- the audit's FP), which the confirm loop status-gates.
//   - isBlockStatus: the block-ish statuses a generic-only match is rejected on.
//   - buildRequest: CR/LF guards on method/host/path.
//
// Run via:  ctest -R sql_injection -V

#include "sql_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::SqlInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString dbms(const char *body) { return matchError(QByteArray(body)).first; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- matchError: DBMS-specific (trusted on any status) ---------------
    chk("sig: MySQL", dbms("You have an error in your SQL syntax; ... your MySQL server version") == "MySQL");
    // MariaDB (the default MySQL-compatible DB on most Linux distros) self-names
    // the engine in its error-based-SQLi marker; the old "SQL syntax.*MySQL" anchor
    // missed it entirely -> a real MariaDB SQLi read clean.
    chk("sig: MariaDB error prose trusted as MySQL",
        dbms("You have an error in your SQL syntax; check the manual that corresponds "
             "to your MariaDB server version for the right syntax to use near ''' at line 1") == "MySQL");
    // The MySQL signature had FOUR untested driver/class alternatives -- only the
    // "SQL syntax .. MySQL" prose (above) was exercised. These three fingerprint
    // .NET Connector/NET and Java stack-trace errors; each body deliberately has
    // no "SQL syntax .. MySQL" prose and no generic phrasing, so it can ONLY match
    // via its own alternative. Silently corrupting any of them would stop
    // fingerprinting that whole error class.
    chk("sig: MySQL .NET MySqlException class",
        dbms("MySql.Data.MySqlClient.MySqlException: Fatal error encountered") == "MySQL");
    chk("sig: MySQL JDBC driver package",
        dbms("at com.mysql.jdbc.Driver during statement execution") == "MySQL");
    chk("sig: MySQL JDBC syntax-error class",
        dbms("Caused by: MySQLSyntaxErrorException near line 1") == "MySQL");
    chk("sig: PostgreSQL", dbms("PostgreSQL query failed: ERROR: syntax error") == "PostgreSQL");
    chk("sig: MSSQL", dbms("Microsoft SQL Server ... Unclosed quotation mark") == "MSSQL");
    chk("sig: Oracle", dbms("ORA-00933: SQL command not properly ended") == "Oracle");
    chk("sig: SQLite", dbms("SQLITE_ERROR: unrecognized token") == "SQLite");
    // ---- matchError: GENERIC (status-gated) -- the WAF-block-prone phrasings -
    chk("sig: generic SQL syntax error", dbms("Request blocked: SQL syntax error detected") == "generic");
    chk("sig: generic SQLSTATE", dbms("SQLSTATE[42000]: Syntax error") == "generic");
    // audit-3: WAF-carryable Oracle PROSE is status-gated (generic), not trusted
    // as an ungated DBMS-specific hit -- a 403 block page can't confirm it. A real
    // ORA-##### code (a WAF page won't carry) is still trusted as Oracle.
    chk("sig: 'Oracle error' prose -> generic (was ungated Oracle)",
        dbms("Request blocked: Oracle error detected") == "generic");
    chk("sig: 'quoted string not properly terminated' prose -> generic",
        dbms("DB message: quoted string not properly terminated") == "generic");
    chk("sig: a real ORA-##### code still trusted as Oracle (even with the prose)",
        dbms("ORA-01756: quoted string not properly terminated") == "Oracle");
    // maybefix #5: MSSQL/SQLite English PROSE is WAF-carryable, so it must be
    // status-gated generic (not an ungated DBMS-specific confirm) -- the same
    // class Oracle's prose was demoted out of. The distinctive class/driver
    // fingerprints stay trusted on any status.
    chk("sig: 'Unclosed quotation mark' prose alone -> generic (was ungated MSSQL)",
        dbms("Request blocked: Unclosed quotation mark before ';'") == "generic");
    chk("sig: 'Incorrect syntax near' prose alone -> generic (was ungated MSSQL)",
        dbms("WAF: Incorrect syntax near the keyword 'OR'") == "generic");
    chk("sig: 'unrecognized token' prose alone -> generic (was ungated SQLite)",
        dbms("Blocked: unrecognized token in the submitted value") == "generic");
    chk("sig: distinctive System.Data.SqlClient still trusted as MSSQL",
        dbms("System.Data.SqlClient.SqlException: Login failed") == "MSSQL");
    chk("sig: distinctive sqlite3.OperationalError still trusted as SQLite",
        dbms("sqlite3.OperationalError: near \"WHERE\": syntax error") == "SQLite");
    chk("sig: unrelated -> none", dbms("<html>0 results</html>").isEmpty());

    // ---- isBlockStatus ---------------------------------------------------
    chk("block: 403", isBlockStatus(403));
    chk("block: 429", isBlockStatus(429));
    chk("block: 503", isBlockStatus(503));
    // 406/451/501 were disjuncts in isBlockStatus but never asserted -- dropping
    // any one would let a generic-family match on that block status through as a
    // false SQLi confirmation. Pin all three (and a nearby non-block negative).
    chk("block: 406 (Not Acceptable / WAF)", isBlockStatus(406));
    chk("block: 451 (Unavailable For Legal Reasons / WAF)", isBlockStatus(451));
    chk("block: 501 (Not Implemented / edge)", isBlockStatus(501));
    chk("block: 200 not", !isBlockStatus(200));
    chk("block: 500 not (real backend error)", !isBlockStatus(500));
    chk("block: 404 not", !isBlockStatus(404));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/list";
        const QByteArray ok = buildRequest(req, "q=x");
        chk("build: request line", ok.startsWith("GET /list?q=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "q=x").contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "q=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "q=x").isEmpty());
        Request badPath = req; badPath.basePath = "/list\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "q=x").isEmpty());
        // The query is spliced into the request line; the baseline send passes it
        // verbatim (only probe values are pre-encoded), so a CR/LF in it must abort
        // the build like the path guard -- else it splits the request line / injects.
        chk("build: CRLF query -> empty (request-line injection guard)",
            buildRequest(req, "id=1\r\nX-Injected: evil").isEmpty());
    }

    std::fprintf(stderr, "sql_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

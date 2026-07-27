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
    chk("sig: unrelated -> none", dbms("<html>0 results</html>").isEmpty());

    // ---- isBlockStatus ---------------------------------------------------
    chk("block: 403", isBlockStatus(403));
    chk("block: 429", isBlockStatus(429));
    chk("block: 503", isBlockStatus(503));
    chk("block: 200 not", !isBlockStatus(200));
    chk("block: 500 not (real backend error)", !isBlockStatus(500));

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

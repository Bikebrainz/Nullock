// Regression corpus for HistoryIndex::find()'s query builder.
//
// find() exposes operator-supplied filters (/api/history/find) to a SQLite
// query. The defence against SQL injection is that EVERY filter value is a bound
// ? parameter -- never interpolated into the SQL text. buildFindQuery() isolates
// that construction so we can lock it:
//   * INJECTION INVARIANT: the produced SQL depends ONLY on which filter keys
//     are present, never on their VALUES. A malicious value (quotes, --, ;,
//     UNION, % ...) produces byte-identical SQL to a benign value for the same
//     key set; the hostile text lands only in the bind list.
//   * limit is clamped to [1, kFindLimitMax] (default when absent/<=0) and is
//     itself bound, not interpolated.
//
// Run via:  ctest -R history_logic -V

#include "history_logic.hpp"

#include <QCoreApplication>
#include <QJsonObject>
#include <QString>
#include <QVariant>

#include <cstdio>

using namespace Nullock::Core::HistoryLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Count occurrences of `marker` in `s` (for counting bound ? placeholders).
int count(const QString &s, const QString &marker) {
    int n = 0, from = 0;
    while ((from = s.indexOf(marker, from)) != -1) { ++n; from += marker.size(); }
    return n;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== empty filter: base query, default limit ======================
    {
        const FindQuery q = buildFindQuery(QJsonObject{});
        chk("empty: selects from rows WHERE 1=1", q.sql.contains("FROM rows WHERE 1=1"));
        chk("empty: ordered newest-first", q.sql.contains("ORDER BY id DESC"));
        chk("empty: has LIMIT ?", q.sql.contains("LIMIT ?"));
        chk("empty: exactly one bind (the limit)", q.binds.size() == 1);
        chk("empty: default limit 200", q.binds.size() == 1 && q.binds[0].toInt() == kFindLimitDefault);
        chk("empty: no clause leaked", !q.sql.contains(" AND "));
    }

    // ===== each filter adds its clause + a bound ? ======================
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "method", "post" }});
        chk("method: clause present", q.sql.contains("AND UPPER(method) = ?"));
        chk("method: value uppercased in bind", q.binds.size() == 2 && q.binds[0].toString() == "POST");
    }
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "host", "%example%" }});
        chk("host: LIKE clause", q.sql.contains("AND host LIKE ?"));
        chk("host: wildcard kept verbatim in bind (data, not SQL)",
            q.binds.size() == 2 && q.binds[0].toString() == "%example%");
    }
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "path", "/api%" }});
        chk("path: LIKE clause", q.sql.contains("AND path LIKE ?"));
        chk("path: bound verbatim", q.binds.size() == 2 && q.binds[0].toString() == "/api%");
    }
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "status", 404 }});
        chk("status: exact-match clause", q.sql.contains("AND status = ?"));
        chk("status: bound int", q.binds.size() == 2 && q.binds[0].toInt() == 404);
    }
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "minSize", 1000 }, { "maxSize", 5000 }});
        chk("minSize: clause", q.sql.contains("AND size >= ?"));
        chk("maxSize: clause", q.sql.contains("AND size <= ?"));
        chk("size bounds bound as numbers", q.binds.size() == 3
            && q.binds[0].toLongLong() == 1000 && q.binds[1].toLongLong() == 5000);
    }
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "sinceMs", 1700000000000.0 }});
        chk("sinceMs: ts clause", q.sql.contains("AND ts >= ?"));
        chk("sinceMs: bound as 64-bit (no precision loss at ms-epoch)",
            q.binds.size() == 2 && q.binds[0].toLongLong() == 1700000000000LL);
    }

    // ===== THE INJECTION INVARIANT ======================================
    // For the SAME key set, a benign value and a hostile value MUST produce
    // byte-identical SQL -- proving the value never reaches the SQL text. The
    // hostile string must appear in the bind list instead.
    {
        QJsonObject benign{
            { "method", "GET" }, { "host", "example.com" }, { "path", "/" },
            { "status", 200 }, { "minSize", 1 }, { "maxSize", 2 }, { "sinceMs", 3 }, { "limit", 50 } };
        QJsonObject evil{
            { "method", "GET'; DROP TABLE rows;--" },
            { "host", "%' OR '1'='1" },
            { "path", "\" UNION SELECT req_json FROM rows --" },
            { "status", 200 }, { "minSize", 1 }, { "maxSize", 2 }, { "sinceMs", 3 }, { "limit", 50 } };
        const FindQuery qb = buildFindQuery(benign);
        const FindQuery qe = buildFindQuery(evil);
        chk("INJECTION: identical key sets -> byte-identical SQL regardless of values", qb.sql == qe.sql);
        chk("INJECTION: SQL carries NO injected keyword (DROP)", !qe.sql.contains("DROP"));
        chk("INJECTION: SQL carries NO injected keyword (UNION)", !qe.sql.contains("UNION"));
        chk("INJECTION: SQL has no stray single-quote", !qe.sql.contains('\''));
        chk("INJECTION: SQL has no stray double-quote", !qe.sql.contains('"'));
        chk("INJECTION: SQL has no comment marker", !qe.sql.contains("--"));
        chk("INJECTION: SQL has no statement separator", !qe.sql.contains(';'));
        // every value is a bound ? -- 7 filters + the limit = 8 placeholders.
        chk("INJECTION: one ? per value (8 placeholders)", count(qe.sql, "?") == 8);
        chk("INJECTION: 8 binds match the 8 placeholders", qe.binds.size() == 8);
        // the hostile method survived (uppercased) into the BIND, not the SQL.
        chk("INJECTION: hostile method lives in the bind list, uppercased",
            qe.binds[0].toString() == QString("GET'; DROP TABLE rows;--").toUpper());
        chk("INJECTION: hostile host lives in the bind list verbatim",
            qe.binds[1].toString() == "%' OR '1'='1");
    }

    // ===== limit clamping ===============================================
    chk("limit: in-range preserved", buildFindQuery(QJsonObject{{ "limit", 37 }}).binds.last().toInt() == 37);
    chk("limit: zero -> default", buildFindQuery(QJsonObject{{ "limit", 0 }}).binds.last().toInt() == kFindLimitDefault);
    chk("limit: negative -> default", buildFindQuery(QJsonObject{{ "limit", -9 }}).binds.last().toInt() == kFindLimitDefault);
    chk("limit: over max -> clamped to max", buildFindQuery(QJsonObject{{ "limit", 999999 }}).binds.last().toInt() == kFindLimitMax);
    chk("limit: exactly max preserved", buildFindQuery(QJsonObject{{ "limit", kFindLimitMax }}).binds.last().toInt() == kFindLimitMax);
    chk("limit: non-numeric (string) -> default", buildFindQuery(QJsonObject{{ "limit", "9999; DROP" }}).binds.last().toInt() == kFindLimitDefault);
    chk("limit: a huge string is NOT interpolated", !buildFindQuery(QJsonObject{{ "limit", "9999; DROP" }}).sql.contains("DROP"));
    chk("limit: sane bounds constant", kFindLimitDefault > 0 && kFindLimitMax >= kFindLimitDefault);

    // ===== clause ordering & all-together ===============================
    {
        QJsonObject all{
            { "method", "GET" }, { "host", "h" }, { "path", "/p" }, { "status", 200 },
            { "minSize", 1 }, { "maxSize", 2 }, { "sinceMs", 3 }, { "limit", 10 } };
        const FindQuery q = buildFindQuery(all);
        chk("all: 8 binds total", q.binds.size() == 8);
        chk("all: WHERE precedes ORDER precedes LIMIT",
            q.sql.indexOf("WHERE") < q.sql.indexOf("ORDER BY")
            && q.sql.indexOf("ORDER BY") < q.sql.indexOf("LIMIT"));
        // all clauses come before ORDER BY (no clause after the order/limit tail)
        chk("all: every AND-clause is in the WHERE section",
            q.sql.lastIndexOf(" AND ") < q.sql.indexOf("ORDER BY"));
    }

    std::fprintf(stderr, "history_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

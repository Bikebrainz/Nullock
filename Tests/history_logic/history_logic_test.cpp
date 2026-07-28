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

    // ===== audit-13: unreadable numeric filters are DROPPED, not guessed ====
    // QJsonValue::toInt()/toDouble() return 0 for a non-numeric value, so the
    // old code silently answered a DIFFERENT query than the operator asked for.
    {
        QStringList ignored;
        const FindQuery q = buildFindQuery(QJsonObject{{ "status", "200" }}, &ignored);
        // "200" is a STRING. Binding 0 would have matched only transport-failure
        // rows -- confidently wrong, and impossible to notice from the results.
        chk("status string: no status clause emitted", !q.sql.contains("AND status = ?"));
        chk("status string: only the limit is bound", q.binds.size() == 1);
        chk("status string: reported as ignored", ignored == QStringList{ "status" });
    }
    {
        QStringList ignored;
        const FindQuery q = buildFindQuery(QJsonObject{{ "sinceMs", "yesterday" }}, &ignored);
        // Binding 0 made this `ts >= 0` -- the time window silently vanished.
        chk("sinceMs string: no ts clause emitted", !q.sql.contains("AND ts >= ?"));
        chk("sinceMs string: reported as ignored", ignored == QStringList{ "sinceMs" });
    }
    {
        // static_cast<qint64> of an out-of-range double is UNDEFINED BEHAVIOUR;
        // in practice it lands on INT64_MIN, which INVERTS a size bound into
        // "match everything". Rejected before the cast now.
        QStringList ignored;
        const FindQuery q = buildFindQuery(QJsonObject{{ "minSize", 1e300 }}, &ignored);
        chk("minSize 1e300: no size clause emitted", !q.sql.contains("AND size >= ?"));
        chk("minSize 1e300: reported as ignored", ignored == QStringList{ "minSize" });
        QStringList ig2;
        buildFindQuery(QJsonObject{{ "maxSize", -1e300 }}, &ig2);
        chk("maxSize -1e300: reported as ignored", ig2 == QStringList{ "maxSize" });
    }
    {
        // Several at once, and the out-param is optional (the 1-arg call still
        // compiles and behaves identically).
        QStringList ignored;
        const FindQuery q = buildFindQuery(
            QJsonObject{{ "status", true }, { "minSize", QJsonValue() }, { "host", "h" }}, &ignored);
        chk("mixed: both unreadable numerics reported",
            ignored.size() == 2 && ignored.contains("status") && ignored.contains("minSize"));
        chk("mixed: the READABLE host filter still applies", q.sql.contains("AND host LIKE ?"));
        const FindQuery q1 = buildFindQuery(QJsonObject{{ "status", "x" }});
        chk("mixed: the 1-arg call still works", !q1.sql.contains("AND status = ?"));
    }
    {
        // Not over-broad: valid numerics are untouched, including 0 and negatives.
        QStringList ignored;
        const FindQuery q = buildFindQuery(
            QJsonObject{{ "status", 0 }, { "minSize", 0 }, { "sinceMs", 1700000000000.0 }}, &ignored);
        chk("valid: nothing reported as ignored", ignored.isEmpty());
        chk("valid: status 0 IS a legitimate filter", q.sql.contains("AND status = ?"));
        chk("valid: ms-epoch survives as 64-bit",
            q.binds.contains(QVariant(qint64(1700000000000LL))));
    }
    {
        // `limit` is deliberately NOT reported: it is a safety ceiling, not a row
        // filter, and falling back to the default can only return FEWER rows.
        QStringList ignored;
        const FindQuery q = buildFindQuery(QJsonObject{{ "limit", "lots" }}, &ignored);
        chk("limit garbage: NOT reported as ignored (it is a ceiling)", ignored.isEmpty());
        chk("limit garbage: falls back to the default",
            q.binds.size() == 1 && q.binds[0].toInt() == kFindLimitDefault);
    }
    {
        // audit-13: method folding must agree with SQLite's ASCII-only UPPER().
        // QString::toUpper() is full-Unicode, so it folded bytes SQLite would
        // leave alone and the comparison could never match.
        const FindQuery q = buildFindQuery(QJsonObject{{ "method", "get" }});
        chk("method: ASCII still uppercased", q.binds[0].toString() == QStringLiteral("GET"));
        const FindQuery qu = buildFindQuery(QJsonObject{{ "method", QString::fromUtf8("gét") }});
        chk("method: a non-ASCII char is LEFT ALONE, matching SQLite's UPPER()",
            qu.binds[0].toString() == QString::fromUtf8("GéT"));
    }
    // SKIPPED, not fixed: host/path LIKE emits no ESCAPE clause, so '_' is a
    // single-character wildcard in a value the operator may have meant literally.
    // The header DOCUMENTS '%' as an intentional wildcard search, and the API has
    // no way to say "this value is literal", so adding ESCAPE would fix a minor
    // over-match by BREAKING the documented feature. These pin the deliberate
    // behaviour so it is not "fixed" by a later audit without that trade-off.
    {
        const FindQuery q = buildFindQuery(QJsonObject{{ "host", "%example%" }});
        chk("LIKE: '%' reaches the bind verbatim (documented wildcard search)",
            q.binds[0].toString() == QStringLiteral("%example%"));
        chk("LIKE: no ESCAPE clause is emitted (would disable the wildcard)",
            !q.sql.contains("ESCAPE"));
        const FindQuery u = buildFindQuery(QJsonObject{{ "host", "build_server" }});
        chk("LIKE: '_' also reaches the bind verbatim (same deliberate semantics)",
            u.binds[0].toString() == QStringLiteral("build_server"));
    }

    std::fprintf(stderr, "history_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

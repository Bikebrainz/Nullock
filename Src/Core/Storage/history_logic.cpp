#include "history_logic.hpp"

#include <cmath>
#include <limits>

namespace Nullock::Core::HistoryLogic {

namespace {

// SQLite's UPPER() folds ASCII ONLY, but QString::toUpper() is full-Unicode.
// Uppercasing the bind with Qt while the column goes through SQLite's UPPER()
// meant the two sides disagreed on any non-ASCII byte: a captured method
// containing one would be folded here, left alone there, and could never match.
// HTTP methods are ASCII tokens (RFC 9110), so anything else is a malformed
// request artefact -- exactly the sort of row an operator is trying to FIND.
// Fold ASCII only, so both sides agree exactly.
QString asciiUpper(const QString &s) {
    QString out = s;
    for (QChar &c : out) {
        const ushort u = c.unicode();
        if (u >= 'a' && u <= 'z') c = QChar(static_cast<ushort>(u - 32));
    }
    return out;
}

// Read a numeric filter, refusing anything that is not a FINITE number inside
// qint64 range. QJsonValue::toDouble() returns 0.0 for a string/bool/null, and
// static_cast<qint64> of an out-of-range double is undefined behaviour, so both
// had to be rejected before the value reached a bind.
bool readInt64(const QJsonObject &f, const QString &key, qint64 &out) {
    const QJsonValue v = f.value(key);
    if (!v.isDouble()) return false;                 // string/bool/null/array/object
    const double d = v.toDouble();
    if (!std::isfinite(d)) return false;             // NaN / +-inf
    // Compare in double space; the qint64 bounds are exactly representable.
    if (d < -9223372036854775808.0 || d >= 9223372036854775808.0) return false;
    out = static_cast<qint64>(d);
    return true;
}

} // namespace

FindQuery buildFindQuery(const QJsonObject &filters, QStringList *ignoredFilters) {
    FindQuery out;
    if (ignoredFilters) ignoredFilters->clear();
    // Fixed skeleton: only literal column names + operators + ? markers. No
    // operator-supplied text is ever appended here -- see the header invariant.
    QString sql = "SELECT id, ts, method, host, port, path, status, size, tls, mime "
                  "FROM rows WHERE 1=1";

    // A numeric filter we cannot read contributes NO clause and is reported.
    // Guessing (the old toInt()/toDouble() zero) silently answered a DIFFERENT
    // query: `status = 0` matched only transport failures, `ts >= 0` matched
    // everything, and an out-of-range double was undefined behaviour.
    auto addNumeric = [&](const QString &key, const char *clause, bool asInt) {
        if (!filters.contains(key)) return;
        qint64 n = 0;
        if (!readInt64(filters, key, n)) {
            if (ignoredFilters) ignoredFilters->append(key);
            return;
        }
        sql += QString::fromLatin1(clause);
        if (asInt) out.binds << static_cast<int>(n);
        else       out.binds << n;
    };

    if (filters.contains("method")) {
        sql += " AND UPPER(method) = ?";
        out.binds << asciiUpper(filters.value("method").toString());
    }
    if (filters.contains("host")) {
        // LIKE, deliberately: the operator may pass % wildcards OR a literal
        // hostname (see the header). Still a bound parameter -- the % is data,
        // never SQL. NOTE: because this is a documented wildcard search, '_' is
        // a single-character wildcard too, so a LITERAL host containing '_'
        // matches slightly more rows than typed. Adding ESCAPE would fix that by
        // BREAKING the documented '%' feature, and the API has no way to say
        // "this value is literal" -- so it stays. See the lock in the test.
        sql += " AND host LIKE ?";
        out.binds << filters.value("host").toString();
    }
    if (filters.contains("path")) {
        sql += " AND path LIKE ?";
        out.binds << filters.value("path").toString();
    }
    addNumeric(QStringLiteral("status"),  " AND status = ?",  /*asInt=*/true);
    addNumeric(QStringLiteral("minSize"), " AND size >= ?",   /*asInt=*/false);
    addNumeric(QStringLiteral("maxSize"), " AND size <= ?",   /*asInt=*/false);
    addNumeric(QStringLiteral("sinceMs"), " AND ts >= ?",     /*asInt=*/false);
    sql += " ORDER BY id DESC";

    // `limit` is NOT reported as ignored: it is not a row filter but a safety
    // ceiling, and falling back to the default is the correct, safe reading of a
    // value we cannot parse -- it can only ever return FEWER rows.
    int limit = filters.value("limit").toInt(kFindLimitDefault);
    if (limit <= 0)            limit = kFindLimitDefault;
    if (limit > kFindLimitMax) limit = kFindLimitMax;
    sql += " LIMIT ?";
    out.binds << limit;

    out.sql = sql;
    return out;
}

} // namespace Nullock::Core::HistoryLogic

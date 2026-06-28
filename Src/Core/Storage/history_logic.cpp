#include "history_logic.hpp"

namespace Nullock::Core::HistoryLogic {

FindQuery buildFindQuery(const QJsonObject &filters) {
    FindQuery out;
    // Fixed skeleton: only literal column names + operators + ? markers. No
    // operator-supplied text is ever appended here -- see the header invariant.
    QString sql = "SELECT id, ts, method, host, port, path, status, size, tls, mime "
                  "FROM rows WHERE 1=1";

    if (filters.contains("method")) {
        sql += " AND UPPER(method) = ?";
        out.binds << filters.value("method").toString().toUpper();
    }
    if (filters.contains("host")) {
        // LIKE: the operator may pass % wildcards or a literal hostname. Still
        // a bound parameter -- the % is data, not SQL.
        sql += " AND host LIKE ?";
        out.binds << filters.value("host").toString();
    }
    if (filters.contains("path")) {
        sql += " AND path LIKE ?";
        out.binds << filters.value("path").toString();
    }
    if (filters.contains("status")) {
        sql += " AND status = ?";
        out.binds << filters.value("status").toInt();
    }
    if (filters.contains("minSize")) {
        sql += " AND size >= ?";
        out.binds << static_cast<qint64>(filters.value("minSize").toDouble());
    }
    if (filters.contains("maxSize")) {
        sql += " AND size <= ?";
        out.binds << static_cast<qint64>(filters.value("maxSize").toDouble());
    }
    if (filters.contains("sinceMs")) {
        sql += " AND ts >= ?";
        out.binds << static_cast<qint64>(filters.value("sinceMs").toDouble());
    }
    sql += " ORDER BY id DESC";

    int limit = filters.value("limit").toInt(kFindLimitDefault);
    if (limit <= 0)            limit = kFindLimitDefault;
    if (limit > kFindLimitMax) limit = kFindLimitMax;
    sql += " LIMIT ?";
    out.binds << limit;

    out.sql = sql;
    return out;
}

} // namespace Nullock::Core::HistoryLogic

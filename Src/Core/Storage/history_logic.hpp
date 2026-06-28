#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QVariant>

// Pure query-construction logic for HistoryIndex::find(), split out of
// history_index.cpp so a unit test can link it against Qt6::Core alone (the rest
// of history_index.cpp pulls Qt6::Sql / QSqlDatabase / QSqlQuery).
namespace Nullock::Core::HistoryLogic {

inline constexpr int kFindLimitDefault = 200;
inline constexpr int kFindLimitMax     = 5000;

// The parameterized SELECT for /api/history/find: a SQL string with ? markers
// plus the ordered bind values.
struct FindQuery {
    QString          sql;
    QList<QVariant>  binds;
};

// Build the find() query from the operator's filter object. PURE -- no DB.
//
// SECURITY INVARIANT (the reason this is its own testable function): every
// operator-supplied value (method/host/path/status/minSize/maxSize/sinceMs/limit)
// goes into `binds` as a bound ? parameter and is NEVER interpolated into `sql`.
// All column names and operators in `sql` are fixed string literals. As a direct
// consequence, the produced `sql` depends ONLY on WHICH filter keys are present,
// never on their VALUES -- so a malicious value cannot alter the query shape.
// `limit` is clamped to [1, kFindLimitMax] (kFindLimitDefault when absent/<=0)
// and is itself bound, not interpolated.
FindQuery buildFindQuery(const QJsonObject &filters);

} // namespace Nullock::Core::HistoryLogic

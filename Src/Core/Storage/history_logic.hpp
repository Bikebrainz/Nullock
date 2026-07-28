#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>
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
//
// UNREADABLE NUMERIC FILTERS ARE DROPPED, NOT GUESSED AT. QJsonValue::toInt()/
// toDouble() yield 0 for a non-numeric value, so {"status":"200"} used to become
// `status = 0` (matching only transport failures) and {"sinceMs":"yesterday"}
// became `ts >= 0` (matching everything) -- both silently returning the wrong
// rows. Worse, static_cast<qint64> of an out-of-range double is UNDEFINED
// BEHAVIOUR: 1e300 lands on INT64_MIN in practice, inverting a size/time bound.
// A filter whose value is not a finite in-range number now contributes NO clause
// at all, and its key is appended to `ignoredFilters` (when supplied) so the
// caller can tell the operator rather than quietly answering a different query.
FindQuery buildFindQuery(const QJsonObject &filters,
                         QStringList *ignoredFilters = nullptr);

} // namespace Nullock::Core::HistoryLogic

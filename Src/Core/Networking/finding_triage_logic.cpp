// Pure finding-triage logic (see finding_triage_logic.hpp). Qt6::Core only.

#include "finding_triage_logic.hpp"

namespace Nullock::Core::FindingTriageLogic {

QString findingKey(const QString &kind, const QString &host,
                   const QString &url, const QString &summary) {
    const QChar sep(QChar(0x1f));   // Unit Separator -- same as ProjectStore::findingKey
    return kind + sep + host + sep + url + sep + summary;
}

bool kindSuppressed(const QString &kind, const QStringList &suppressedKinds) {
    return !kind.isEmpty() && suppressedKinds.contains(kind);
}

bool keyIsFalsePositive(const QString &key, const QStringList &falsePositiveKeys) {
    return falsePositiveKeys.contains(key);
}

} // namespace Nullock::Core::FindingTriageLogic

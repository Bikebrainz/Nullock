// Pure finding-triage logic (see finding_triage_logic.hpp). Qt6::Core only.

#include "finding_triage_logic.hpp"

#include <QJsonObject>
#include <QJsonValue>

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

QString effectiveSeverity(const QString &key, const QString &original,
                          const QJsonArray &overrides) {
    for (const QJsonValue &v : overrides) {
        const QJsonObject o = v.toObject();
        if (o.value("key").toString() != key) continue;
        const QString sev = o.value("severity").toString();
        return sev.isEmpty() ? original : sev;   // a blank override never masks
    }
    return original;
}

} // namespace Nullock::Core::FindingTriageLogic

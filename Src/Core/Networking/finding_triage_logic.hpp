#pragma once

// Pure triage logic for scanner findings: the identity key an operator's
// "false positive" mark and "suppress this issue kind" decision are keyed on,
// plus the two membership predicates. Qt6::Core only, so it is unit-testable.
//
// Findings persist append-only to findings.ndjson, so a mark made AFTER a finding
// was written can't be rewritten in place. Instead the mark set (a list of
// finding identity keys) and the suppressed-kind set live in the project file and
// are applied at DISPLAY time -- unsuppressing a kind or clearing a mark brings
// findings back with no re-scan. The identity key here MUST match project_store's
// dedup key byte-for-byte or a mark would never line up with its finding.

#include <QString>
#include <QStringList>

namespace Nullock::Core::FindingTriageLogic {

// kind + US + host + US + url + US + summary (US = 0x1F), IDENTICAL to
// ProjectStore's findingKey so a mark keyed on it matches the persisted finding.
QString findingKey(const QString &kind, const QString &host,
                   const QString &url, const QString &summary);

// Is this issue kind in the suppressed set? Exact, case-sensitive match on the
// stable kind slug (e.g. "missing-csp").
bool kindSuppressed(const QString &kind, const QStringList &suppressedKinds);

// Is this finding's identity key in the false-positive set?
bool keyIsFalsePositive(const QString &key, const QStringList &falsePositiveKeys);

} // namespace Nullock::Core::FindingTriageLogic

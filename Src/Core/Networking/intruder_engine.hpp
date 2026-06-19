#pragma once

// Multi-mode Intruder payload engine -- the Burp attack types (Sniper,
// Battering Ram, Pitchfork, Cluster Bomb) as pure combination generation +
// positional marker substitution, so they're unit-testable and the I/O
// (firing requests) stays in the caller. Markers are paired § (U+00A7);
// the text between the §s is that position's default value.

#include <QString>
#include <QStringList>
#include <QList>

namespace Nullock::Core::IntruderEngine {

enum class AttackType { Sniper, BatteringRam, Pitchfork, ClusterBomb };

// Parse "sniper" / "battering-ram" / "pitchfork" / "cluster-bomb"
// (case-insensitive, hyphen/underscore/space tolerant). Defaults to Sniper.
AttackType parseAttackType(const QString &s);
QString attackTypeName(AttackType t);

// Number of §...§ marker positions in the template.
int countMarkers(const QString &templ);

// Generate the per-request payload vectors. Each inner list has `positions`
// entries (one per marker). A null QString entry means "leave this marker at
// its default" (used by Sniper for the non-active positions). `payloadSets`:
//   - Sniper / Battering Ram: one set (extra sets ignored).
//   - Pitchfork / Cluster Bomb: one set per position (missing sets -> default).
// `maxResults` bounds generation (cluster bomb's cartesian product explodes);
// generation stops once the cap is hit.
QList<QStringList> generateCombinations(AttackType type, int positions,
                                        const QList<QStringList> &payloadSets,
                                        int maxResults = 10000);

// Substitute the k-th §...§ marker with combo[k]; a null combo[k] keeps the
// marker's own default (the text between its §s).
QString applyPayloads(const QString &templ, const QStringList &combo);

} // namespace Nullock::Core::IntruderEngine

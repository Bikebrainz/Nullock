#include "intruder_engine.hpp"

#include <QChar>

namespace Nullock::Core::IntruderEngine {

namespace {

constexpr ushort kMarker = 0x00A7;   // §

// Spans of each §...§ marker (start index of the first §, length incl. both
// §s) in template order, with the inner default text.
struct Marker { int start; int len; QString def; };

QList<Marker> findMarkers(const QString &templ) {
    QList<Marker> out;
    int i = 0;
    while (i < templ.size()) {
        if (templ.at(i).unicode() == kMarker) {
            int j = i + 1;
            while (j < templ.size() && templ.at(j).unicode() != kMarker) ++j;
            if (j < templ.size()) {                 // matched a closing §
                out.append({ i, j - i + 1, templ.mid(i + 1, j - i - 1) });
                i = j + 1;
                continue;
            }
            break;                                  // unbalanced -- stop
        }
        ++i;
    }
    return out;
}

} // namespace

AttackType parseAttackType(const QString &s) {
    QString k = s.toLower();
    k.replace(' ', '-').replace('_', '-');
    if (k == "battering-ram" || k == "ram" || k == "batteringram") return AttackType::BatteringRam;
    if (k == "pitchfork")                                          return AttackType::Pitchfork;
    if (k == "cluster-bomb" || k == "clusterbomb" || k == "cluster") return AttackType::ClusterBomb;
    return AttackType::Sniper;
}

QString attackTypeName(AttackType t) {
    switch (t) {
        case AttackType::BatteringRam: return "battering-ram";
        case AttackType::Pitchfork:    return "pitchfork";
        case AttackType::ClusterBomb:  return "cluster-bomb";
        case AttackType::Sniper:       return "sniper";
    }
    return "sniper";
}

int countMarkers(const QString &templ) {
    return static_cast<int>(findMarkers(templ).size());
}

QList<QStringList> generateCombinations(AttackType type, int positions,
                                        const QList<QStringList> &sets,
                                        int maxResults) {
    QList<QStringList> out;
    if (positions <= 0 || maxResults <= 0) return out;
    const QString def = QString();   // null => use the marker's own default

    switch (type) {
    case AttackType::BatteringRam: {
        const QStringList &s = sets.value(0);
        for (const QString &p : s) {
            out.append(QStringList(positions, p));
            if (out.size() >= maxResults) break;
        }
        break;
    }
    case AttackType::Sniper: {
        const QStringList &s = sets.value(0);
        for (int pos = 0; pos < positions && out.size() < maxResults; ++pos)
            for (const QString &p : s) {
                QStringList combo(positions, def);
                combo[pos] = p;
                out.append(combo);
                if (out.size() >= maxResults) break;
            }
        break;
    }
    case AttackType::Pitchfork: {
        // Zip the per-position sets; request count = shortest non-empty set.
        int minLen = -1;
        for (int p = 0; p < positions; ++p) {
            const int n = sets.value(p).size();
            if (n == 0) continue;
            if (minLen < 0 || n < minLen) minLen = n;
        }
        if (minLen < 0) break;
        for (int k = 0; k < minLen && out.size() < maxResults; ++k) {
            QStringList combo(positions, def);
            for (int p = 0; p < positions; ++p) {
                const QStringList &s = sets.value(p);
                if (k < s.size()) combo[p] = s[k];
            }
            out.append(combo);
        }
        break;
    }
    case AttackType::ClusterBomb: {
        // Cartesian product; a position with no set contributes its default.
        QList<int> idx(positions, 0);
        bool any = false;
        for (int p = 0; p < positions; ++p) if (!sets.value(p).isEmpty()) any = true;
        if (!any) break;
        while (out.size() < maxResults) {
            QStringList combo(positions, def);
            for (int p = 0; p < positions; ++p) {
                const QStringList &s = sets.value(p);
                if (!s.isEmpty()) combo[p] = s[idx[p]];
            }
            out.append(combo);
            // odometer increment, skipping empty (single-default) positions
            int p = positions - 1;
            for (; p >= 0; --p) {
                const QStringList &s = sets.value(p);
                if (s.isEmpty()) continue;
                if (idx[p] + 1 < s.size()) { ++idx[p]; break; }
                idx[p] = 0;
            }
            if (p < 0) break;   // rolled over -> done
        }
        break;
    }
    }
    return out;
}

QString applyPayloads(const QString &templ, const QStringList &combo) {
    const QList<Marker> markers = findMarkers(templ);
    QString out;
    out.reserve(templ.size());
    int cursor = 0;
    for (int k = 0; k < markers.size(); ++k) {
        const Marker &m = markers[k];
        out += templ.mid(cursor, m.start - cursor);          // text before marker
        const QString &p = k < combo.size() ? combo[k] : QString();
        out += p.isNull() ? m.def : p;                       // null => default
        cursor = m.start + m.len;
    }
    out += templ.mid(cursor);                                // trailing text
    return out;
}

} // namespace Nullock::Core::IntruderEngine

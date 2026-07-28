#include "ci_gate_logic.hpp"

namespace Nullock::Core::CiGate {

QString canonicalSeverity(const QString &sev) {
    const QString s = sev.trimmed().toLower();
    if (s == QLatin1String("critical")) return QStringLiteral("critical");
    if (s == QLatin1String("high"))     return QStringLiteral("high");
    if (s == QLatin1String("medium"))   return QStringLiteral("medium");
    if (s == QLatin1String("low"))      return QStringLiteral("low");
    // Blank / info / anything unrecognised is treated as informational.
    return QStringLiteral("info");
}

int severityRank(const QString &sev) {
    const QString s = canonicalSeverity(sev);
    if (s == QLatin1String("critical")) return 4;
    if (s == QLatin1String("high"))     return 3;
    if (s == QLatin1String("medium"))   return 2;
    if (s == QLatin1String("low"))      return 1;
    return 0; // info
}

int thresholdRank(const QString &failOn) {
    const QString s = failOn.trimmed().toLower();
    if (s == QLatin1String("none") || s == QLatin1String("off")
        || s == QLatin1String("never"))
        return kNeverFail;
    if (s == QLatin1String("critical")) return 4;
    if (s == QLatin1String("high"))     return 3;
    if (s == QLatin1String("medium"))   return 2;
    if (s == QLatin1String("low"))      return 1;
    if (s == QLatin1String("info"))     return 0;
    // Unknown / empty -> a sane CI default: fail on high or worse.
    return 3;
}

QString thresholdName(const QString &failOn) {
    const QString s = failOn.trimmed().toLower();
    if (s == QLatin1String("none") || s == QLatin1String("off")
        || s == QLatin1String("never"))
        return QStringLiteral("none");
    if (s == QLatin1String("critical") || s == QLatin1String("high")
        || s == QLatin1String("medium") || s == QLatin1String("low")
        || s == QLatin1String("info"))
        return s;
    return QStringLiteral("high"); // unknown / empty default
}

GateResult evaluate(const QList<QString> &severities, const QString &failOn) {
    GateResult r;
    r.threshold     = thresholdName(failOn);
    r.thresholdRank = thresholdRank(failOn);
    r.total         = static_cast<int>(severities.size());

    // Seed the breakdown so absent buckets report 0 rather than being missing.
    for (const char *k : { "critical", "high", "medium", "low", "info" })
        r.bySeverity.insert(QString::fromLatin1(k), 0);

    for (const QString &sev : severities) {
        const QString c = canonicalSeverity(sev);
        r.bySeverity[c] += 1;
        if (severityRank(sev) >= r.thresholdRank) ++r.offendingCount;
    }

    r.pass     = (r.offendingCount == 0);
    r.exitCode = r.pass ? kExitPass : kExitFail;
    return r;
}

GateResult unreachable(const QString &failOn, const QString &error) {
    GateResult r;
    r.threshold     = thresholdName(failOn);
    r.thresholdRank = thresholdRank(failOn);
    // Same seeded breakdown as evaluate(), so a caller formatting the summary
    // sees 0s rather than missing keys.
    for (const char *k : { "critical", "high", "medium", "low", "info" })
        r.bySeverity.insert(QString::fromLatin1(k), 0);
    r.reachable = false;
    r.error     = error;
    // An explicit "none"/"off" means the operator opted out of gating entirely;
    // honour it rather than surprising a reporting-only pipeline with a new
    // failure. Everyone else fails CLOSED: not scanning is not passing.
    const bool neverFail = (r.thresholdRank >= kNeverFail);
    r.pass     = neverFail;
    r.exitCode = neverFail ? kExitPass : kExitUnreachable;
    return r;
}

} // namespace Nullock::Core::CiGate

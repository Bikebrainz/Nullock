// Pure recon helpers (see recon_logic.hpp). No I/O; Qt6::Core only.

#include "recon_logic.hpp"

namespace Nullock::Core::ReconLogic {

QString cleanName(QString s) {
    s = s.trimmed().toLower();
    while (s.startsWith(QLatin1String("*."))) s.remove(0, 2);   // strip ALL leading "*."
    return s;
}

bool acceptCertName(const QString &cleaned, const QString &domain) {
    if (cleaned.isEmpty() || domain.isEmpty()) return false;
    if (cleaned.contains(QLatin1Char('*'))) return false;       // residual partial wildcard -> not a host
    if (cleaned == domain) return false;                        // the apex is not a subdomain
    return cleaned.endsWith(QLatin1Char('.') + domain);
}

bool recordMatchesQuery(const QString &recordName, const QString &askedName) {
    return recordName.compare(askedName, Qt::CaseInsensitive) == 0
        || recordName.endsWith(QLatin1Char('.') + askedName, Qt::CaseInsensitive);
}

bool isWildcardResolved(const QStringList &candidateIps, const QStringList &wildcardIps) {
    if (candidateIps.isEmpty() || wildcardIps.isEmpty()) return false;
    for (const QString &ip : candidateIps)
        if (!wildcardIps.contains(ip)) return false;            // a distinct address -> a real host
    return true;                                                // resolves ONLY to wildcard IPs
}

QStringList mergeIps(const QStringList &existing, const QStringList &incoming) {
    QStringList out = existing;
    for (const QString &ip : incoming)
        if (!ip.isEmpty() && !out.contains(ip)) out.append(ip);  // union, preserve order, dedup
    return out;
}

} // namespace Nullock::Core::ReconLogic

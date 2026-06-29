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

QString ipToReverseDnsName(const QString &ip) {
    const QString s = ip.trimmed();
    if (s.isEmpty()) return {};

    // IPv4: exactly 4 decimal octets 0..255, reversed, + .in-addr.arpa.
    if (!s.contains(QLatin1Char(':'))) {
        const QStringList parts = s.split(QLatin1Char('.'));
        if (parts.size() != 4) return {};
        int o[4];
        for (int i = 0; i < 4; ++i) {
            const QString &p = parts[i];
            if (p.isEmpty() || p.size() > 3) return {};
            for (const QChar c : p) if (!c.isDigit()) return {};
            bool ok = false;
            const int v = p.toInt(&ok);
            if (!ok || v < 0 || v > 255) return {};
            o[i] = v;
        }
        return QString::number(o[3]) + QLatin1Char('.') + QString::number(o[2])
             + QLatin1Char('.') + QString::number(o[1]) + QLatin1Char('.')
             + QString::number(o[0]) + QLatin1String(".in-addr.arpa");
    }

    // IPv6: expand "::" to 8 groups, then nibble-reverse all 32 hex digits.
    QString left = s, right;
    const int dc = s.indexOf(QLatin1String("::"));
    if (dc >= 0) {
        if (s.indexOf(QLatin1String("::"), dc + 1) >= 0) return {};  // only one "::"
        left  = s.left(dc);
        right = s.mid(dc + 2);
    }
    const QStringList lg = left.isEmpty()  ? QStringList() : left.split(QLatin1Char(':'));
    const QStringList rg = right.isEmpty() ? QStringList() : right.split(QLatin1Char(':'));
    QStringList groups;
    if (dc >= 0) {
        const int fill = 8 - (lg.size() + rg.size());
        if (fill < 0) return {};                  // too many groups for a "::"
        groups = lg;
        for (int i = 0; i < fill; ++i) groups << QStringLiteral("0");
        groups += rg;
    } else {
        groups = lg;
    }
    if (groups.size() != 8) return {};

    QString nibbles;
    nibbles.reserve(32);
    for (const QString &g : groups) {
        if (g.isEmpty() || g.size() > 4) return {};
        for (const QChar c : g) {
            const char ch = c.toLatin1();
            const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
                          || (ch >= 'A' && ch <= 'F');
            if (!hex) return {};
        }
        nibbles += QString(4 - g.size(), QLatin1Char('0')) + g.toLower();
    }
    QString out;                                   // 32 reversed nibbles, dot-separated
    out.reserve(73);
    for (int i = nibbles.size() - 1; i >= 0; --i) {
        out += nibbles[i];
        out += QLatin1Char('.');
    }
    out += QLatin1String("ip6.arpa");
    return out;
}

} // namespace Nullock::Core::ReconLogic

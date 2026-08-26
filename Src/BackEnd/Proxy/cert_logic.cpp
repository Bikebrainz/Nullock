// Pure MITM-CA host-validation logic (see cert_logic.hpp). No I/O; Qt6::Core only.

#include "cert_logic.hpp"

#include <QStringList>

namespace Nullock::Proxy::CertLogic {

QString sanitize(const QString &host) {
    QString out;
    out.reserve(host.size());
    for (const QChar c : host) {
        const bool ok = c.isLetterOrNumber() || c == QChar('-') || c == QChar('.') || c == QChar('_');
        out.append(ok ? c : QChar('_'));
    }
    return out;
}

bool isIpv6Literal(const QString &hostIn) {
    // Strict textual-IPv6 check, Qt6::Core only (QHostAddress lives in QtNetwork).
    // Accepts ::1, 2001:db8::1, fe80::1, ::ffff:192.0.2.1, 1:2:3:4:5:6:7:8, "::".
    // Rejects a zone id (%eth0), >1 "::", empty/oversize groups, and non-hex.
    if (hostIn.isEmpty() || hostIn.size() > 45) return false;
    if (hostIn.contains(QChar('%'))) return false;                 // no zone id
    QString host = hostIn;
    // An embedded IPv4 dotted-quad tail fills the low 32 bits (2 hex groups).
    if (host.contains(QChar('.'))) {
        const int lc = host.lastIndexOf(QChar(':'));
        if (lc < 0 || !isIpv4Literal(host.mid(lc + 1))) return false;
        host = host.left(lc + 1) + QStringLiteral("0:0");          // -> two placeholder groups
    }
    // At most one "::" compression run.
    const int dc = host.indexOf(QStringLiteral("::"));
    const bool compressed = dc >= 0;
    if (compressed && host.indexOf(QStringLiteral("::"), dc + 2) >= 0) return false;
    // A lone ':' at either end (not part of "::") is malformed.
    if ((host.startsWith(QChar(':')) && !host.startsWith(QLatin1String("::"))) ||
        (host.endsWith(QChar(':'))   && !host.endsWith(QLatin1String("::")))) return false;
    QStringList groups;
    if (compressed) {
        const QString before = host.left(dc);
        const QString after  = host.mid(dc + 2);
        const QStringList b = before.isEmpty() ? QStringList() : before.split(QChar(':'));
        const QStringList a = after.isEmpty()  ? QStringList() : after.split(QChar(':'));
        if (b.size() + a.size() >= 8) return false;                // "::" must cover >=1 zero group
        groups = b + a;
    } else {
        groups = host.split(QChar(':'));
        if (groups.size() != 8) return false;
    }
    for (const QString &g : groups) {
        if (g.isEmpty() || g.size() > 4) return false;
        for (const QChar c : g) {
            const ushort u = c.unicode();
            const bool hex = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f') || (u >= 'A' && u <= 'F');
            if (!hex) return false;
        }
    }
    return true;
}

bool isValidHostForCert(const QString &host) {
    if (host.isEmpty()) return false;
    // An IPv6 literal is valid to mint a leaf for (it becomes an IP: SAN), even
    // though it carries ':' which the general host check below rejects.
    if (isIpv6Literal(host)) return true;
    // DNS limit, measured in UTF-8 BYTES (not QString/UTF-16 code units) so a host
    // of many multi-byte letters can't slip past and overflow the X.509 field.
    if (host.toUtf8().size() > 253) return false;
    // Refuse a leading '-' / '_' -- defence in depth against an openssl subcommand
    // mistaking a value for an option (QProcess::setArguments already avoids a shell).
    if (host.startsWith('-') || host.startsWith('_')) return false;
    for (const QChar c : host) {
        if (c.isLetterOrNumber()) continue;                       // any-script letter/number
        if (c == QChar('-') || c == QChar('.') || c == QChar('_')) continue;
        return false;   // '\n' '\r' '/' '=' '\\' ':' ';' space ... all rejected here
    }
    // No leading/trailing dot, no double dot.
    if (host.startsWith('.') || host.endsWith('.')) return false;
    if (host.contains(QLatin1String(".."))) return false;
    return true;
}

bool isIpv4Literal(const QString &host) {
    const QStringList parts = host.split(QChar('.'));
    if (parts.size() != 4) return false;
    for (const QString &p : parts) {
        if (p.isEmpty() || p.size() > 3) return false;
        for (const QChar c : p)
            if (c.unicode() < '0' || c.unicode() > '9') return false;  // ASCII digits only
        bool ok = false;
        const int v = p.toInt(&ok);
        if (!ok || v < 0 || v > 255) return false;
    }
    return true;
}

QString sanEntryForHost(const QString &host) {
    if (isIpv4Literal(host) || isIpv6Literal(host)) return QStringLiteral("IP:") + host;
    return QStringLiteral("DNS:") + host;
}

} // namespace Nullock::Proxy::CertLogic

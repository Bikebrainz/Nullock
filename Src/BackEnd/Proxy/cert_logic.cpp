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

bool isValidHostForCert(const QString &host) {
    if (host.isEmpty()) return false;
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
    if (isIpv4Literal(host)) return QStringLiteral("IP:") + host;
    return QStringLiteral("DNS:") + host;
}

} // namespace Nullock::Proxy::CertLogic

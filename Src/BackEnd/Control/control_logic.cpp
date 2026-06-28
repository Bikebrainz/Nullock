#include "control_logic.hpp"

#include <QSet>
#include <QStringList>

namespace Nullock::Control::ControlLogic {

bool isHostAllowed(const QString &hostHdr, quint16 port) {
    if (hostHdr.isEmpty()) return true;
    const QString portStr = QString::number(port);
    static const auto buildAllowed = [](const QString &p) {
        return QSet<QString>{
            "127.0.0.1:" + p,
            "localhost:" + p,
            "[::1]:" + p,
            // Some clients omit the port when it's the default; we never listen
            // on 80 by default, but allow plain loopback hostnames just in case.
            QStringLiteral("127.0.0.1"),
            QStringLiteral("localhost"),
            QStringLiteral("[::1]"),
        };
    };
    const QSet<QString> allowed = buildAllowed(portStr);
    return allowed.contains(hostHdr.toLower());
}

bool isMethodAllowed(const QString &method) {
    static const QStringList kAllowed = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    };
    return kAllowed.contains(method);
}

bool isReadMethod(const QString &method) {
    return method == "GET" || method == "HEAD" || method == "OPTIONS";
}

bool isRequestAuthorized(const QString &method, const QString &origin,
                         const QString &nullockHdr, quint16 port) {
    if (isReadMethod(method)) return true;
    const QString portStr = QString::number(port);
    const bool originOk = (origin == "http://127.0.0.1:" + portStr
                        || origin == "http://localhost:" + portStr);
    const bool tokenOk  = (nullockHdr == "1" || nullockHdr.toLower() == "true");
    return originOk || tokenOk;
}

QString mdCodeSpanSafe(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u == '`') continue;              // can't be escaped inside a code span -> drop
        if (u < 0x20 || u == 0x7F) { out += QLatin1Char(' '); continue; }  // control -> space
        out += ch;
    }
    return out;
}

QString mdTextSafe(const QString &s) {
    static const QString kMeta = QStringLiteral("\\`*_[]()<>|!#");
    QString out;
    out.reserve(s.size() + 8);
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u < 0x20 || u == 0x7F) { out += QLatin1Char(' '); continue; }  // control -> space (no new line/list/heading)
        if (kMeta.contains(ch)) out += QLatin1Char('\\');                  // backslash-escape inline metacharacters
        out += ch;
    }
    return out;
}

} // namespace Nullock::Control::ControlLogic

#include "oast_logic.hpp"

#include <QRegularExpression>

namespace Nullock::Core::OastLogic {

QString extractToken(const QString &hostHeader, const QString &path) {
    // The token is exactly 16 lowercase-hex chars. The regex is fixed-length and
    // anchored (^[0-9a-f]{16}$) -- linear, no backtracking, so no ReDoS on the
    // attacker-controlled label.
    static const QRegularExpression hex16(QStringLiteral("^[0-9a-f]{16}$"));

    // Subdomain form: <token>.<base-host>:<port>
    const int dot = hostHeader.indexOf('.');
    if (dot > 0) {
        const QString head = hostHeader.left(dot).toLower();
        if (hex16.match(head).hasMatch()) return head;
    }
    // Path form: /oast/<token>/...
    if (path.startsWith(QLatin1String("/oast/"))) {
        const int next = path.indexOf('/', 6);
        const QString seg = next > 0 ? path.mid(6, next - 6) : path.mid(6);
        if (hex16.match(seg).hasMatch()) return seg;
    }
    return {};
}

} // namespace Nullock::Core::OastLogic

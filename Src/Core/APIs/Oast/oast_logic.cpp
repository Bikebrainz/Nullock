#include "oast_logic.hpp"

#include <QRegularExpression>

namespace Nullock::Core::OastLogic {

QString extractToken(const QString &hostHeader, const QString &path) {
    // The token is exactly 16 lowercase-hex chars. Anchor with \A...\z, NOT ^...$:
    // PCRE2's $ (default) also matches immediately before a single trailing '\n',
    // so ^[0-9a-f]{16}$ would accept a 17-char "….abcdef\n" label and return it --
    // violating the exact-16-hex contract and leaking a raw LF into downstream
    // sinks. \z matches ONLY the very end of the subject. Still fixed-length and
    // linear (no backtracking), so no ReDoS on the attacker-controlled label.
    static const QRegularExpression hex16(QStringLiteral("\\A[0-9a-f]{16}\\z"));

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

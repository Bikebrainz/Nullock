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
    // Path form: /oast/<token>[/...][?query][#frag]. The token segment ends at the
    // next '/', '?' OR '#' -- a real callback URL commonly carries a query/fragment
    // (/oast/<token>?x=1), and terminating only on '/' left the '?x=1' glued to the
    // token so the 16-hex match failed and the OOB callback was never correlated.
    if (path.startsWith(QLatin1String("/oast/"))) {
        int next = -1;
        for (int i = 6; i < path.size(); ++i) {
            const QChar c = path[i];
            if (c == QLatin1Char('/') || c == QLatin1Char('?') || c == QLatin1Char('#')) { next = i; break; }
        }
        const QString seg = next > 0 ? path.mid(6, next - 6) : path.mid(6);
        if (hex16.match(seg).hasMatch()) return seg;
    }
    return {};
}

} // namespace Nullock::Core::OastLogic

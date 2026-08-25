#include "oast_logic.hpp"

#include <QJsonArray>
#include <QRegularExpression>

namespace Nullock::Core::OastLogic {

namespace {
constexpr int kStateVersion = 1;
}

QJsonObject serializeState(const QHash<QString, OastOrigin> &tokens,
                           const QSet<QString> &confirmed) {
    QJsonArray toks;
    for (auto it = tokens.cbegin(); it != tokens.cend(); ++it) {
        const OastOrigin &o = it.value();
        toks.append(QJsonObject{
            { QStringLiteral("token"), it.key() },
            { QStringLiteral("rowId"), o.rowId },
            { QStringLiteral("host"),  o.host },
            { QStringLiteral("param"), o.param },
            { QStringLiteral("url"),   o.url },
            { QStringLiteral("kind"),  o.kind },
            { QStringLiteral("note"),  o.note },
        });
    }
    QJsonArray conf;
    for (const QString &t : confirmed) conf.append(t);
    return QJsonObject{
        { QStringLiteral("version"),   kStateVersion },
        { QStringLiteral("tokens"),    toks },
        { QStringLiteral("confirmed"), conf },
    };
}

void deserializeState(const QJsonObject &obj,
                      QHash<QString, OastOrigin> &tokens,
                      QSet<QString> &confirmed) {
    tokens.clear();
    confirmed.clear();
    if (obj.value(QStringLiteral("version")).toInt() != kStateVersion) return;
    for (const QJsonValue &v : obj.value(QStringLiteral("tokens")).toArray()) {
        const QJsonObject e = v.toObject();
        const QString token = e.value(QStringLiteral("token")).toString();
        if (token.isEmpty()) continue;
        OastOrigin o;
        o.rowId = e.value(QStringLiteral("rowId")).toInt();
        o.host  = e.value(QStringLiteral("host")).toString();
        o.param = e.value(QStringLiteral("param")).toString();
        o.url   = e.value(QStringLiteral("url")).toString();
        o.kind  = e.value(QStringLiteral("kind")).toString();
        o.note  = e.value(QStringLiteral("note")).toString();
        tokens.insert(token, o);
    }
    for (const QJsonValue &v : obj.value(QStringLiteral("confirmed")).toArray()) {
        const QString t = v.toString();
        if (!t.isEmpty()) confirmed.insert(t);
    }
}

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

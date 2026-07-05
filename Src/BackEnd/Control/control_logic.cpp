#include "control_logic.hpp"

#include <QRegularExpression>
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

QString bearerToken(const QString &authHeaderValue) {
    const QString v = authHeaderValue.trimmed();
    static const QString scheme = QStringLiteral("bearer");
    if (v.size() <= scheme.size()) return {};
    if (v.left(scheme.size()).toLower() != scheme) return {};
    if (!v.at(scheme.size()).isSpace()) return {};   // must be "Bearer <token>"
    return v.mid(scheme.size()).trimmed();
}

bool constantTimeEquals(const QString &a, const QString &b) {
    const QByteArray ab = a.toUtf8();
    const QByteArray bb = b.toUtf8();
    if (ab.isEmpty() || bb.isEmpty()) return ab.isEmpty() && bb.isEmpty();
    // Fold the length difference into the accumulator, then compare every byte
    // (indexing modulo each length so a size mismatch never short-circuits the
    // loop). diff stays non-zero if any byte or the lengths differ.
    unsigned diff = static_cast<unsigned>(ab.size()) ^ static_cast<unsigned>(bb.size());
    const int n = qMax(ab.size(), bb.size());
    for (int i = 0; i < n; ++i) {
        const unsigned ca = static_cast<unsigned char>(ab.at(i % ab.size()));
        const unsigned cb = static_cast<unsigned char>(bb.at(i % bb.size()));
        diff |= (ca ^ cb);
    }
    return diff == 0;
}

bool isTokenAuthorized(const QString &authHeaderValue, const QString &configuredToken) {
    if (configuredToken.isEmpty()) return false;          // auth disabled -> not authorized here
    const QString presented = bearerToken(authHeaderValue);
    if (presented.isEmpty()) return false;
    return constantTimeEquals(presented, configuredToken);
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

QString xmlAttrEscape(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        const ushort u = c.unicode();
        // Control chars (incl. CR/LF/tab) -> space: a raw control byte would let
        // attacker content break attribute framing, and many XML parsers reject
        // or mangle them inside an attribute value.
        if (u < 0x20) { out += QLatin1Char(' '); continue; }
        switch (u) {
        case '&':  out += QStringLiteral("&amp;");  break;
        case '<':  out += QStringLiteral("&lt;");   break;
        case '>':  out += QStringLiteral("&gt;");   break;
        case '"':  out += QStringLiteral("&quot;"); break;
        case '\'': out += QStringLiteral("&apos;"); break;
        default:   out += c;
        }
    }
    return out;
}

bool hasRequestSmugglingChars(const QString &s) {
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u == '\r' || u == '\n' || u == '\0') return true;
    }
    return false;
}

QString safeJoin(const QString &dir, const QString &rel) {
    // Strip leading slashes, refuse "..", confine to dir.
    QString r = rel;
    while (r.startsWith('/') || r.startsWith('\\')) r.remove(0, 1);
    if (r.contains("..")) return {};
    return dir + "/" + r;
}

bool looksLikeCatastrophicRegex(const QString &pattern) {
    // (1) Nested unbounded quantifier: a quantifier INSIDE a group whose group
    //     is itself unbounded-quantified -- (a+)+ / (a*)* / (a{2,})+.
    static const QRegularExpression kNestedQuant(
        QStringLiteral(R"(\([^)]*[*+]\)[*+]|\([^)]*\{\d+,\}\)[*+])"),
        QRegularExpression::NoPatternOption);
    if (kNestedQuant.match(pattern).hasMatch()) return true;
    // (2) Alternation with two IDENTICAL adjacent branches under an unbounded
    //     quantifier -- (a|a)+, (\d|\d)+, ([ab]|[ab])+, (a|a|a)+. The \1
    //     backreference matches "a branch immediately followed by the SAME
    //     branch"; the trailing [^)]* allows further alternatives before the
    //     group closes and *requires* an outer + / * so a benign unquantified
    //     (a|a) isn't flagged, while disjoint (foo|bar)+ / (a|b)+ never match.
    static const QRegularExpression kDupAltBranch(
        QStringLiteral(R"(\(([^|)]+)\|\1[^)]*\)[*+])"),
        QRegularExpression::NoPatternOption);
    if (kDupAltBranch.match(pattern).hasMatch()) return true;
    return false;
}

} // namespace Nullock::Control::ControlLogic

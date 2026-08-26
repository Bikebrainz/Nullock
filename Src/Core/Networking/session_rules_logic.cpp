// Pure session-rule logic (see session_rules_logic.hpp). No I/O; Qt6::Core only.

#include "session_rules_logic.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace Nullock::Core::SessionRulesLogic {

QRegularExpression globToRx(const QString &glob) {
    // Anchor with \A ... \z (absolute start/end), NOT ^ ... $: PCRE2's $ (without
    // DollarEndOnly) also matches immediately BEFORE a trailing newline, so
    // "api.example.com$" would over-match "api.example.com\n" and the scope gate
    // would fire on a trailing-newline variant of the host/path it should reject.
    QString rx = "\\A";
    for (QChar c : glob) {
        if (c == '*')      rx += ".*";
        else if (c == '?') rx += ".";
        else               rx += QRegularExpression::escape(QString(c));
    }
    rx += "\\z";
    return QRegularExpression(rx, QRegularExpression::CaseInsensitiveOption);
}

QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QString findCookieValue(const QString &raw, const QString &name) {
    // Only the FIRST segment is the name=value cookie pair; later segments are
    // attributes (Path/Domain/Expires/...) and must not be returned as a value.
    const QList<QString> segs = raw.split(';');
    if (segs.isEmpty()) return {};
    const QString s = segs.first().trimmed();
    const int eq = s.indexOf('=');
    if (eq <= 0) return {};
    if (s.left(eq).trimmed().compare(name, Qt::CaseInsensitive) == 0)
        return s.mid(eq + 1).trimmed();
    return {};
}

QString jsonPathGet(const QByteArray &body, const QString &path) {
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(body, &err);
    if (err.error != QJsonParseError::NoError) return {};
    QJsonValue cur = doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object());
    for (const QString &seg : path.split('.', Qt::SkipEmptyParts)) {
        if (cur.isObject()) {
            cur = cur.toObject().value(seg);
        } else if (cur.isArray()) {
            bool ok = false;
            const int idx = seg.toInt(&ok);
            if (!ok || idx < 0 || idx >= cur.toArray().size()) return {};
            cur = cur.toArray().at(idx);
        } else {
            return {};
        }
    }
    if (cur.isString()) return cur.toString();
    if (cur.isDouble()) {
        // Preserve exact integer text -- a bare QString::number(double) emits
        // scientific notation / loses digits for epoch timestamps and 64-bit IDs.
        const double d = cur.toDouble();
        const qint64 i = cur.toInteger();
        if (static_cast<double>(i) == d) return QString::number(i);
        return QString::number(d, 'g', 17);
    }
    if (cur.isBool())   return cur.toBool() ? "true" : "false";
    return {};
}

QString substitute(const QString &templ, const QHash<QString, QString> &vars) {
    QString out = templ;
    static const QRegularExpression rx(R"(\{\{([A-Za-z_][A-Za-z0-9_]*)\}\})");
    int offset = 0;
    while (true) {
        auto m = rx.match(out, offset);
        if (!m.hasMatch()) break;
        const QString name = m.captured(1);
        auto it = vars.find(name);
        if (it == vars.end()) { offset = m.capturedEnd(); continue; }
        out.replace(m.capturedStart(), m.capturedLength(), *it);
        offset = m.capturedStart() + it->size();   // single-pass (security)
    }
    return out;
}

bool hasUnresolvedPlaceholder(const QString &s) {
    // Same {{name}} shape substitute() targets, so this is exactly "a placeholder
    // substitute() would have replaced had the variable existed".
    static const QRegularExpression rx(R"(\{\{[A-Za-z_][A-Za-z0-9_]*\}\})");
    return rx.match(s).hasMatch();
}

QString firstCapture(const QRegularExpressionMatch &m) {
    for (int i = 1; i <= m.lastCapturedIndex(); ++i)
        if (!m.captured(i).isNull() && !m.captured(i).isEmpty()) return m.captured(i);
    return m.captured(0);
}

QString sanitizeHeaderValue(const QString &v) {
    QString out = v;
    out.remove('\r').remove('\n');
    // Drop other C0 control chars too (a header value must be printable-ish).
    QString clean;
    clean.reserve(out.size());
    for (const QChar c : out)
        if (c.unicode() >= 0x20 || c == '\t') clean.append(c);
    return clean;
}

QString sanitizeCookieValue(const QString &v) {
    return sanitizeHeaderValue(v).remove(';');   // ';' would forge extra cookie pairs
}

QString jsonEscapeInner(const QString &v) {
    // Serialize as a JSON string then strip the surrounding quotes -- gives a
    // correctly-escaped inner body for substitution inside a JSON string literal.
    const QByteArray j = QJsonDocument(QJsonArray{ v }).toJson(QJsonDocument::Compact);
    QString s = QString::fromUtf8(j).trimmed();   // ["...escaped..."]
    const int a = s.indexOf('"'), b = s.lastIndexOf('"');
    if (a >= 0 && b > a) return s.mid(a + 1, b - a - 1);
    return v;
}

QString stripQuery(const QString &path) {
    const int q = path.indexOf('?');
    return q < 0 ? path : path.left(q);
}

bool ruleAppliesToTool(int toolsMask, int tool) {
    if (toolsMask == 0) return true;         // unset == all tools (back-compatible)
    return (toolsMask & tool) != 0;
}

bool responseIsLoggedOut(int status, const QString &bodyText,
                         const QString &statusList, const QString &bodyRegex) {
    if (status != 0) {
        const QStringList codes = statusList.split(QLatin1Char(','), Qt::SkipEmptyParts);
        for (const QString &c : codes) {
            bool ok = false;
            if (c.trimmed().toInt(&ok) == status && ok) return true;
        }
    }
    if (!bodyRegex.isEmpty()) {
        const QRegularExpression re(bodyRegex);
        if (re.isValid() && re.match(bodyText).hasMatch()) return true;
    }
    return false;
}

QByteArray injectIntoNonFormBody(const QByteArray &body, const QString &injectKey,
                                 const QString &variable, const QString &value, bool isJson) {
    const QString sub = isJson ? jsonEscapeInner(value) : value;
    QByteArray b = body;
    b.replace(QStringLiteral("{{%1}}").arg(injectKey).toUtf8(), sub.toUtf8());
    if (!variable.isEmpty())
        b.replace(QStringLiteral("{{%1}}").arg(variable).toUtf8(), sub.toUtf8());
    return b;
}

bool urlScopeMatches(const QString &host, const QString &path,
                     const QStringList &includeGlobs, const QStringList &excludeGlobs) {
    if (includeGlobs.isEmpty() && excludeGlobs.isEmpty()) return true;   // no URL scope
    const QString target = host + stripQuery(path);
    for (const QString &ex : excludeGlobs)
        if (!ex.isEmpty() && globToRx(ex).match(target).hasMatch()) return false;  // exclude wins
    if (includeGlobs.isEmpty()) return true;
    for (const QString &in : includeGlobs)
        if (!in.isEmpty() && globToRx(in).match(target).hasMatch()) return true;
    return false;
}

} // namespace Nullock::Core::SessionRulesLogic

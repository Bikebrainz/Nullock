#include "session_rules.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>
#include <QRegularExpression>

namespace Nullock::Core {

namespace {

// Glob to anchored regex. Same trick as M&R: any-char (*) and
// single-char (?) wildcards, otherwise escape.
QRegularExpression globToRx(const QString &glob) {
    QString rx = "^";
    for (QChar c : glob) {
        if (c == '*')      rx += ".*";
        else if (c == '?') rx += ".";
        else               rx += QRegularExpression::escape(QString(c));
    }
    rx += "$";
    return QRegularExpression(rx, QRegularExpression::CaseInsensitiveOption);
}

QString findHeader(const QList<QPair<QString,QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QString findCookieValue(const QString &raw, const QString &name) {
    // raw is either a Cookie or Set-Cookie header value. Walk segments.
    for (const QString &seg : raw.split(';')) {
        const QString s = seg.trimmed();
        const int eq = s.indexOf('=');
        if (eq <= 0) continue;
        if (s.left(eq).trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return s.mid(eq + 1).trimmed();
    }
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
    if (cur.isDouble()) return QString::number(cur.toDouble());
    if (cur.isBool())   return cur.toBool() ? "true" : "false";
    return {};
}

} // namespace

void SessionRules::setRules(const QList<SessionRule> &rules) {
    {
        QMutexLocker lk(&m_mutex);
        m_rules = rules;
    }
    emit rulesChanged();
}

QList<SessionRule> SessionRules::rules() const {
    QMutexLocker lk(&m_mutex);
    return m_rules;
}

QHash<QString, QString> SessionRules::variables() const {
    QMutexLocker lk(&m_mutex);
    return m_vars;
}

void SessionRules::clearAll() {
    {
        QMutexLocker lk(&m_mutex);
        m_vars.clear();
    }
    emit variablesChanged();
}

bool SessionRules::matches(const SessionRule &r,
                           const QString &host, const QString &path) const {
    return globToRx(r.hostGlob).match(host).hasMatch()
        && globToRx(r.pathGlob).match(path).hasMatch();
}

QString SessionRules::substitute(const QString &templ,
                                 const QHash<QString, QString> &vars) const {
    // {{var}} substitution. Unknown vars stay literal so the user can
    // see in a captured request that a value was missing.
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
        offset = m.capturedStart() + it->size();
    }
    return out;
}

void SessionRules::applyToResponse(const Nullock::Proxy::HttpRequest &req,
                                   const Nullock::Proxy::HttpResponse &resp) {
    QList<SessionRule> rs;
    {
        QMutexLocker lk(&m_mutex);
        rs = m_rules;
    }
    if (rs.isEmpty()) return;

    QHash<QString, QString> newVars;
    for (const auto &r : rs) {
        if (!r.enabled) continue;
        if (!matches(r, req.host, req.path)) continue;
        if (r.variable.isEmpty() || r.extractKey.isEmpty()) continue;

        QString val;
        switch (r.extractFrom) {
            case SessionRule::ExtractFromHeader:
                val = findHeader(resp.headers, r.extractKey);
                break;
            case SessionRule::ExtractFromCookie:
                // Walk every Set-Cookie response header looking for the name.
                for (const auto &h : resp.headers) {
                    if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
                    val = findCookieValue(h.second, r.extractKey);
                    if (!val.isEmpty()) break;
                }
                break;
            case SessionRule::ExtractFromJsonPath:
                val = jsonPathGet(resp.body, r.extractKey);
                break;
            case SessionRule::ExtractFromRegex: {
                QRegularExpression rx(r.extractKey,
                    QRegularExpression::DotMatchesEverythingOption);
                if (!rx.isValid()) break;
                // Cap the body we scan -- regex against a 10 MB JSON
                // payload is a real-world foot-gun.
                const QByteArray buf = resp.body.left(1 * 1024 * 1024);
                auto m = rx.match(QString::fromUtf8(buf));
                if (m.hasMatch())
                    val = m.lastCapturedIndex() >= 1 ? m.captured(1) : m.captured(0);
                break;
            }
        }
        if (!val.isEmpty()) newVars.insert(r.variable, val);
    }
    if (newVars.isEmpty()) return;
    {
        QMutexLocker lk(&m_mutex);
        for (auto it = newVars.cbegin(); it != newVars.cend(); ++it)
            m_vars.insert(it.key(), it.value());
    }
    emit variablesChanged();
}

void SessionRules::applyToRequest(Nullock::Proxy::HttpRequest &req) const {
    QList<SessionRule> rs;
    QHash<QString, QString> vars;
    {
        QMutexLocker lk(&m_mutex);
        rs = m_rules;
        vars = m_vars;
    }
    if (rs.isEmpty() || vars.isEmpty()) return;

    for (const auto &r : rs) {
        if (!r.enabled) continue;
        if (!matches(r, req.host, req.path)) continue;
        if (r.injectKey.isEmpty()) continue;

        const QString templ = r.injectTemplate.isEmpty()
            ? QString("{{%1}}").arg(r.variable.isEmpty() ? r.injectKey : r.variable)
            : r.injectTemplate;
        const QString value = substitute(templ, vars);
        if (value.isEmpty()) continue;

        switch (r.injectInto) {
            case SessionRule::InjectIntoHeader: {
                // Replace existing header by name, else append.
                bool replaced = false;
                for (auto &h : req.headers) {
                    if (h.first.compare(r.injectKey, Qt::CaseInsensitive) == 0) {
                        h.second = value;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                    req.headers.append({ r.injectKey, value });
                break;
            }
            case SessionRule::InjectIntoCookie: {
                // Merge into existing Cookie header. Same-name overwrites.
                int idx = -1;
                for (int i = 0; i < req.headers.size(); ++i)
                    if (req.headers[i].first.compare("Cookie", Qt::CaseInsensitive) == 0) {
                        idx = i; break;
                    }
                QString val = idx >= 0 ? req.headers[idx].second : QString();
                QStringList parts;
                bool replaced = false;
                for (const QString &seg : val.split(';', Qt::SkipEmptyParts)) {
                    const QString s = seg.trimmed();
                    const int eq = s.indexOf('=');
                    const QString name = eq > 0 ? s.left(eq).trimmed() : s;
                    if (name.compare(r.injectKey, Qt::CaseInsensitive) == 0) {
                        parts << (r.injectKey + "=" + value);
                        replaced = true;
                    } else {
                        parts << s;
                    }
                }
                if (!replaced) parts << (r.injectKey + "=" + value);
                const QString joined = parts.join("; ");
                if (idx >= 0) req.headers[idx].second = joined;
                else          req.headers.append({ "Cookie", joined });
                break;
            }
            case SessionRule::InjectIntoBody: {
                // Replace {{var}} in body, or append "&k=v" to a form body.
                const QString contentType = findHeader(req.headers, "Content-Type");
                if (contentType.startsWith("application/x-www-form-urlencoded", Qt::CaseInsensitive)) {
                    QByteArray b = req.body;
                    if (!b.isEmpty() && !b.endsWith('&')) b.append('&');
                    b.append(QUrl::toPercentEncoding(r.injectKey));
                    b.append('=');
                    b.append(QUrl::toPercentEncoding(value));
                    req.body = b;
                } else {
                    // JSON / other: replace literal "{{name}}" tokens.
                    QByteArray b = req.body;
                    b.replace(QString("{{%1}}").arg(r.injectKey).toUtf8(), value.toUtf8());
                    if (!r.variable.isEmpty())
                        b.replace(QString("{{%1}}").arg(r.variable).toUtf8(), value.toUtf8());
                    req.body = b;
                }
                break;
            }
            case SessionRule::InjectIntoUrl: {
                QString p = req.path;
                const QChar sep = p.contains('?') ? QChar('&') : QChar('?');
                p += QString("%1%2=%3").arg(sep)
                                       .arg(QString::fromUtf8(QUrl::toPercentEncoding(r.injectKey)))
                                       .arg(QString::fromUtf8(QUrl::toPercentEncoding(value)));
                req.path   = p;
                req.target = p;
                break;
            }
        }
    }
}

} // namespace Nullock::Core

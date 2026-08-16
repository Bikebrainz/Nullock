#include "session_rules.hpp"
#include "session_rules_logic.hpp"

#include <QDateTime>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QtConcurrent>
#include <QUrl>

namespace Nullock::Core {

// globToRx/findHeader/findCookieValue/jsonPathGet/substitute and the new
// sanitizers are pure and live in session_rules_logic.cpp (Qt6::Core only) so
// they can be unit-tested. This TU keeps the QObject + the proxy-typed pipeline.
using namespace SessionRulesLogic;

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
    // Flattened view for the UI/debug (later hosts win on a name collision).
    QHash<QString, QString> flat;
    for (auto h = m_varsByHost.cbegin(); h != m_varsByHost.cend(); ++h)
        for (auto v = h->cbegin(); v != h->cend(); ++v)
            flat.insert(v.key(), v.value());
    return flat;
}

void SessionRules::clearAll() {
    {
        QMutexLocker lk(&m_mutex);
        m_varsByHost.clear();
    }
    emit variablesChanged();
}

bool SessionRules::matches(const SessionRule &r,
                           const QString &host, const QString &path) const {
    // QRegularExpression caches compiled state lazily on first match,
    // BUT we throw the object away after each call which discards the
    // cache. Instead, keep a process-local memoization keyed by the
    // glob string -- 99% of requests reuse the same handful of globs.
    // Thread-safe access via the static QMutex.
    static QMutex          cacheMu;
    static QHash<QString, QRegularExpression> cache;
    auto resolve = [](const QString &g) -> QRegularExpression {
        QMutexLocker lk(&cacheMu);
        auto it = cache.find(g);
        if (it != cache.end()) return *it;
        const QRegularExpression rx = globToRx(g);
        cache.insert(g, rx);
        return rx;
    };
    // Match the pathGlob against the path component only -- req.path carries the
    // "?query", so an exact glob would otherwise never match a query-bearing req.
    return resolve(r.hostGlob).match(host).hasMatch()
        && resolve(r.pathGlob).match(stripQuery(path)).hasMatch();
}

QString SessionRules::substitute(const QString &templ,
                                 const QHash<QString, QString> &vars) const {
    return SessionRulesLogic::substitute(templ, vars);
}

void SessionRules::applyToResponse(const Nullock::Proxy::HttpRequest &req,
                                   const Nullock::Proxy::HttpResponse &resp) {
    // Session validity: a logged-out response for a macro's host triggers an async
    // re-auth. Runs first + independent of extraction, so it fires even when no
    // extraction rule matches this response.
    maybeReauth(req.host, resp);

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
                // Walk EVERY Set-Cookie response header; the LAST same-name set
                // value wins (browser cookie-jar semantics -- a rotated session
                // cookie re-issued later in the response is the authoritative one).
                for (const auto &h : resp.headers) {
                    if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
                    const QString v = findCookieValue(h.second, r.extractKey);
                    if (!v.isEmpty()) val = v;
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
                if (m.hasMatch()) val = firstCapture(m);   // first PARTICIPATING group
                break;
            }
        }
        if (!val.isEmpty()) newVars.insert(r.variable, val);
    }
    if (newVars.isEmpty()) return;
    {
        QMutexLocker lk(&m_mutex);
        // Store under the HOST the value was extracted from -- never inject a
        // host-A secret into a host-B request.
        auto &hostVars = m_varsByHost[req.host];
        for (auto it = newVars.cbegin(); it != newVars.cend(); ++it)
            hostVars.insert(it.key(), it.value());
    }
    emit variablesChanged();
}

bool SessionRules::applyToRequest(Nullock::Proxy::HttpRequest &req, int tool) const {
    QList<SessionRule> rs;
    QHash<QString, QString> vars;
    {
        QMutexLocker lk(&m_mutex);
        rs = m_rules;
        // ONLY variables captured from THIS request's host -- a secret extracted
        // from another host must never ride along cross-origin.
        vars = m_varsByHost.value(req.host);
    }
    if (rs.isEmpty() || vars.isEmpty()) return false;
    bool modified = false;

    for (const auto &r : rs) {
        if (!r.enabled) continue;
        if (!SessionRulesLogic::ruleAppliesToTool(r.tools, tool)) continue;
        if (!matches(r, req.host, req.path)) continue;
        if (r.injectKey.isEmpty()) continue;

        const QString templ = r.injectTemplate.isEmpty()
            ? QString("{{%1}}").arg(r.variable.isEmpty() ? r.injectKey : r.variable)
            : r.injectTemplate;
        const QString value = substitute(templ, vars);
        if (value.isEmpty()) continue;
        modified = true;   // a rule matched + produced a value -> it injects below

        switch (r.injectInto) {
            case SessionRule::InjectIntoHeader: {
                // Strip CR/LF: a target-controlled value must not split the header
                // line / smuggle a request onto the wire (CWE-93/CWE-113).
                const QString hv = sanitizeHeaderValue(value);
                bool replaced = false;
                for (auto &h : req.headers) {
                    if (h.first.compare(r.injectKey, Qt::CaseInsensitive) == 0) {
                        h.second = hv;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                    req.headers.append({ r.injectKey, hv });
                break;
            }
            case SessionRule::InjectIntoCookie: {
                // Strip CR/LF AND ';' (a ';' would forge extra cookie pairs).
                const QString cv = sanitizeCookieValue(value);
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
                        parts << (r.injectKey + "=" + cv);
                        replaced = true;
                    } else {
                        parts << s;
                    }
                }
                if (!replaced) parts << (r.injectKey + "=" + cv);
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
                    // JSON / other: replace literal "{{name}}" tokens. JSON-escape
                    // the value when the body is JSON so a value containing a quote
                    // or backslash can't break/forge the JSON.
                    const bool isJson = contentType.contains("json", Qt::CaseInsensitive);
                    const QString sub = isJson ? jsonEscapeInner(value) : value;
                    QByteArray b = req.body;
                    b.replace(QString("{{%1}}").arg(r.injectKey).toUtf8(), sub.toUtf8());
                    if (!r.variable.isEmpty())
                        b.replace(QString("{{%1}}").arg(r.variable).toUtf8(), sub.toUtf8());
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
    return modified;
}

// Minimal HTTP/1.1 request parse for the bytes-level wrapper: request line
// (method / target / version) + headers + body. Faithfulness of the UNMODIFIED
// request doesn't matter -- applyToRequestBytes only reserializes when a rule
// fired, and otherwise sends the original bytes untouched.
static Nullock::Proxy::HttpRequest parseRawRequest(const QByteArray &raw,
                                                   const QString &host) {
    Nullock::Proxy::HttpRequest req;
    req.host = host;
    int sepLen = 4;
    int sep = raw.indexOf("\r\n\r\n");
    if (sep < 0) { sep = raw.indexOf("\n\n"); sepLen = 2; }
    const QByteArray head = (sep < 0) ? raw : raw.left(sep);
    req.body = (sep < 0) ? QByteArray() : raw.mid(sep + sepLen);
    const QList<QByteArray> lines = head.split('\n');
    if (!lines.isEmpty()) {
        const QList<QByteArray> p = lines.first().trimmed().split(' ');
        if (p.size() >= 2) {
            req.method = QString::fromLatin1(p[0]);
            req.path   = QString::fromLatin1(p[1]);
            req.target = QString::fromLatin1(p[1]);
        }
        if (p.size() >= 3) req.httpVersion = QString::fromLatin1(p[2]);
    }
    for (int i = 1; i < lines.size(); ++i) {
        QByteArray l = lines[i]; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        req.headers.append({ QString::fromLatin1(l.left(c)).trimmed(),
                             QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed()) });
    }
    return req;
}

bool SessionRules::applyToRequestBytes(QByteArray &rawRequest, const QString &host,
                                       int tool) const {
    Nullock::Proxy::HttpRequest req = parseRawRequest(rawRequest, host);
    if (!applyToRequest(req, tool)) return false;   // no rule fired -> untouched
    rawRequest = Nullock::Proxy::serializeRequestForOrigin(req);
    return true;
}

void SessionRules::ingestVariables(const QString &host,
                                   const QHash<QString, QString> &vars) {
    if (host.isEmpty() || vars.isEmpty()) return;
    {
        QMutexLocker lk(&m_mutex);
        QHash<QString, QString> &bag = m_varsByHost[host];
        for (auto it = vars.cbegin(); it != vars.cend(); ++it)
            bag.insert(it.key(), it.value());
    }
    emit variablesChanged();
}

void SessionRules::setMacros(const QList<SessionMacro> &macros) {
    { QMutexLocker lk(&m_mutex); m_macros = macros; }
    emit macrosChanged();
}

QList<SessionMacro> SessionRules::macros() const {
    QMutexLocker lk(&m_mutex);
    return m_macros;
}

bool SessionRules::runMacro(const QString &name) {
    SessionMacro macro;
    bool found = false;
    {
        QMutexLocker lk(&m_mutex);
        for (const auto &m : m_macros)
            if (m.name == name) { macro = m; found = true; break; }
    }
    if (!found || macro.steps.isEmpty()) return false;
    // Replay the recorded login sequence (synchronous network I/O). Callers run
    // this off the proxy worker: the API dispatches it, the auto path via
    // maybeReauth's QtConcurrent task.
    const auto result = Nullock::Core::ChainRunner::run(macro.steps, /*continueOnError*/ false);
    if (result.vars.isEmpty()) return false;
    ingestVariables(macro.sessionHost, result.vars);
    emit sessionReauthed(macro.sessionHost, name);
    return true;
}

void SessionRules::maybeReauth(const QString &host,
                               const Nullock::Proxy::HttpResponse &resp) {
    constexpr qint64 kCooldownMs = 5000;   // never re-auth a host more than ~1x/5s
    QString macroName;
    {
        QMutexLocker lk(&m_mutex);
        if (m_macros.isEmpty()) return;
        const QString bodyText = QString::fromUtf8(resp.body.left(64 * 1024));
        for (const auto &m : m_macros) {
            if (m.sessionHost.isEmpty() || m.sessionHost != host) continue;
            if (m.loggedOutStatus.isEmpty() && m.loggedOutBodyRegex.isEmpty()) continue;
            if (!SessionRulesLogic::responseIsLoggedOut(resp.statusCode, bodyText,
                     m.loggedOutStatus, m.loggedOutBodyRegex))
                continue;
            if (m_reauthInFlight.contains(host)) return;    // already re-authing
            const qint64 now = QDateTime::currentMSecsSinceEpoch();
            if (now - m_lastReauthMs.value(host, 0) < kCooldownMs) return;   // cooldown
            macroName = m.name;
            m_reauthInFlight.insert(host);
            m_lastReauthMs[host] = now;
            break;
        }
    }
    if (macroName.isEmpty()) return;
    // Async so we never block the proxy worker on login I/O. The macro's OWN
    // requests use ChainRunner's client (not the proxy), so they never re-enter
    // applyToResponse -- no re-auth loop from the macro itself.
    const QString hostCopy = host;
    (void)QtConcurrent::run([this, macroName, hostCopy]() {
        runMacro(macroName);
        QMutexLocker lk(&m_mutex);
        m_reauthInFlight.remove(hostCopy);
    });
}

} // namespace Nullock::Core

#include "session_manager.hpp"

#include <QDateTime>
#include <QMutexLocker>

namespace Nullock::Core {

SessionManager::SessionManager(QObject *parent) : QObject(parent) {}

int SessionManager::hostCount() const {
    QMutexLocker lk(&m_mutex);
    return m_byHost.size();
}

QList<HostSession> SessionManager::sessions() const {
    QMutexLocker lk(&m_mutex);
    return m_byHost.values();
}

QStringList SessionManager::hosts() const {
    QMutexLocker lk(&m_mutex);
    return m_byHost.keys();
}

QString SessionManager::lowercaseHost(const QString &host) {
    return host.toLower();
}

// Strip CR / LF / NUL and other C0 control bytes. Hostile upstreams that
// embed \r\n in a Set-Cookie can otherwise cause us to write split
// headers back out on the next request (HTTP request smuggling).
static QString stripCtrl(QString s) {
    QString out;
    out.reserve(s.size());
    for (QChar c : s) {
        const ushort u = c.unicode();
        if (u == '\r' || u == '\n' || u == '\0') continue;
        if (u < 0x20) continue;     // other C0
        out.append(c);
    }
    return out;
}

CapturedCookie SessionManager::parseSetCookie(const QString &raw) {
    CapturedCookie c;
    c.raw = stripCtrl(raw);
    // First "key=value;" is the cookie itself; remaining "; attr[=val]"
    // segments are attributes.
    const QStringList parts = c.raw.split(';');
    if (parts.isEmpty()) return c;
    const QString first = parts.first().trimmed();
    const int eq = first.indexOf('=');
    if (eq <= 0) return c;
    c.name  = stripCtrl(first.left(eq).trimmed());
    c.value = stripCtrl(first.mid(eq + 1).trimmed());
    // The name must also be a "token" per RFC 6265; we don't enforce the
    // full grammar but at minimum reject names that contain '=' or any
    // whitespace -- they're meaningless and would produce a broken Cookie
    // header on inject.
    if (c.name.contains('=') || c.name.contains(' ') || c.name.contains('\t'))
        c.name.clear();
    for (int i = 1; i < parts.size(); ++i) {
        const QString seg = parts[i].trimmed();
        if (seg.isEmpty()) continue;
        const int eq2 = seg.indexOf('=');
        const QString key  = (eq2 < 0 ? seg : seg.left(eq2)).trimmed().toLower();
        const QString val  = eq2 < 0 ? QString() : seg.mid(eq2 + 1).trimmed();
        if      (key == "path")     c.path     = val;
        else if (key == "expires")  c.expires  = val;
        else if (key == "httponly") c.httpOnly = true;
        else if (key == "secure")   c.secure   = true;
        else if (key == "samesite") c.sameSite = val;
    }
    return c;
}

void SessionManager::onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                                        const Nullock::Proxy::HttpResponse &resp) {
    if (req.method.startsWith("WS")) return;       // skip WebSocket entries
    if (req.host.isEmpty()) return;

    QList<CapturedCookie> fresh;
    for (const auto &h : resp.headers) {
        if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
        const CapturedCookie c = parseSetCookie(h.second);
        if (!c.name.isEmpty()) fresh.append(c);
    }
    if (fresh.isEmpty()) return;

    const QString hostKey = lowercaseHost(req.host);
    {
        QMutexLocker lk(&m_mutex);
        HostSession &s = m_byHost[hostKey];
        s.host     = req.host;
        s.lastSeen = QDateTime::currentMSecsSinceEpoch();
        // Merge: replace existing cookies by name, append new ones. Keeps
        // the bag size bounded by distinct cookie names per host. Hard
        // cap at 256 -- a hostile upstream emitting thousands of distinct
        // Set-Cookie names should not be allowed to grow our hash
        // unboundedly (O(n) per insert with the same lock held).
        constexpr int kMaxCookiesPerHost = 256;
        for (const auto &c : fresh) {
            bool replaced = false;
            for (auto &existing : s.cookies) {
                if (existing.name == c.name) {
                    existing = c;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                if (s.cookies.size() >= kMaxCookiesPerHost) {
                    // Drop the oldest (front) to make room. Cheap LRU.
                    s.cookies.removeFirst();
                }
                s.cookies.append(c);
            }
        }
    }
    emit sessionsChanged();
}

void SessionManager::injectInto(Nullock::Proxy::HttpRequest &req) const {
    if (req.host.isEmpty()) return;
    QList<CapturedCookie> use;
    {
        QMutexLocker lk(&m_mutex);
        auto it = m_byHost.constFind(lowercaseHost(req.host));
        if (it == m_byHost.constEnd()) return;
        if (!it->autoInject) return;
        use = it->cookies;
    }
    if (use.isEmpty()) return;

    // Find or create the request's Cookie header. Build a map of
    // existing cookies so the client's values stay on conflict-free
    // names; server-side captured cookies override on same-name.
    QHash<QString, QString> jar;
    int existingIdx = -1;
    for (int i = 0; i < req.headers.size(); ++i) {
        if (req.headers[i].first.compare("Cookie", Qt::CaseInsensitive) == 0) {
            existingIdx = i;
            const QStringList parts = req.headers[i].second.split(';');
            for (const QString &p : parts) {
                const QString s = p.trimmed();
                const int eq = s.indexOf('=');
                if (eq <= 0) continue;
                jar.insert(s.left(eq).trimmed(), s.mid(eq + 1).trimmed());
            }
            break;
        }
    }
    // Captured cookies overwrite.
    for (const auto &c : use) jar.insert(c.name, c.value);

    QStringList combined;
    for (auto it = jar.constBegin(); it != jar.constEnd(); ++it)
        combined.append(it.key() + "=" + it.value());
    const QString joined = combined.join("; ");

    if (existingIdx >= 0) req.headers[existingIdx].second = joined;
    else                  req.headers.append({ "Cookie", joined });
}

bool SessionManager::setAutoInject(const QString &host, bool on) {
    const QString key = lowercaseHost(host);
    bool changed = false;
    {
        QMutexLocker lk(&m_mutex);
        auto it = m_byHost.find(key);
        if (it == m_byHost.end()) return false;
        if (it->autoInject != on) { it->autoInject = on; changed = true; }
    }
    if (changed) emit sessionsChanged();
    return true;
}

bool SessionManager::clearHost(const QString &host) {
    bool removed = false;
    {
        QMutexLocker lk(&m_mutex);
        removed = (m_byHost.remove(lowercaseHost(host)) > 0);
    }
    if (removed) emit sessionsChanged();
    return removed;
}

void SessionManager::clearAll() {
    {
        QMutexLocker lk(&m_mutex);
        m_byHost.clear();
    }
    emit sessionsChanged();
}

bool SessionManager::copyTo(const QString &fromHost, const QString &toHost) {
    bool ok = false;
    {
        QMutexLocker lk(&m_mutex);
        auto src = m_byHost.constFind(lowercaseHost(fromHost));
        if (src == m_byHost.constEnd()) return false;
        HostSession dst = src.value();
        dst.host     = toHost;
        dst.lastSeen = QDateTime::currentMSecsSinceEpoch();
        m_byHost.insert(lowercaseHost(toHost), dst);
        ok = true;
    }
    if (ok) emit sessionsChanged();
    return ok;
}

} // namespace Nullock::Core

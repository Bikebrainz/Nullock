#include "session_manager.hpp"

#include <QDateTime>
#include <QJsonObject>
#include <QJsonValue>
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

// stripCtrl()/parseSetCookie() + the pure inject-decision helpers (pathMatches,
// injectableOverTransport) live in session_manager_logic.cpp so they can be
// unit-tested against Qt6::Core alone. This TU keeps the QObject + I/O.

void SessionManager::onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                                        const Nullock::Proxy::HttpResponse &resp) {
    if (req.method.startsWith("WS")) return;       // skip WebSocket entries
    if (req.host.isEmpty()) return;

    QList<CapturedCookie> fresh;
    // One capture timestamp for the whole response: resolveCookieExpiry turns a
    // Max-Age delta into an absolute expiry relative to THIS moment, and the
    // deletion check below reuses it so both agree.
    const qint64 nowSec = QDateTime::currentSecsSinceEpoch();
    for (const auto &h : resp.headers) {
        if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
        CapturedCookie c = SessionLogic::parseSetCookie(h.second);
        if (c.name.isEmpty()) continue;
        SessionLogic::resolveCookieExpiry(c, nowSec);   // fill persistent / expiresEpoch
        fresh.append(c);
    }
    if (fresh.isEmpty()) return;

    const QString hostKey = lowercaseHost(req.host);
    {
        QMutexLocker lk(&m_mutex);
        // Bound the number of distinct hosts retained: the page chooses which
        // origins to fetch, so a hostile page fanning out to thousands of
        // subdomains could otherwise grow this map unboundedly (every sibling
        // store in the codebase is capped). Evict the least-recently-seen host
        // (LRU by lastSeen) when a NEW host would exceed the cap.
        constexpr int kMaxHosts = 4096;
        if (!m_byHost.contains(hostKey) && m_byHost.size() >= kMaxHosts) {
            QString oldestKey;
            qint64 oldest = QDateTime::currentMSecsSinceEpoch() + 1;   // > any existing lastSeen
            for (auto it = m_byHost.constBegin(); it != m_byHost.constEnd(); ++it) {
                if (it.value().lastSeen < oldest) { oldest = it.value().lastSeen; oldestKey = it.key(); }
            }
            if (!oldestKey.isEmpty()) m_byHost.remove(oldestKey);
        }
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
            // A freshly-set cookie that is ALREADY expired (Max-Age <= 0, or a
            // past Expires) is a DELETION -- this is how a server logs you out.
            // Drop any stored cookie of that name and do NOT store the new one.
            if (SessionLogic::cookieExpired(c, nowSec)) {
                for (int i = 0; i < s.cookies.size(); ++i) {
                    if (s.cookies[i].name == c.name) { s.cookies.removeAt(i); break; }
                }
                continue;
            }
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

    // Build the outgoing cookie list in a DETERMINISTIC order: the client's
    // existing cookies in their original order, then captured cookies in capture
    // order, captured overriding the client value on a same-name (kept in the
    // client's position). A QHash join order was non-deterministic -- a fingerprint
    // tell and non-reproducible. Each captured cookie is gated:
    //   * Secure cookies are NOT injected over a non-TLS request (cleartext leak);
    //   * a Path-scoped cookie is NOT injected onto a non-matching request path.
    QList<QPair<QString, QString>> ordered;   // (name, value) in emit order
    QHash<QString, int> pos;                   // name -> index into `ordered`
    int existingIdx = -1;
    for (int i = 0; i < req.headers.size(); ++i) {
        if (req.headers[i].first.compare("Cookie", Qt::CaseInsensitive) == 0) {
            existingIdx = i;
            const QStringList parts = req.headers[i].second.split(';');
            for (const QString &p : parts) {
                const QString s = p.trimmed();
                const int eq = s.indexOf('=');
                if (eq <= 0) continue;
                const QString n = s.left(eq).trimmed();
                pos[n] = ordered.size();
                ordered.append({ n, s.mid(eq + 1).trimmed() });
            }
            break;
        }
    }
    const qint64 nowSec = QDateTime::currentSecsSinceEpoch();
    for (const auto &c : use) {
        if (SessionLogic::cookieExpired(c, nowSec))               continue;  // past its Max-Age/Expires -> never replay
        if (!SessionLogic::injectableOverTransport(c, req.tls)) continue;   // Secure over cleartext -> skip
        if (!SessionLogic::pathMatches(c.path, req.path))         continue;  // path-scope mismatch -> skip
        auto f = pos.find(c.name);
        if (f != pos.end()) ordered[f.value()].second = c.value;            // override, keep position
        else { pos[c.name] = ordered.size(); ordered.append({ c.name, c.value }); }
    }

    QStringList combined;
    for (const auto &kv : ordered) combined.append(kv.first + "=" + kv.second);
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
        removed = m_byHost.remove(lowercaseHost(host));   // Qt6 QHash::remove returns bool
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

QJsonArray SessionManager::exportJson() const {
    QMutexLocker lk(&m_mutex);
    QJsonArray arr;
    for (auto it = m_byHost.cbegin(); it != m_byHost.cend(); ++it) {
        const HostSession &hs = it.value();
        QJsonArray cookies;
        for (const CapturedCookie &c : hs.cookies)
            cookies.append(SessionLogic::cookieToJson(c));
        arr.append(QJsonObject{
            { "host", hs.host }, { "autoInject", hs.autoInject },
            { "lastSeen", QString::number(hs.lastSeen) }, { "cookies", cookies } });
    }
    return arr;
}

void SessionManager::importJson(const QJsonArray &arr, long long nowEpoch) {
    {
        QMutexLocker lk(&m_mutex);
        m_byHost.clear();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            HostSession hs;
            hs.host = o.value("host").toString();
            if (hs.host.isEmpty()) continue;
            hs.autoInject = o.value("autoInject").toBool(false);
            hs.lastSeen   = o.value("lastSeen").toString().toLongLong();
            for (const QJsonValue &cv : o.value("cookies").toArray()) {
                CapturedCookie c = SessionLogic::cookieFromJson(cv.toObject());
                if (SessionLogic::cookieExpired(c, nowEpoch)) continue;   // drop stale/logged-out
                hs.cookies.append(c);
            }
            m_byHost.insert(hs.host, hs);
        }
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

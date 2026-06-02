#pragma once

#include "proxy_server.hpp"

#include <QHash>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Core {

// One captured cookie. Per-host (key is `host`), per-name. Holds the raw
// `Set-Cookie:` value plus the parsed name=value pair so we can both
// display it and re-inject it on outgoing requests.
struct CapturedCookie {
    QString name;
    QString value;
    QString raw;          // full Set-Cookie value (everything after the colon)
    QString path;
    QString expires;
    bool    httpOnly = false;
    bool    secure   = false;
    QString sameSite;
};

// Per-host session bag. We currently key on `host` only -- domain
// inheritance (cookies on .example.com applying to api.example.com)
// is intentionally simple, since the typical Burp workflow is one
// target host anyway. Users can still copy a cookie to another host
// via the UI if they need cross-subdomain.
struct HostSession {
    QString                  host;
    QList<CapturedCookie>    cookies;
    bool                     autoInject = false;  // gate for outgoing rewrite
    qint64                   lastSeen   = 0;      // ms since epoch
};

class SessionManager : public QObject {
    Q_OBJECT
    Q_PROPERTY(int hostCount READ hostCount NOTIFY sessionsChanged)
public:
    explicit SessionManager(QObject *parent = nullptr);

    int  hostCount() const;
    QList<HostSession> sessions() const;
    QStringList hosts() const;

    // ---- mutation API (UI / control server / scripts) ------------
    Q_INVOKABLE bool setAutoInject(const QString &host, bool on);
    Q_INVOKABLE bool clearHost(const QString &host);
    Q_INVOKABLE void clearAll();
    // Copy session from one host to another -- subdomain coverage when
    // the user knows the wildcard should apply.
    Q_INVOKABLE bool copyTo(const QString &fromHost, const QString &toHost);

public slots:
    // Wired to ProxyServer::responseReceived. Walks `Set-Cookie` headers,
    // updates the per-host bag.
    void onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                            const Nullock::Proxy::HttpResponse &resp);

signals:
    void sessionsChanged();

public:
    // ---- outgoing rewrite hook -----------------------------------
    // Called by ProxyServer::applyRequestRules (right after match&replace).
    // If autoInject is on for this host, ensures the request's Cookie
    // header contains the captured name=value pairs, MERGING with any
    // cookies the client already sent (server-side wins on conflict).
    void injectInto(Nullock::Proxy::HttpRequest &req) const;

private:
    static CapturedCookie parseSetCookie(const QString &raw);
    static QString lowercaseHost(const QString &host);

    mutable QMutex                   m_mutex;
    QHash<QString, HostSession>      m_byHost;
};

} // namespace Nullock::Core

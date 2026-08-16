#pragma once

// Out-of-band Application Security Testing (OAST) sink. Equivalent to
// Burp Collaborator's HTTP-side. The idea:
//
//   1. We listen on a known port for HTTP requests.
//   2. The user (or an active probe) generates a fresh token, then
//      embeds a URL like http://<token>.<bind-host>:<port>/ into a
//      payload that gets fired at a target.
//   3. If the target is vulnerable to SSRF / blind-redirect / blind
//      XXE / log4j-style RCE / OOB-DNS-resolving SQLi, it eventually
//      makes a request to that URL.
//   4. OastServer logs the hit. Polling /api/oast/poll surfaces it.
//      The token in the URL ties the hit back to the originating row.
//
// This is the HTTP-only half of Collaborator -- DNS callbacks would
// need a real DNS server reachable from the public internet, which is
// a deployment concern beyond what a self-host-first tool can ship.
// For purely internal testing (lab targets, internal networks), HTTP
// callbacks are sufficient and need no public infrastructure.
//
// Security posture: this server accepts ANY inbound request and logs
// it. Bind to a LAN address (or behind a tunnel) -- never bind to a
// public interface without rate-limiting in front, or anyone on the
// internet can pollute your callback log.

#include <QHostAddress>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

class QTcpServer;
class QTcpSocket;
class QTimer;
class QNetworkAccessManager;

namespace Nullock::Core {

struct OastHit {
    qint64     id          = 0;
    qint64     atMs        = 0;
    QString    token;        // extracted from subdomain or first path segment
    QString    sourceIp;
    QString    method;
    QString    hostHeader;
    QString    path;
    int        bodyBytes   = 0;
    QString    userAgent;
    QString    bodyPreview; // first 4 KB, UTF-8 best-effort
};

class OastServer : public QObject {
    Q_OBJECT
public:
    explicit OastServer(QObject *parent = nullptr);
    ~OastServer() override;

    // Start the HTTP listener. baseHost is what we'll embed into
    // generated callback URLs (e.g. "192.168.1.42" for LAN testing or
    // "oast.example.com" if a real DNS wildcard points at this box).
    // Returns the bound port, or 0 on failure.
    quint16 start(quint16 port, const QString &baseHost);
    void    stop();
    bool    running() const;

    // CLIENT MODE. Instead of running a local sink, point at a REMOTE nullock-oast
    // admin API (base = "http://host:adminPort", key = its admin key). mintToken()
    // then proxies to the remote's POST /mint (so callback URLs carry the remote's
    // public host), and a poll timer pulls GET /poll and re-emits each hit via
    // hitReceived exactly like the local sink -- so OastCorrelator and every
    // /api/oast/* endpoint work unchanged against a hosted Collaborator. Does a
    // synchronous GET /healthz first to learn the remote's baseHost/port; returns
    // false (and stays in local-capable state) if the remote is unreachable.
    bool    startRemote(const QString &base, const QString &key, int pollMs = 3000);
    bool    remoteMode() const { return m_remoteMode; }

    // Mint a fresh 16-char hex token + the full base URL for embedding
    // into a payload. The token is what we'll look for in the inbound
    // Host header or first path segment.
    Q_INVOKABLE QJsonObject mintToken();

    // Return hits with id strictly greater than sinceId.
    QList<OastHit> hitsSince(qint64 sinceId) const;
    int            hitCount() const;
    quint16        port() const;
    QString        baseHost() const;

signals:
    void hitReceived(const OastHit &hit);

private slots:
    void onNewConnection();
    void pollRemote();

private:
    void   handleClient(QTcpSocket *socket);
    static QString extractToken(const QString &hostHeader, const QString &path);
    // Blocking HTTP request to the remote admin API (nested event loop). Returns
    // the parsed JSON object, or an object with ok=false on any failure.
    QJsonObject remoteRequest(const QString &httpMethod, const QString &pathAndQuery,
                              int timeoutMs = 6000);

    QTcpServer    *m_server    = nullptr;
    QString        m_baseHost;
    mutable QMutex m_mutex;
    QList<OastHit> m_hits;          // ring; we cap at kMaxHits
    qint64         m_nextHitId = 1;
    static constexpr int kMaxHits = 1000;

    // Client mode: poll a remote nullock-oast instead of listening locally.
    bool                   m_remoteMode  = false;
    QString                m_remoteBase;         // e.g. "http://host:8889" (no trailing /)
    QString                m_remoteKey;
    quint16                m_remotePort  = 0;    // remote's callback port (from /healthz)
    qint64                 m_remoteSince = 0;    // remote hit-id watermark for /poll?since=
    QNetworkAccessManager *m_nam         = nullptr;
    QTimer                *m_pollTimer   = nullptr;
};

} // namespace Nullock::Core

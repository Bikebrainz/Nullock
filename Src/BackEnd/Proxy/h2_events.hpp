#pragma once

// HTTP/2 frame-level visibility. Bridges the libnghttp2 callbacks in
// H2Client into a control-API-readable event log so the user can
// inspect stream-level h2 behaviour: SETTINGS exchange, stream
// HEADERS, DATA byte counts, RST_STREAM (with error code), GOAWAY,
// WINDOW_UPDATE, PRIORITY changes.
//
// What this gives the user vs the current h1-shaped capture:
//   * Distinguish stream multiplexing from sequential requests
//   * See server-pushed PRIORITY orderings
//   * See exactly why a stream got RST_STREAM'd (flow control? cancel?)
//   * Surface SETTINGS / WINDOW_UPDATE asymmetry that flags weird WAF
//     behaviour
//
// Per-connection state is held in H2EventLog as a ring of
// kMaxEventsPerConn events; rolling buffer behaviour mirrors
// WsRepeater so attacker bytes can't pin RAM.

#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Proxy {

struct H2Event {
    qint64  ts;            // epoch ms
    QString conn;          // connection id (typically host:port)
    quint8  frameType;     // 0=DATA 1=HEADERS 2=PRIORITY 3=RST_STREAM
                           // 4=SETTINGS 5=PUSH_PROMISE 6=PING 7=GOAWAY
                           // 8=WINDOW_UPDATE 9=CONTINUATION
    quint8  flags;
    qint32  streamId;
    qint64  bytes;         // payload bytes
    quint32 errorCode;     // RST_STREAM / GOAWAY only
    QString summary;       // ":method GET" or ":status 200" -- header gist
};

struct H2StreamSummary {
    qint32  streamId  = 0;
    QString conn;
    QString method;
    QString path;
    int     status     = 0;
    qint64  bytesIn    = 0;
    qint64  bytesOut   = 0;
    int     framesIn   = 0;
    int     framesOut  = 0;
    quint32 lastError  = 0;
    qint64  openedAtMs = 0;
    bool    closed     = false;
};

class H2EventLog : public QObject {
    Q_OBJECT
public:
    static H2EventLog *instance();

    // Logged from H2Client's libnghttp2 callbacks.
    void noteFrame(const QString &conn, int frameType, int flags,
                   qint32 streamId, qint64 bytes, bool sent);
    void noteRequestHeader(const QString &conn, qint32 streamId,
                           const QString &method, const QString &path);
    void noteResponseStatus(const QString &conn, qint32 streamId, int status);
    void noteRstStream(const QString &conn, qint32 streamId, quint32 errCode);
    void noteStreamClosed(const QString &conn, qint32 streamId);

    QList<H2Event>         eventsSince(qint64 sinceTs) const;
    QList<H2StreamSummary> streams() const;

signals:
    void eventsChanged();

private:
    explicit H2EventLog(QObject *parent = nullptr) : QObject(parent) {}

    mutable QMutex                          m_mutex;
    QList<H2Event>                          m_events;
    QMap<QString, H2StreamSummary>          m_streams;   // key = conn|streamId
    static constexpr int kMaxEvents = 5000;
    static QString streamKey(const QString &conn, qint32 streamId);
};

} // namespace Nullock::Proxy

#pragma once

// WebSocket Repeater. Captures live WS tunnels by ID so the user can
// fire arbitrary frames into a still-open connection from the UI or
// from the control API. Daily-driver feature for testing modern apps
// whose protocol is mostly WS (chat, live trading, collaborative
// editors, anything LLM-streaming).
//
// Usage (server-side wiring):
//   1. In runWebSocketRelay, call WsRepeater::registerSession(...) right
//      before the event loop, deregisterSession(...) on disconnect.
//   2. The control server exposes:
//        GET  /api/ws/sessions
//        POST /api/ws/send { sessionId, direction, opcode, payload }
//      which both call into the singleton.

#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QObject>
#include <QPointer>
#include <QString>

class QTcpSocket;

namespace Nullock::Proxy {

struct WsSessionInfo {
    qint64     id = 0;
    QString    host;
    quint16    port = 0;
    qint64     openedAtMs = 0;
    qint64     framesUp = 0;
    qint64     framesDown = 0;
};

class WsRepeater : public QObject {
    Q_OBJECT
public:
    static WsRepeater *instance();

    // Returns a new session id. The sockets are recorded only so sessions()
    // can report the tunnel -- nothing here ever writes to them. See sendFrame.
    qint64 registerSession(QTcpSocket *client, QTcpSocket *upstream,
                           const QString &host, quint16 port);
    void   deregisterSession(qint64 id);

    // Increments per-session counters. Called from the relay's per-frame
    // emit so the UI can see throughput.
    void noteFrame(qint64 id, bool fromClient);

    QList<WsSessionInfo> sessions() const;

    /*
     *  Build an RFC 6455 frame and hand it to the relay that owns this session.
     *  Direction "up" means client->server (masked, like a real client would
     *  send); "down" means server->client (unmasked).
     *
     *  ASYNCHRONOUS, and it has to be. The sockets belong to their connection's
     *  worker thread, and this is called from the control server's thread, so
     *  there are only two ways to reach them and both are broken:
     *    * dispatch to the socket with a BlockingQueuedConnection WITHOUT holding
     *      m_mutex -- the socket can be destroyed between the lookup and the
     *      dispatch, so the receiver dangles. That is what this used to do.
     *    * hold m_mutex across that blocking dispatch -- now the socket cannot
     *      die, but the worker takes the SAME mutex in noteFrame(), so it blocks
     *      on us while we block on it. Deadlock.
     *  So the frame is emitted on frameQueued() instead and the relay, which
     *  lives on the owning thread and whose connection dies with it, does the
     *  write. No dangling receiver, no mutex held across threads, and the
     *  control server's own event loop no longer blocks on a worker.
     *
     *  Returns TRUE when the frame was queued for a live session, FALSE when no
     *  such session exists. It deliberately does NOT report whether the bytes
     *  reached the wire -- nothing at this end can know that synchronously.
    */
    Q_INVOKABLE bool sendFrame(qint64 id,
                               const QString &direction,
                               int opcode,
                               const QByteArray &payload);

signals:
    void sessionsChanged();

    // note: the relay for `id` connects to this with ITSELF as the context
    // object, so the connection is severed automatically when that connection
    // (and its sockets) are destroyed. That is what makes the write safe.
    void frameQueued(qint64 id, const QByteArray &bytes, bool toUpstream);

private:
    explicit WsRepeater(QObject *parent = nullptr) : QObject(parent) {}

    struct Entry {
        QPointer<QTcpSocket> client;
        QPointer<QTcpSocket> upstream;
        WsSessionInfo info;
    };

    static QByteArray buildFrame(quint8 opcode, const QByteArray &payload, bool mask);

    mutable QMutex m_mutex;
    QMap<qint64, Entry> m_sessions;
    qint64 m_nextId = 1;
};

} // namespace Nullock::Proxy

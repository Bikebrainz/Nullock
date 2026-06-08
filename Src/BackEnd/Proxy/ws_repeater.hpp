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

    // Returns a new session id. ownerThread is the thread the sockets
    // live on; sends marshal back to it via QMetaObject::invokeMethod.
    qint64 registerSession(QTcpSocket *client, QTcpSocket *upstream,
                           const QString &host, quint16 port);
    void   deregisterSession(qint64 id);

    // Increments per-session counters. Called from the relay's per-frame
    // emit so the UI can see throughput.
    void noteFrame(qint64 id, bool fromClient);

    QList<WsSessionInfo> sessions() const;

    // Build an RFC 6455 frame and write it to either the client-facing or
    // upstream-facing socket of the given session. Direction "up" means
    // client->server (frame is masked, like a real client would send).
    // Direction "down" means server->client (unmasked). Returns false if
    // the session doesn't exist or the socket is no longer connected.
    Q_INVOKABLE bool sendFrame(qint64 id,
                               const QString &direction,
                               int opcode,
                               const QByteArray &payload);

signals:
    void sessionsChanged();

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

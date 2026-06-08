#include "ws_repeater.hpp"

#include <QDateTime>
#include <QMetaObject>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QTcpSocket>
#include <QThread>

namespace Nullock::Proxy {

WsRepeater *WsRepeater::instance() {
    static WsRepeater r;
    return &r;
}

qint64 WsRepeater::registerSession(QTcpSocket *client, QTcpSocket *upstream,
                                   const QString &host, quint16 port) {
    qint64 id;
    {
        QMutexLocker lk(&m_mutex);
        id = m_nextId++;
        Entry e;
        e.client   = client;
        e.upstream = upstream;
        e.info.id  = id;
        e.info.host = host;
        e.info.port = port;
        e.info.openedAtMs = QDateTime::currentMSecsSinceEpoch();
        m_sessions.insert(id, e);
    }
    emit sessionsChanged();
    return id;
}

void WsRepeater::deregisterSession(qint64 id) {
    {
        QMutexLocker lk(&m_mutex);
        m_sessions.remove(id);
    }
    emit sessionsChanged();
}

void WsRepeater::noteFrame(qint64 id, bool fromClient) {
    {
        QMutexLocker lk(&m_mutex);
        auto it = m_sessions.find(id);
        if (it == m_sessions.end()) return;
        if (fromClient) ++it->info.framesUp;
        else            ++it->info.framesDown;
    }
    emit sessionsChanged();
}

QList<WsSessionInfo> WsRepeater::sessions() const {
    QMutexLocker lk(&m_mutex);
    QList<WsSessionInfo> out;
    out.reserve(m_sessions.size());
    for (const Entry &e : m_sessions) out.append(e.info);
    return out;
}

// RFC 6455 §5.2: frame format. We only ever build single-fragment
// frames (FIN=1). For client-direction writes we have to mask with a
// random 4-byte mask, because real WS clients always do; some servers
// abort the conn if they see unmasked client frames. For server
// direction we MUST NOT mask.
QByteArray WsRepeater::buildFrame(quint8 opcode, const QByteArray &payload, bool mask) {
    QByteArray out;
    out.reserve(payload.size() + 14);
    // FIN=1, RSV=0, opcode.
    out.append(static_cast<char>(0x80 | (opcode & 0x0F)));
    const qint64 len = payload.size();
    quint8 maskBit = mask ? 0x80 : 0x00;
    if (len < 126) {
        out.append(static_cast<char>(maskBit | static_cast<quint8>(len)));
    } else if (len <= 0xFFFF) {
        out.append(static_cast<char>(maskBit | 126));
        out.append(static_cast<char>((len >> 8) & 0xFF));
        out.append(static_cast<char>(len & 0xFF));
    } else {
        out.append(static_cast<char>(maskBit | 127));
        // 8-byte length, network order. Top bit must be 0 per RFC.
        for (int shift = 56; shift >= 0; shift -= 8)
            out.append(static_cast<char>((len >> shift) & 0xFF));
    }
    if (mask) {
        quint8 m[4];
        for (int i = 0; i < 4; ++i)
            m[i] = static_cast<quint8>(QRandomGenerator::global()->bounded(256));
        for (int i = 0; i < 4; ++i) out.append(static_cast<char>(m[i]));
        for (qint64 i = 0; i < len; ++i)
            out.append(static_cast<char>(static_cast<quint8>(payload.at(i)) ^ m[i & 3]));
    } else {
        out.append(payload);
    }
    return out;
}

bool WsRepeater::sendFrame(qint64 id, const QString &direction,
                           int opcode, const QByteArray &payload) {
    // Resolve session + which socket to write to.
    QPointer<QTcpSocket> target;
    bool clientToServer = direction.compare("up", Qt::CaseInsensitive) == 0
                       || direction.compare("client", Qt::CaseInsensitive) == 0
                       || direction.compare("upstream", Qt::CaseInsensitive) == 0;
    {
        QMutexLocker lk(&m_mutex);
        auto it = m_sessions.find(id);
        if (it == m_sessions.end()) return false;
        target = clientToServer ? it->upstream : it->client;
    }
    if (!target) return false;

    // Build the frame bytes. Client->server frames are masked; the
    // opposite direction is unmasked per RFC.
    const QByteArray bytes = buildFrame(
        static_cast<quint8>(opcode & 0x0F), payload, clientToServer);

    // Sockets live in their connection's thread (see runWebSocketRelay).
    // Marshal the write so the thread that owns the socket performs it.
    // If we're already on that thread, do a direct call -- otherwise
    // BlockingQueuedConnection would deadlock (queue at self).
    QTcpSocket *raw = target.data();
    auto write = [raw, bytes]() -> bool {
        if (!raw || raw->state() != QAbstractSocket::ConnectedState) return false;
        const qint64 written = raw->write(bytes);
        return (written == bytes.size());
    };
    if (raw->thread() == QThread::currentThread()) {
        return write();
    }
    bool ok = false;
    QMetaObject::invokeMethod(raw, [&ok, write]() { ok = write(); },
                              Qt::BlockingQueuedConnection);
    return ok;
}

} // namespace Nullock::Proxy

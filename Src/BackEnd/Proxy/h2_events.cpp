#include "h2_events.hpp"

#include "h2_logic.hpp"

#include <QDateTime>
#include <QMutexLocker>

namespace Nullock::Proxy {

H2EventLog *H2EventLog::instance() {
    static H2EventLog log;
    return &log;
}

QString H2EventLog::streamKey(const QString &conn, qint32 streamId) {
    return conn + "|" + QString::number(streamId);
}

void H2EventLog::noteFrame(const QString &conn, int frameType, int flags,
                           qint32 streamId, qint64 bytes, bool sent) {
    {
        QMutexLocker lk(&m_mutex);
        H2Event e;
        e.ts        = QDateTime::currentMSecsSinceEpoch();
        e.conn      = conn;
        e.frameType = static_cast<quint8>(frameType);
        e.flags     = static_cast<quint8>(flags);
        e.streamId  = streamId;
        e.bytes     = bytes;
        e.errorCode = 0;
        m_events.append(e);
        while (m_events.size() > kMaxEvents) m_events.removeFirst();

        if (streamId > 0) {
            const QString k = streamKey(conn, streamId);
            auto it = m_streams.find(k);
            if (it == m_streams.end()) {
                H2StreamSummary s;
                s.streamId  = streamId;
                s.conn      = conn;
                s.openedAtMs = e.ts;
                it = m_streams.insert(k, s);
            }
            if (sent) { it->bytesOut += bytes; ++it->framesOut; }
            else      { it->bytesIn  += bytes; ++it->framesIn;  }
        }
        H2Logic::capStreamSummaries(m_streams, H2Logic::kMaxStreams);
    }
    emit eventsChanged();
}

void H2EventLog::noteRequestHeader(const QString &conn, qint32 streamId,
                                   const QString &method, const QString &path) {
    {
        QMutexLocker lk(&m_mutex);
        const QString k = streamKey(conn, streamId);
        auto &s = m_streams[k];
        s.streamId = streamId;
        s.conn     = conn;
        // :method / :path are untrusted proxied bytes -- clamp before storing.
        s.method   = H2Logic::clampTelemetryField(method, H2Logic::kMaxTelemetryFieldLen);
        s.path     = H2Logic::clampTelemetryField(path,   H2Logic::kMaxTelemetryFieldLen);
        if (s.openedAtMs == 0) s.openedAtMs = QDateTime::currentMSecsSinceEpoch();
        H2Logic::capStreamSummaries(m_streams, H2Logic::kMaxStreams);
    }
    emit eventsChanged();
}

void H2EventLog::noteResponseStatus(const QString &conn, qint32 streamId, int status) {
    {
        QMutexLocker lk(&m_mutex);
        const QString k = streamKey(conn, streamId);
        m_streams[k].status = status;
        H2Logic::capStreamSummaries(m_streams, H2Logic::kMaxStreams);
    }
    emit eventsChanged();
}

void H2EventLog::noteRstStream(const QString &conn, qint32 streamId, quint32 errCode) {
    {
        QMutexLocker lk(&m_mutex);
        const QString k = streamKey(conn, streamId);
        m_streams[k].lastError = errCode;
        m_streams[k].closed    = true;
        // Stamp the errorCode onto THIS stream's RST event, not just whatever
        // frame happens to be last: with concurrent multiplexed streams another
        // stream's frame can land between the RST's noteFrame and this call.
        // Scan back for the matching (conn, streamId, RST=3) event.
        for (int i = m_events.size() - 1; i >= 0; --i) {
            H2Event &e = m_events[i];
            if (e.frameType == 3 && e.streamId == streamId && e.conn == conn) {
                e.errorCode = errCode;
                break;
            }
        }
        H2Logic::capStreamSummaries(m_streams, H2Logic::kMaxStreams);
    }
    emit eventsChanged();
}

void H2EventLog::noteStreamClosed(const QString &conn, qint32 streamId) {
    {
        QMutexLocker lk(&m_mutex);
        m_streams[streamKey(conn, streamId)].closed = true;
        H2Logic::capStreamSummaries(m_streams, H2Logic::kMaxStreams);
    }
    emit eventsChanged();
}

QList<H2Event> H2EventLog::eventsSince(qint64 sinceTs) const {
    QMutexLocker lk(&m_mutex);
    QList<H2Event> out;
    for (const auto &e : m_events)
        if (e.ts > sinceTs) out.append(e);
    return out;
}

QList<H2StreamSummary> H2EventLog::streams() const {
    QMutexLocker lk(&m_mutex);
    return m_streams.values();
}

} // namespace Nullock::Proxy

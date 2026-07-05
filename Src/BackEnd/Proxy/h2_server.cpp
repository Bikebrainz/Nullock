#include "h2_server.hpp"
#include "h2_server_logic.hpp"
#include "h2_events.hpp"

#include <QByteArray>
#include <QElapsedTimer>
#include <QSslSocket>

#ifdef _MSC_VER
#  include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#include <nghttp2/nghttp2.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

namespace Nullock::Proxy {

namespace {

constexpr int    kReadTimeoutMs         = 15'000;
constexpr int    kTotalDeadlineMs       = 300'000;             // whole-tunnel backstop
constexpr int    kMaxServerStreams      = 128;                 // concurrent browser streams
constexpr qint64 kMaxServerReqBody      = 8LL * 1024 * 1024;   // per-request body cap
// Aggregate request-body buffering across ALL of this connection's streams. The
// browser is the UNTRUSTED peer in a MITM; a per-stream cap alone lets 128
// streams * per-stream cap pin gigabytes, so bound the sum too.
constexpr qint64 kMaxServerBufferedBytes = 128LL * 1024 * 1024;

// One browser request stream. Its address is the nghttp2 stream_user_data, so it
// is owned via unique_ptr in a std::map (node-stable) -- never a vector.
struct ServerStream {
    int32_t   streamId = -1;
    QList<QPair<QString, QString>> headers;   // received h2 headers (pseudo+regular)
    QByteArray reqBody;
    bool       requestDone = false;
    // response body, streamed back via the data provider.
    QByteArray respBody;
    qsizetype  respOffset = 0;
};

struct ServerSession {
    QString connName;
    std::map<int32_t, std::unique_ptr<ServerStream>> streams;
    QList<int32_t> readyQueue;   // streams whose request just completed
    qint64 bufferedBytes = 0;    // sum of all streams' buffered request bodies
    bool fatal = false;
};

ServerStream *streamOf(nghttp2_session *s, int32_t id) {
    return static_cast<ServerStream *>(nghttp2_session_get_stream_user_data(s, id));
}

int onBeginHeaders(nghttp2_session *session, const nghttp2_frame *frame, void *user) {
    if (frame->hd.type != NGHTTP2_HEADERS
        || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    auto *sess = static_cast<ServerSession *>(user);
    if (sess->streams.size() >= size_t(kMaxServerStreams)) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                                  NGHTTP2_REFUSED_STREAM);
        return 0;
    }
    auto st = std::make_unique<ServerStream>();
    st->streamId = frame->hd.stream_id;
    ServerStream *raw = st.get();
    sess->streams.emplace(frame->hd.stream_id, std::move(st));
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, raw);
    return 0;
}

int onHeader(nghttp2_session *session, const nghttp2_frame *frame,
             const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen, uint8_t, void *) {
    ServerStream *st = streamOf(session, frame->hd.stream_id);
    if (!st) return 0;
    st->headers.append({ QString::fromUtf8(reinterpret_cast<const char *>(name), int(namelen)),
                         QString::fromUtf8(reinterpret_cast<const char *>(value), int(valuelen)) });
    return 0;
}

int onDataChunk(nghttp2_session *session, uint8_t, int32_t streamId,
                const uint8_t *data, size_t len, void *user) {
    auto *sess = static_cast<ServerSession *>(user);
    ServerStream *st = streamOf(session, streamId);
    if (!st) return 0;
    // Bound BOTH the per-stream body and the connection-wide aggregate.
    if (st->reqBody.size() + qint64(len) > kMaxServerReqBody
        || sess->bufferedBytes + qint64(len) > kMaxServerBufferedBytes) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, streamId,
                                  NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }
    st->reqBody.append(reinterpret_cast<const char *>(data), int(len));
    sess->bufferedBytes += qint64(len);
    return 0;
}

int onFrameRecv(nghttp2_session *session, const nghttp2_frame *frame, void *user) {
    auto *sess = static_cast<ServerSession *>(user);
    H2EventLog::instance()->noteFrame(sess->connName, frame->hd.type, frame->hd.flags,
                                      frame->hd.stream_id,
                                      static_cast<qint64>(frame->hd.length), /*sent=*/false);
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        && (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA)) {
        ServerStream *st = streamOf(session, frame->hd.stream_id);
        if (st && !st->requestDone) {
            st->requestDone = true;
            sess->readyQueue.append(frame->hd.stream_id);
        }
    }
    return 0;
}

int onStreamClose(nghttp2_session *, int32_t streamId, uint32_t, void *user) {
    auto *sess = static_cast<ServerSession *>(user);
    // Called after the response is fully sent + the stream is closed; the response
    // data provider is done reading respBody, so it is safe to free the stream.
    auto it = sess->streams.find(streamId);
    if (it != sess->streams.end()) {
        sess->bufferedBytes -= it->second->reqBody.size();   // release its buffered body
        sess->streams.erase(it);
    }
    return 0;
}

ssize_t respRead(nghttp2_session *session, int32_t streamId, uint8_t *buf, size_t length,
                 uint32_t *data_flags, nghttp2_data_source *, void *) {
    ServerStream *st = streamOf(session, streamId);
    if (!st) { *data_flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
    const qsizetype remaining = st->respBody.size() - st->respOffset;
    const qsizetype toCopy = qMin(static_cast<qsizetype>(length), remaining);
    if (toCopy > 0) {
        std::memcpy(buf, st->respBody.constData() + st->respOffset, size_t(toCopy));
        st->respOffset += toCopy;
    }
    if (st->respOffset >= st->respBody.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(toCopy);
}

bool drainToBrowser(nghttp2_session *session, QSslSocket *sock, ServerSession &sess) {
    bool wrote = false;
    for (;;) {
        const uint8_t *out = nullptr;
        const ssize_t produced = nghttp2_session_mem_send(session, &out);
        if (produced < 0) { sess.fatal = true; return false; }
        if (produced == 0) break;
        if (sock->write(reinterpret_cast<const char *>(out), qint64(produced)) != qint64(produced)) {
            sess.fatal = true; return false;
        }
        wrote = true;
    }
    if (wrote) sock->waitForBytesWritten(kReadTimeoutMs);
    return true;
}

} // namespace

void H2Terminator::run(QSslSocket *browser, const QString &connName,
                       const UpstreamFn &upstream) {
    nghttp2_session_callbacks *cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) return;
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, onBeginHeaders);
    nghttp2_session_callbacks_set_on_header_callback(cbs, onHeader);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, onFrameRecv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClose);

    ServerSession sess;
    sess.connName = connName;
    nghttp2_session *session = nullptr;
    if (nghttp2_session_server_new(&session, cbs, &sess) != 0) {
        nghttp2_session_callbacks_del(cbs);
        return;
    }

    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 24 },
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kMaxServerStreams },
        { NGHTTP2_SETTINGS_ENABLE_PUSH,            0 },
    };
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(iv[0]));
    // Raise the CONNECTION-level receive window to match the per-stream one
    // (stream 0). Without this the connection window stays at the 64 KiB default
    // and throttles a large request body regardless of the per-stream setting.
    nghttp2_session_set_local_window_size(session, NGHTTP2_FLAG_NONE, 0, 1 << 24);
    if (!drainToBrowser(session, browser, sess)) { /* fall through to teardown */ }

    QElapsedTimer clock;
    clock.start();
    while (!sess.fatal && browser->state() == QAbstractSocket::ConnectedState) {
        if (clock.hasExpired(kTotalDeadlineMs)) break;

        if (browser->bytesAvailable() == 0 && !browser->waitForReadyRead(kReadTimeoutMs))
            break;   // idle close / timeout
        const QByteArray buf = browser->readAll();
        if (buf.isEmpty()) {
            if (browser->state() != QAbstractSocket::ConnectedState) break;
            continue;
        }
        const ssize_t consumed = nghttp2_session_mem_recv(
            session, reinterpret_cast<const uint8_t *>(buf.constData()), size_t(buf.size()));
        if (consumed < 0) { sess.fatal = true; break; }

        // Fulfill each request that completed this round (sequentially upstream).
        const QList<int32_t> ready = sess.readyQueue;
        sess.readyQueue.clear();
        for (const int32_t sid : ready) {
            // The deadline is a true backstop even inside a long ready queue.
            if (clock.hasExpired(kTotalDeadlineMs)) { sess.fatal = true; break; }
            auto it = sess.streams.find(sid);
            if (it == sess.streams.end()) continue;
            ServerStream *st = it->second.get();

            HttpResponse resp;
            const H2Terminator::UpstreamOutcome uo = upstream(st->headers, st->reqBody, resp);
            if (uo == H2Terminator::UpstreamOutcome::TunnelDead) {
                // The upstream connection itself died -- tearing down the browser
                // tunnel (vs. RST-storming every future stream) lets it reconnect
                // with a fresh upstream session.
                sess.fatal = true;
                break;
            }
            if (uo == H2Terminator::UpstreamOutcome::RejectStream) {
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, sid, NGHTTP2_INTERNAL_ERROR);
                continue;
            }
            st->respBody = resp.body;
            st->respOffset = 0;

            const auto nvList = H2ServerLogic::responseHeaders(resp.statusCode, resp.headers);
            std::vector<nghttp2_nv> nvs;
            nvs.reserve(nvList.size());
            for (const auto &h : nvList) {
                nghttp2_nv nv;
                nv.name     = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(h.name.constData()));
                nv.namelen  = size_t(h.name.size());
                nv.value    = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(h.value.constData()));
                nv.valuelen = size_t(h.value.size());
                nv.flags    = NGHTTP2_NV_FLAG_NONE;
                nvs.push_back(nv);
            }
            nghttp2_data_provider dp;
            dp.source.ptr = st;
            dp.read_callback = respRead;
            nghttp2_data_provider *dpPtr = st->respBody.isEmpty() ? nullptr : &dp;
            nghttp2_submit_response(session, sid, nvs.data(), nvs.size(), dpPtr);
            H2EventLog::instance()->noteResponseStatus(sess.connName, sid, resp.statusCode);
        }

        if (!drainToBrowser(session, browser, sess)) break;   // flush responses
    }

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(cbs);
}

} // namespace Nullock::Proxy

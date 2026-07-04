#include "http2_client.hpp"
#include "h2_events.hpp"
#include "h2_client_logic.hpp"

#include <QByteArray>
#include <QElapsedTimer>
#include <QList>
#include <QPair>
#include <QSslSocket>
#include <QString>

// MSVC has no <sys/types.h> ssize_t but does ship SSIZE_T in BaseTsd.h.
// Define ssize_t before pulling in <nghttp2/nghttp2.h> so its function
// signatures that use ssize_t compile cleanly.
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

constexpr int    kReadTimeoutMs             = 15'000;            // per blocking wait
constexpr int    kTotalDeadlineMs           = 120'000;          // whole-batch backstop
constexpr int    kMaxConcurrentStreamsLocal = 64;                  // >= advertised 16
constexpr qint64 kMaxBodyBytesPerStream     = 64LL * 1024 * 1024;  // per-stream DoS guard

using H2ClientLogic::PumpAction;

// Per-stream mutable state. Its ADDRESS is handed to nghttp2 as stream_user_data,
// so it must stay stable for the stream's whole life. It is therefore owned via
// unique_ptr inside a std::map (node addresses are stable across other inserts /
// erases). NEVER store these in a vector/QList -- reallocation would dangle every
// outstanding nghttp2 pointer and UAF inside a callback.
struct StreamState {
    int32_t   streamId = -1;
    bool      done = false;
    bool      headersComplete = false;
    bool      hadError = false;
    QString   errorMessage;
    int       statusCode = 0;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
    qint64    bodyBytes = 0;          // accumulated received body, for the cap

    // Outbound body cursor (per-stream; nghttp2 pulls this during the pump).
    const QByteArray *reqBody = nullptr;
    qsizetype reqOffset = 0;

    int resultIndex = -1;            // maps back to the caller's request order
};

// Whole-session state; its address is the nghttp2 session user_data.
struct SessionState {
    QString connName;
    std::map<int32_t, std::unique_ptr<StreamState>> streams;   // stable addresses
    int     openStreams = 0;
    bool    fatal = false;
    QString fatalMessage;
};

// Route a callback to its stream via nghttp2's per-stream user_data (set at
// submit_request time) -- no more brittle "== the one stream id" guards.
StreamState *streamOf(nghttp2_session *session, int32_t streamId) {
    return static_cast<StreamState *>(
        nghttp2_session_get_stream_user_data(session, streamId));
}

int onHeader(nghttp2_session *session, const nghttp2_frame *frame,
             const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen,
             uint8_t /*flags*/, void * /*userData*/) {
    StreamState *st = streamOf(session, frame->hd.stream_id);
    if (!st) return 0;
    const QString n = QString::fromUtf8(reinterpret_cast<const char *>(name), int(namelen));
    const QString v = QString::fromUtf8(reinterpret_cast<const char *>(value), int(valuelen));
    if (n == QLatin1String(":status")) st->statusCode = v.toInt();
    else if (!n.startsWith(QLatin1Char(':'))) st->headers.append({ n, v });
    return 0;
}

int onDataChunk(nghttp2_session *session, uint8_t /*flags*/, int32_t streamId,
                const uint8_t *data, size_t len, void * /*userData*/) {
    StreamState *st = streamOf(session, streamId);
    if (!st) return 0;
    st->bodyBytes += static_cast<qint64>(len);
    if (H2ClientLogic::bodyOverBudget(st->bodyBytes, kMaxBodyBytesPerStream)) {
        st->hadError = true;
        st->errorMessage = QStringLiteral("h2: response body exceeded %1 bytes")
                               .arg(kMaxBodyBytesPerStream);
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, streamId,
                                  NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;   // stop appending; the RST will close this stream
    }
    st->body.append(reinterpret_cast<const char *>(data), int(len));
    return 0;
}

int onFrameRecv(nghttp2_session *session, const nghttp2_frame *frame, void *userData) {
    auto *sess = static_cast<SessionState *>(userData);
    // Surface EVERY frame (incl. stream-0 SETTINGS / PING / GOAWAY) into the log.
    H2EventLog::instance()->noteFrame(sess->connName, frame->hd.type, frame->hd.flags,
                                      frame->hd.stream_id,
                                      static_cast<qint64>(frame->hd.length), /*sent=*/false);
    StreamState *st = streamOf(session, frame->hd.stream_id);
    if (frame->hd.type == NGHTTP2_HEADERS
        && (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) && st) {
        st->headersComplete = true;
        H2EventLog::instance()->noteResponseStatus(sess->connName, st->streamId, st->statusCode);
    }
    if (frame->hd.type == NGHTTP2_RST_STREAM) {
        H2EventLog::instance()->noteRstStream(sess->connName, frame->hd.stream_id,
                                              frame->rst_stream.error_code);
    }
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && st) st->done = true;
    return 0;
}

int onStreamClose(nghttp2_session *session, int32_t streamId, uint32_t errCode, void *userData) {
    auto *sess = static_cast<SessionState *>(userData);
    H2EventLog::instance()->noteStreamClosed(sess->connName, streamId);
    StreamState *st = streamOf(session, streamId);
    if (!st) return 0;
    st->done = true;
    if (sess->openStreams > 0) --sess->openStreams;   // gate the pump-loop exit
    if (errCode != NGHTTP2_NO_ERROR && !st->hadError) {
        st->hadError = true;
        st->errorMessage = QStringLiteral("h2 stream closed with error 0x%1").arg(errCode, 0, 16);
    }
    return 0;
}

// nghttp2 pulls the request body through here; the cursor lives in StreamState
// (routed via stream_user_data), so concurrent streams each stream their own
// body without sharing a request-scoped cursor.
ssize_t bodyRead(nghttp2_session *session, int32_t streamId,
                 uint8_t *buf, size_t length, uint32_t *data_flags,
                 nghttp2_data_source * /*source*/, void * /*user_data*/) {
    StreamState *st = streamOf(session, streamId);
    if (!st || !st->reqBody) { *data_flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
    const qsizetype remaining = st->reqBody->size() - st->reqOffset;
    const qsizetype toCopy = qMin(static_cast<qsizetype>(length), remaining);
    if (toCopy > 0) {
        std::memcpy(buf, st->reqBody->constData() + st->reqOffset, size_t(toCopy));
        st->reqOffset += toCopy;
    }
    if (st->reqOffset >= st->reqBody->size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(toCopy);
}

// Drain all queued outbound frames to the socket. Returns false on a hard error
// (also sets sess.fatal); *wrote reports whether any bytes went out.
bool drainSend(nghttp2_session *session, QSslSocket *sock, SessionState &sess, bool *wrote) {
    *wrote = false;
    for (;;) {
        const uint8_t *out = nullptr;
        const ssize_t produced = nghttp2_session_mem_send(session, &out);
        if (produced < 0) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: mem_send error");
            return false;
        }
        if (produced == 0) return true;
        const qint64 written = sock->write(reinterpret_cast<const char *>(out), qint64(produced));
        if (written != qint64(produced)) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: socket short write");
            return false;
        }
        *wrote = true;
    }
}

} // namespace

QList<H2Client::Result> H2Client::sendConcurrent(QSslSocket *sock,
                                                 const QList<HttpRequest> &reqs) {
    QList<Result> results;
    for (int i = 0; i < reqs.size(); ++i) results.append(Result{});

    if (!sock) {
        for (auto &r : results) r.errorMessage = QStringLiteral("h2: null socket");
        return results;
    }
    if (reqs.isEmpty()) return results;

    nghttp2_session_callbacks *cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        for (auto &r : results) r.errorMessage = QStringLiteral("h2: callbacks_new failed");
        return results;
    }
    nghttp2_session_callbacks_set_on_header_callback(cbs, onHeader);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, onFrameRecv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClose);

    SessionState sess;
    sess.connName = reqs.first().host + ":" + QString::number(reqs.first().port);

    nghttp2_session *session = nullptr;
    if (nghttp2_session_client_new(&session, cbs, &sess) != 0) {
        nghttp2_session_callbacks_del(cbs);
        for (auto &r : results) r.errorMessage = QStringLiteral("h2: session_client_new failed");
        return results;
    }

    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 24 },
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kMaxConcurrentStreamsLocal },
        // Refuse server push: a PUSH_PROMISE opens a peer-initiated stream that
        // our submit-time concurrency cap never sees, and its DATA would land in
        // a StreamState we didn't budget. We only want the responses we asked for.
        { NGHTTP2_SETTINGS_ENABLE_PUSH,            0 },
    };
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(iv[0]));

    // Submit all requests up front (subject to the local concurrency cap) so the
    // origin can interleave their responses over the one session.
    for (int i = 0; i < reqs.size(); ++i) {
        const HttpRequest &req = reqs.at(i);
        if (H2ClientLogic::shouldRejectSubmit(sess.openStreams, kMaxConcurrentStreamsLocal)) {
            results[i].errorMessage = QStringLiteral("h2: local concurrent-stream cap reached");
            continue;
        }
        const auto nvList = H2ClientLogic::buildRequestHeaders(req.method, req.host,
                                                              req.path, req.headers);
        std::vector<nghttp2_nv> nvs;
        nvs.reserve(nvList.size());
        for (const auto &h : nvList) {
            nghttp2_nv nv;
            nv.name     = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(h.name.constData()));
            nv.namelen  = size_t(h.name.size());
            nv.value    = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(h.value.constData()));
            nv.valuelen = size_t(h.value.size());
            nv.flags    = NGHTTP2_NV_FLAG_NONE;   // nghttp2 copies on submit
            nvs.push_back(nv);
        }

        auto st = std::make_unique<StreamState>();
        st->resultIndex = i;
        nghttp2_data_provider dp;
        nghttp2_data_provider *dpPtr = nullptr;
        if (!req.body.isEmpty()) {
            st->reqBody   = &req.body;   // `reqs` outlives this synchronous call
            dp.source.ptr = st.get();    // bodyRead actually routes via stream_user_data
            dp.read_callback = bodyRead;
            dpPtr = &dp;
        }

        StreamState *raw = st.get();     // stable heap address; survives the move
        const int32_t sid = nghttp2_submit_request(session, nullptr, nvs.data(),
                                                   nvs.size(), dpPtr, raw);
        if (sid < 0) {
            results[i].errorMessage = QStringLiteral("h2: submit_request failed (%1)").arg(sid);
            continue;
        }
        raw->streamId = sid;
        sess.streams.emplace(sid, std::move(st));
        ++sess.openStreams;
        H2EventLog::instance()->noteRequestHeader(sess.connName, sid, req.method, req.path);
        H2EventLog::instance()->noteFrame(sess.connName, /*HEADERS*/1, 0, sid, 0, /*sent=*/true);
    }

    // Pump loop. Each iteration FULLY drains outbound first (so no stream's
    // frames sit unsent behind a blocking read -> the deadlock the design flags),
    // then reads inbound, until every stream is closed. An absolute deadline
    // backstops a peer that dribbles bytes forever to keep the loop alive
    // (a per-wait timeout resets on every byte; only a wall-clock budget bounds
    // the aggregate -- mirrors the WHOIS/PCRE2 aggregate-budget pattern).
    QElapsedTimer clock;
    clock.start();
    while (sock->state() == QAbstractSocket::ConnectedState) {
        if (clock.hasExpired(kTotalDeadlineMs)) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: total deadline exceeded");
            break;
        }
        bool wrote = false;
        if (!drainSend(session, sock, sess, &wrote)) break;   // sets sess.fatal
        const PumpAction action = H2ClientLogic::nextPumpAction(sess.openStreams, wrote, sess.fatal);
        if (action == PumpAction::Fatal || action == PumpAction::Done) break;
        if (action == PumpAction::WriteThenRead
            && !sock->waitForBytesWritten(kReadTimeoutMs)) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: waitForBytesWritten timed out");
            break;
        }
        if (sock->bytesAvailable() == 0 && !sock->waitForReadyRead(kReadTimeoutMs)) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: waitForReadyRead timed out");
            break;
        }
        const QByteArray buf = sock->readAll();
        if (buf.isEmpty()) continue;
        const ssize_t consumed = nghttp2_session_mem_recv(
            session, reinterpret_cast<const uint8_t *>(buf.constData()), size_t(buf.size()));
        if (consumed < 0) {
            sess.fatal = true; sess.fatalMessage = QStringLiteral("h2: mem_recv error (%1)").arg(consumed);
            break;
        }
    }

    // Final outbound flush (our own GOAWAY ack etc.).
    bool flushed = false;
    drainSend(session, sock, sess, &flushed);
    sock->waitForBytesWritten(1000);

    // Assemble per-request results, mapped back to the original request order.
    for (const auto &kv : sess.streams) {
        StreamState *st = kv.second.get();
        if (st->resultIndex < 0 || st->resultIndex >= results.size()) continue;
        Result &r = results[st->resultIndex];
        // A stream that already received its full response (headers + :status +
        // END_STREAM, no error) is valid REGARDLESS of a later connection-level
        // stall: a single hung sibling driving the pump to its deadline must not
        // clobber responses that already completed in earlier iterations.
        const bool completedOk = st->done && st->statusCode != 0 && !st->hadError;
        if (!completedOk) {
            if (sess.fatal)          { r.ok = false; r.errorMessage = sess.fatalMessage; continue; }
            if (st->hadError)        { r.ok = false; r.errorMessage = st->errorMessage;  continue; }
            if (st->statusCode == 0) { r.ok = false; r.errorMessage = QStringLiteral("h2: no :status received"); continue; }
        }
        r.response.httpVersion  = QStringLiteral("HTTP/1.1");
        r.response.statusCode   = st->statusCode;
        r.response.reasonPhrase = QString::fromLatin1(H2ClientLogic::reasonFor(st->statusCode));
        r.response.headers      = st->headers;
        r.response.body         = st->body;
        r.response.peerAddress  = sock->peerAddress().toString();
        r.response.wasTls       = true;
        r.ok = true;
    }
    // A connection-level failure fails even requests that never opened a stream.
    if (sess.fatal)
        for (auto &r : results)
            if (!r.ok && r.errorMessage.isEmpty()) r.errorMessage = sess.fatalMessage;

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(cbs);
    return results;
}

H2Client::Result H2Client::sendRequest(QSslSocket *sock, const HttpRequest &req) {
    const QList<Result> rs = sendConcurrent(sock, { req });
    if (rs.isEmpty()) { Result r; r.errorMessage = QStringLiteral("h2: no result"); return r; }
    return rs.first();
}

} // namespace Nullock::Proxy

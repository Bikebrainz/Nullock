#include "http2_client.hpp"
#include "h2_events.hpp"

#include <QByteArray>
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
#include <vector>

namespace Nullock::Proxy {

namespace {

constexpr int kReadTimeoutMs = 15'000;

// Per-request mutable state. Lifetime matches one sendRequest call.
struct H2RequestState {
    int32_t streamId = -1;
    bool    streamDone = false;
    bool    headersComplete = false;
    bool    hadError = false;
    QString errorMessage;
    QString connName;     // for H2EventLog correlation

    int statusCode = 0;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
};

QByteArray toBytes(const QString &s) { return s.toUtf8(); }

const char *reasonFor(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 408: return "Request Timeout";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:
            if (status >= 200 && status < 300) return "OK";
            if (status >= 300 && status < 400) return "Redirect";
            if (status >= 400 && status < 500) return "Client Error";
            if (status >= 500 && status < 600) return "Server Error";
            return "Unknown";
    }
}

int onHeader(nghttp2_session *,
             const nghttp2_frame *frame,
             const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen,
             uint8_t /*flags*/, void *userData) {
    auto *st = static_cast<H2RequestState *>(userData);
    if (frame->hd.stream_id != st->streamId) return 0;

    const QString n = QString::fromUtf8(reinterpret_cast<const char *>(name),
                                        static_cast<int>(namelen));
    const QString v = QString::fromUtf8(reinterpret_cast<const char *>(value),
                                        static_cast<int>(valuelen));
    if (n == ":status") {
        st->statusCode = v.toInt();
    } else if (!n.startsWith(':')) {
        st->headers.append({ n, v });
    }
    return 0;
}

int onDataChunk(nghttp2_session *,
                uint8_t /*flags*/, int32_t streamId,
                const uint8_t *data, size_t len,
                void *userData) {
    auto *st = static_cast<H2RequestState *>(userData);
    if (streamId != st->streamId) return 0;
    st->body.append(reinterpret_cast<const char *>(data), static_cast<int>(len));
    return 0;
}

int onFrameRecv(nghttp2_session *, const nghttp2_frame *frame, void *userData) {
    auto *st = static_cast<H2RequestState *>(userData);
    // Surface every frame (not just our stream) into the H2 event log
    // so the user can see SETTINGS / PING / GOAWAY too.
    Nullock::Proxy::H2EventLog::instance()->noteFrame(
        st->connName,
        frame->hd.type,
        frame->hd.flags,
        frame->hd.stream_id,
        static_cast<qint64>(frame->hd.length),
        /*sent=*/false);
    if (frame->hd.type == NGHTTP2_HEADERS
        && (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
        && frame->hd.stream_id == st->streamId) {
        st->headersComplete = true;
        Nullock::Proxy::H2EventLog::instance()->noteResponseStatus(
            st->connName, st->streamId, st->statusCode);
    }
    if (frame->hd.type == NGHTTP2_RST_STREAM) {
        Nullock::Proxy::H2EventLog::instance()->noteRstStream(
            st->connName, frame->hd.stream_id,
            frame->rst_stream.error_code);
    }
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        && frame->hd.stream_id == st->streamId) {
        st->streamDone = true;
    }
    return 0;
}

int onStreamClose(nghttp2_session *, int32_t streamId, uint32_t errCode, void *userData) {
    auto *st = static_cast<H2RequestState *>(userData);
    Nullock::Proxy::H2EventLog::instance()->noteStreamClosed(st->connName, streamId);
    if (streamId != st->streamId) return 0;
    st->streamDone = true;
    if (errCode != NGHTTP2_NO_ERROR) {
        st->hadError = true;
        st->errorMessage = QString("h2 stream closed with error 0x%1")
                               .arg(errCode, 0, 16);
    }
    return 0;
}

// Streams req.body into DATA frames. nghttp2 calls this repeatedly with a
// buffer to fill until we set NGHTTP2_DATA_FLAG_EOF.
struct BodyCursor {
    const QByteArray *body = nullptr;
    qsizetype offset = 0;
};

ssize_t bodyRead(nghttp2_session *, int32_t /*streamId*/,
                 uint8_t *buf, size_t length,
                 uint32_t *data_flags,
                 nghttp2_data_source *source, void * /*user_data*/) {
    auto *cursor = static_cast<BodyCursor *>(source->ptr);
    if (!cursor || !cursor->body) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    const qsizetype remaining = cursor->body->size() - cursor->offset;
    const qsizetype toCopy = qMin(static_cast<qsizetype>(length), remaining);
    if (toCopy > 0) {
        std::memcpy(buf, cursor->body->constData() + cursor->offset,
                    static_cast<size_t>(toCopy));
        cursor->offset += toCopy;
    }
    if (cursor->offset >= cursor->body->size())
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(toCopy);
}

} // namespace

H2Client::Result H2Client::sendRequest(QSslSocket *sock, const HttpRequest &req) {
    Result result;
    if (!sock) {
        result.errorMessage = "h2: null socket";
        return result;
    }

    nghttp2_session_callbacks *cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        result.errorMessage = "h2: callbacks_new failed";
        return result;
    }
    nghttp2_session_callbacks_set_on_header_callback(cbs, onHeader);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, onFrameRecv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClose);

    H2RequestState state;
    state.connName = req.host + ":" + QString::number(req.port);

    nghttp2_session *session = nullptr;
    if (nghttp2_session_client_new(&session, cbs, &state) != 0) {
        nghttp2_session_callbacks_del(cbs);
        result.errorMessage = "h2: session_client_new failed";
        return result;
    }

    // Initial SETTINGS frame. Generous flow control window so we don't have
    // to micromanage WINDOW_UPDATE for the common single-request case.
    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 24 },
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 16      },
    };
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv,
                                sizeof(iv) / sizeof(iv[0])) != 0) {
        nghttp2_session_del(session);
        nghttp2_session_callbacks_del(cbs);
        result.errorMessage = "h2: submit_settings failed";
        return result;
    }

    // Build request headers. h2 requires lowercase header names and bans
    // hop-by-hop headers like Connection / Transfer-Encoding.
    const QByteArray method    = toBytes(req.method.isEmpty() ? QStringLiteral("GET") : req.method);
    const QByteArray scheme    = QByteArrayLiteral("https");
    const QByteArray authority = toBytes(req.host);
    const QByteArray path      = toBytes(req.path.isEmpty() ? QStringLiteral("/") : req.path);

    std::vector<nghttp2_nv> nvs;
    nvs.reserve(req.headers.size() + 4);

    auto pushHeader = [&](const QByteArray &name, const QByteArray &value) {
        nghttp2_nv nv;
        nv.name     = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(name.constData()));
        nv.namelen  = static_cast<size_t>(name.size());
        nv.value    = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(value.constData()));
        nv.valuelen = static_cast<size_t>(value.size());
        nv.flags    = NGHTTP2_NV_FLAG_NONE;
        nvs.push_back(nv);
    };

    // Pseudo-headers first, in this order (required by spec).
    pushHeader(QByteArrayLiteral(":method"),    method);
    pushHeader(QByteArrayLiteral(":scheme"),    scheme);
    pushHeader(QByteArrayLiteral(":authority"), authority);
    pushHeader(QByteArrayLiteral(":path"),      path);

    // Keep storage alive for the duration of submit_request (nghttp2 doesn't
    // copy until the frame is serialized).
    std::vector<QByteArray> nameStorage;
    std::vector<QByteArray> valueStorage;
    nameStorage.reserve(req.headers.size());
    valueStorage.reserve(req.headers.size());

    for (const auto &kv : req.headers) {
        const QString lower = kv.first.toLower();
        // h2 forbids these connection-control headers.
        if (lower == "host" || lower == "connection" ||
            lower == "proxy-connection" || lower == "transfer-encoding" ||
            lower == "upgrade" || lower == "keep-alive" || lower == "te")
            continue;
        nameStorage.push_back(lower.toUtf8());
        valueStorage.push_back(kv.second.toUtf8());
        pushHeader(nameStorage.back(), valueStorage.back());
    }

    BodyCursor cursor;
    nghttp2_data_provider dp;
    nghttp2_data_provider *dpPtr = nullptr;
    if (!req.body.isEmpty()) {
        cursor.body = &req.body;
        dp.source.ptr = &cursor;
        dp.read_callback = bodyRead;
        dpPtr = &dp;
    }

    state.streamId = nghttp2_submit_request(session, nullptr, nvs.data(),
                                            nvs.size(), dpPtr, nullptr);
    if (state.streamId > 0) {
        Nullock::Proxy::H2EventLog::instance()->noteRequestHeader(
            state.connName, state.streamId, req.method, req.path);
        Nullock::Proxy::H2EventLog::instance()->noteFrame(
            state.connName, /*HEADERS*/1, /*flags*/0, state.streamId,
            /*bytes*/0, /*sent=*/true);
    }
    if (state.streamId < 0) {
        nghttp2_session_del(session);
        nghttp2_session_callbacks_del(cbs);
        result.errorMessage = QString("h2: submit_request failed (%1)")
                                  .arg(state.streamId);
        return result;
    }

    // Pump loop: drain outbound, then read inbound, until stream closes.
    while (sock->state() == QAbstractSocket::ConnectedState && !state.streamDone) {
        // Outbound: keep calling mem_send until it returns 0.
        bool wrote = false;
        while (true) {
            const uint8_t *out = nullptr;
            const ssize_t produced = nghttp2_session_mem_send(session, &out);
            if (produced < 0) {
                state.hadError = true;
                state.errorMessage = "h2: mem_send error";
                break;
            }
            if (produced == 0) break;
            const qint64 written = sock->write(reinterpret_cast<const char *>(out),
                                               static_cast<qint64>(produced));
            if (written != static_cast<qint64>(produced)) {
                state.hadError = true;
                state.errorMessage = "h2: socket short write";
                break;
            }
            wrote = true;
        }
        if (state.hadError) break;
        // Only block on flush if we actually queued bytes. Otherwise the
        // wait sits the full timeout because there's nothing for the socket
        // to drain.
        if (wrote && !sock->waitForBytesWritten(kReadTimeoutMs)) {
            state.hadError = true;
            state.errorMessage = "h2: waitForBytesWritten timed out";
            break;
        }

        if (state.streamDone) break;

        // Inbound: feed any available bytes to the session.
        if (sock->bytesAvailable() == 0 && !sock->waitForReadyRead(kReadTimeoutMs)) {
            state.hadError = true;
            state.errorMessage = "h2: waitForReadyRead timed out";
            break;
        }
        const QByteArray buf = sock->readAll();
        if (buf.isEmpty()) continue;
        const ssize_t consumed = nghttp2_session_mem_recv(
            session, reinterpret_cast<const uint8_t *>(buf.constData()),
            static_cast<size_t>(buf.size()));
        if (consumed < 0) {
            state.hadError = true;
            state.errorMessage = QString("h2: mem_recv error (%1)").arg(consumed);
            break;
        }
    }

    // Try to flush any final outbound frames (e.g., our own GOAWAY ack).
    while (true) {
        const uint8_t *out = nullptr;
        const ssize_t produced = nghttp2_session_mem_send(session, &out);
        if (produced <= 0) break;
        sock->write(reinterpret_cast<const char *>(out), static_cast<qint64>(produced));
    }
    sock->waitForBytesWritten(1000);

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(cbs);

    if (state.hadError) {
        result.errorMessage = state.errorMessage;
        return result;
    }
    if (state.statusCode == 0) {
        result.errorMessage = "h2: no :status received";
        return result;
    }

    result.response.httpVersion  = QStringLiteral("HTTP/1.1");
    result.response.statusCode   = state.statusCode;
    result.response.reasonPhrase = QString::fromLatin1(reasonFor(state.statusCode));
    result.response.headers      = state.headers;
    result.response.body         = state.body;
    result.response.peerAddress  = sock->peerAddress().toString();
    result.response.wasTls       = true;
    result.ok = true;
    return result;
}

} // namespace Nullock::Proxy

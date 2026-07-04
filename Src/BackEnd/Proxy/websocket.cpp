#include "websocket.hpp"

#include <zlib.h>       // Qt6Core's bundled zlib (Z_PREFIX -> z_inflate*)
#include <cstring>      // memset

namespace Nullock::Proxy {

namespace {
constexpr qint64 kMaxFramePayload = 16 * 1024 * 1024;  // 16 MiB sanity cap
// Hard cap on the per-stream reassembly buffer. A hostile upstream that
// dribbles bytes of a frame declared at the max payload length would
// otherwise pin kMaxFramePayload per concurrent WS connection; 100
// streams = 1.6 GiB. With this cap, m_buf is bounded at 2x the max
// frame -- enough headroom to fully buffer one max frame plus a header
// for the next, but small enough that 100 attacker streams sit at
// 3.2 GiB total which still beats unbounded. When the cap is hit we
// stop parsing frames for this stream (the raw relay continues so the
// user's app keeps working; we just lose frame-level visibility).
constexpr qint64 kMaxBufferBytes  = 2 * kMaxFramePayload;
}

const char *wsOpcodeLabel(quint8 opcode) {
    switch (opcode & 0x0F) {
        case 0x0: return "cont";
        case 0x1: return "text";
        case 0x2: return "binary";
        case 0x8: return "close";
        case 0x9: return "ping";
        case 0xA: return "pong";
        default:  return "reserved";
    }
}

qint64 WsFrameParser::tryParseOne(WsFrame *out, qsizetype start) {
    // All length checks are relative to `start` (the moving cursor), so the bytes
    // available for THIS frame are `avail`, never the whole buffer.
    const qsizetype avail = m_buf.size() - start;
    if (avail < 2) return 0;

    const quint8 b0 = static_cast<quint8>(m_buf.at(start));
    const quint8 b1 = static_cast<quint8>(m_buf.at(start + 1));
    const bool   fin    = (b0 & 0x80) != 0;
    const bool   rsv1   = (b0 & 0x40) != 0;   // permessage-deflate compressed bit
    const quint8 opcode = b0 & 0x0F;
    const bool   masked = (b1 & 0x80) != 0;
    qint64       payloadLen = b1 & 0x7F;

    qsizetype offset = 2;   // bytes into THIS frame (relative to `start`)

    if (payloadLen == 126) {
        if (avail < offset + 2) return 0;
        payloadLen = (static_cast<quint8>(m_buf.at(start + offset)) << 8)
                   |  static_cast<quint8>(m_buf.at(start + offset + 1));
        offset += 2;
    } else if (payloadLen == 127) {
        if (avail < offset + 8) return 0;
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8)
                       | static_cast<quint8>(m_buf.at(start + offset + i));
        }
        offset += 8;
        if (payloadLen < 0 || payloadLen > kMaxFramePayload) {
            // Negative-by-overflow (high bit set) or absurd: a hard RFC 6455
            // violation. Fatal -- feed() tears the parser down (no resync).
            return -1;
        }
    }

    quint8 mask[4] = { 0, 0, 0, 0 };
    if (masked) {
        if (avail < offset + 4) return 0;
        for (int i = 0; i < 4; ++i)
            mask[i] = static_cast<quint8>(m_buf.at(start + offset + i));
        offset += 4;
    }

    if (avail < offset + payloadLen) return 0;

    out->opcode = opcode;
    out->fin    = fin;
    out->rsv1   = rsv1;
    // qsizetype args (no int cast); payloadLen is capped at 16 MiB above so the
    // offsets are far below INT_MAX, but mid() takes qsizetype so don't truncate.
    out->payload = m_buf.mid(start + offset, payloadLen);
    if (masked) {
        for (qint64 i = 0; i < payloadLen; ++i) {
            out->payload[i] = static_cast<char>(
                static_cast<quint8>(out->payload[i]) ^ mask[i & 3]);
        }
    }

    return offset + payloadLen;   // size of this frame
}

QList<WsFrame> WsFrameParser::feed(const QByteArray &chunk) {
    if (m_giveUp) {
        // Stream previously exceeded our buffer cap / hit a protocol error; keep no
        // state. The caller's raw relay still forwards bytes; we just stop emitting
        // frame events.
        return {};
    }
    // Bound the input BEFORE growing m_buf: appending first and checking after let
    // a single oversized chunk transiently allocate past the cap. m_buf.size() is
    // always <= kMaxBufferBytes here, so the subtraction can't underflow.
    if (chunk.size() > kMaxBufferBytes - m_buf.size()) {
        m_buf.clear();
        m_giveUp = true;
        return {};
    }
    m_buf.append(chunk);

    QList<WsFrame> out;
    qsizetype pos = 0;                 // moving read cursor -> the whole pass is O(n)
    while (true) {
        WsFrame f;
        const qint64 consumed = tryParseOne(&f, pos);
        if (consumed < 0) {
            // Protocol error (absurd length): FATAL. Drop state and give up so the
            // attacker can't keep the parser in a wedged, mis-resyncing loop.
            m_buf.clear();
            m_giveUp = true;
            return out;
        }
        if (consumed == 0) break;      // incomplete frame -> wait for more bytes
        out.append(f);
        pos += consumed;
    }
    if (pos > 0) m_buf.remove(0, pos); // compact the consumed prefix ONCE (not per frame)
    return out;
}

// ===================== permessage-deflate (RFC 7692) ======================

namespace {
constexpr int    kInflateChunk       = 16 * 1024;         // output scratch per pass
constexpr qint64 kMaxInflatedMessage = 64 * 1024 * 1024;  // 64 MiB zip-bomb guard
// The 4-octet tail every permessage-deflate sender strips before transmit; we
// re-append it so zlib sees a flushable empty stored block (RFC 7692 s7.2.2).
const char kDeflateTail[4] = { '\x00', '\x00', '\xFF', '\xFF' };
}

WsInflater::WsInflater() {
    auto *zs = new z_stream;
    std::memset(zs, 0, sizeof(z_stream));
    // windowBits = -15 -> RAW DEFLATE (no zlib/gzip wrapper), as RFC 7692 uses.
    if (inflateInit2(zs, -15) == Z_OK) {
        m_stream = zs;
        m_ok = true;
    } else {
        delete zs;
    }
}

WsInflater::~WsInflater() {
    if (m_stream) {
        auto *zs = static_cast<z_stream *>(m_stream);
        inflateEnd(zs);
        delete zs;
    }
}

QByteArray WsInflater::inflateMessage(const QByteArray &compressed, bool *ok) {
    if (ok) *ok = false;
    if (!m_ok || !m_stream) return {};
    auto *zs = static_cast<z_stream *>(m_stream);

    // Feed the message body followed by the stripped empty-block tail. A local
    // copy keeps next_in pointing at stable storage for the whole inflate.
    QByteArray in = compressed;
    in.append(kDeflateTail, 4);
    zs->next_in  = reinterpret_cast<Bytef *>(in.data());
    zs->avail_in = static_cast<uInt>(in.size());

    QByteArray out;
    char buf[kInflateChunk];
    for (;;) {
        zs->next_out  = reinterpret_cast<Bytef *>(buf);
        zs->avail_out = sizeof(buf);
        const int ret = inflate(zs, Z_SYNC_FLUSH);
        // Z_BUF_ERROR just means "no forward progress possible" -- the normal
        // way a Z_SYNC_FLUSH message ends once its input is drained. Only a hard
        // error (Z_DATA_ERROR / Z_MEM_ERROR / Z_STREAM_ERROR) poisons us.
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            m_ok = false;          // shared window is now untrustworthy
            return out;
        }
        const qint64 produced = static_cast<qint64>(sizeof(buf)) - zs->avail_out;
        if (produced > 0) out.append(buf, produced);
        if (out.size() > kMaxInflatedMessage) {
            m_ok = false;          // refuse to keep expanding a bomb
            return out;
        }
        // Full output buffer => there may be more to drain; otherwise we're done.
        if (zs->avail_out != 0) break;
    }

    if (ok) *ok = true;
    return out;
}

} // namespace Nullock::Proxy

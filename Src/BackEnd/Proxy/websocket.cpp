#include "websocket.hpp"

namespace Nullock::Proxy {

namespace {
constexpr qint64 kMaxFramePayload = 16 * 1024 * 1024;  // 16 MiB sanity cap
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

qint64 WsFrameParser::tryParseOne(WsFrame *out) {
    if (m_buf.size() < 2) return 0;

    const quint8 b0 = static_cast<quint8>(m_buf.at(0));
    const quint8 b1 = static_cast<quint8>(m_buf.at(1));
    const bool   fin    = (b0 & 0x80) != 0;
    const quint8 opcode = b0 & 0x0F;
    const bool   masked = (b1 & 0x80) != 0;
    qint64       payloadLen = b1 & 0x7F;

    qsizetype offset = 2;

    if (payloadLen == 126) {
        if (m_buf.size() < offset + 2) return 0;
        payloadLen = (static_cast<quint8>(m_buf.at(offset)) << 8)
                   |  static_cast<quint8>(m_buf.at(offset + 1));
        offset += 2;
    } else if (payloadLen == 127) {
        if (m_buf.size() < offset + 8) return 0;
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8)
                       | static_cast<quint8>(m_buf.at(offset + i));
        }
        offset += 8;
        if (payloadLen < 0 || payloadLen > kMaxFramePayload) {
            // Either negative-by-overflow or absurd; bail rather than alloc.
            return -1;
        }
    }

    quint8 mask[4] = { 0, 0, 0, 0 };
    if (masked) {
        if (m_buf.size() < offset + 4) return 0;
        for (int i = 0; i < 4; ++i)
            mask[i] = static_cast<quint8>(m_buf.at(offset + i));
        offset += 4;
    }

    if (m_buf.size() < offset + payloadLen) return 0;

    out->opcode = opcode;
    out->fin    = fin;
    out->payload = m_buf.mid(static_cast<int>(offset), static_cast<int>(payloadLen));
    if (masked) {
        for (qint64 i = 0; i < payloadLen; ++i) {
            out->payload[i] = static_cast<char>(
                static_cast<quint8>(out->payload[i]) ^ mask[i & 3]);
        }
    }

    return offset + payloadLen;
}

QList<WsFrame> WsFrameParser::feed(const QByteArray &chunk) {
    m_buf.append(chunk);
    QList<WsFrame> out;
    while (true) {
        WsFrame f;
        const qint64 consumed = tryParseOne(&f);
        if (consumed <= 0) {
            // 0 = incomplete (wait for more bytes); -1 = give up on this
            // stream entirely. Either way we stop emitting and let the
            // caller forward raw bytes anyway.
            if (consumed < 0) m_buf.clear();
            break;
        }
        out.append(f);
        m_buf.remove(0, static_cast<int>(consumed));
    }
    return out;
}

} // namespace Nullock::Proxy

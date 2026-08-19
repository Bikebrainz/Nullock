// Pure WebSocket frame (re)encoder + hold-eligibility (see websocket.hpp). No I/O
// and no zlib -- links against Qt6::Core alone, so the security-critical framing +
// masking logic unit-tests + mutation-proves in isolation. This is the ONE
// serializer used for both WsRepeater injection and the intercept forward path, so
// a framing/masking bug can't slip in on one path while the other's tests pass.

#include "websocket.hpp"

#include <QRandomGenerator>

namespace Nullock::Proxy {

QByteArray wsEncodeFrame(quint8 opcode, bool fin, bool rsv1,
                         const QByteArray &payload, bool mask) {
    QByteArray out;
    out.reserve(payload.size() + 14);
    // Byte 0: FIN, RSV1 (permessage-deflate compressed), RSV2/RSV3 always 0, opcode.
    const quint8 b0 = (fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00)
                    | static_cast<quint8>(opcode & 0x0F);
    out.append(static_cast<char>(b0));
    const qint64 len = payload.size();
    const quint8 maskBit = mask ? 0x80 : 0x00;
    // Minimal length form (RFC 6455 5.2): <126 inline, <=0xFFFF as 16-bit, else 64-bit.
    if (len < 126) {
        out.append(static_cast<char>(maskBit | static_cast<quint8>(len)));
    } else if (len <= 0xFFFF) {
        out.append(static_cast<char>(maskBit | 126));
        out.append(static_cast<char>((len >> 8) & 0xFF));
        out.append(static_cast<char>(len & 0xFF));
    } else {
        out.append(static_cast<char>(maskBit | 127));
        // 8-byte length, network byte order. The high bit is 0 (RFC 6455 5.2).
        for (int shift = 56; shift >= 0; shift -= 8)
            out.append(static_cast<char>((len >> shift) & 0xFF));
    }
    if (mask) {
        // Fresh CSPRNG mask key per frame (never reuse the captured frame's key).
        quint8 m[4];
        for (int i = 0; i < 4; ++i)
            m[i] = static_cast<quint8>(QRandomGenerator::system()->bounded(256));
        for (int i = 0; i < 4; ++i) out.append(static_cast<char>(m[i]));
        for (qint64 i = 0; i < len; ++i)
            out.append(static_cast<char>(static_cast<quint8>(payload.at(i)) ^ m[i & 3]));
    } else {
        out.append(payload);
    }
    return out;
}

bool wsHoldEligible(quint8 opcode, bool rsv1, bool rsv2, bool rsv3) {
    if (opcode & 0x08) return false;          // control frame (close/ping/pong) -> never held
    if (rsv1 || rsv2 || rsv3) return false;   // compressed / other-extension bytes -> verbatim
    return opcode == 0x1 || opcode == 0x2;    // only an uncompressed text/binary data message
}

} // namespace Nullock::Proxy

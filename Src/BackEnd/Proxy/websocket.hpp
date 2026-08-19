#pragma once

#include <QByteArray>
#include <QList>

namespace Nullock::Proxy {

// One decoded WebSocket frame -- payload is already unmasked and ready to
// display. We keep opcode + FIN so the GUI can show continuation/control
// frames distinctly if it cares.
struct WsFrame {
    quint8     opcode = 0;   // 0=cont, 1=text, 2=binary, 8=close, 9=ping, A=pong
    bool       fin    = true;
    bool       rsv1   = false;  // RFC 7692 "compressed" bit; set only on the
                                // first frame of a permessage-deflate message
    QByteArray payload;
};

// Incremental parser per RFC 6455 frame format. Feed bytes from the wire,
// get back any whole frames that completed. Internal buffer holds the
// tail of an incomplete frame between calls. One parser per direction
// (client->server frames are masked; server->client are not -- both work).
class WsFrameParser {
public:
    QList<WsFrame> feed(const QByteArray &chunk);

    // Anything currently buffered (partial frame) hasn't been emitted yet.
    qsizetype bufferedBytes() const { return m_buf.size(); }

private:
    // Parse one frame starting at byte `start` in m_buf (a moving cursor, so the
    // caller never has to remove() from the front per frame -- that was O(n^2)).
    // Returns the frame size in bytes if a complete frame was parsed and filled
    // *out, 0 if the buffer is incomplete from `start`, -1 on protocol error.
    qint64 tryParseOne(WsFrame *out, qsizetype start);

    QByteArray m_buf;
    // Set true after the per-stream buffer cap was exceeded; future
    // feed() calls become no-ops so memory doesn't grow again.
    bool m_giveUp = false;
};

// Best-effort label for a frame opcode, useful for the GUI URL column.
const char *wsOpcodeLabel(quint8 opcode);

// --- Frame (re)encoder + hold-eligibility (pure; ws_encode.cpp, Qt6::Core only) --
// The single serializer for every frame the proxy puts on the wire: WsRepeater
// injection today, and the forward path of WebSocket INTERCEPTION next. Emits an
// RFC 6455 frame: FIN + RSV1 + opcode, a minimal-form length (7 / 16 / 64 bit), and
// -- for a client->server frame (mask=true) -- a FRESH CSPRNG 4-byte mask key with
// the payload XOR-masked after it (server->client frames are never masked). rsv1 is
// the permessage-deflate "compressed" bit; pass false for a plain frame.
QByteArray wsEncodeFrame(quint8 opcode, bool fin, bool rsv1,
                         const QByteArray &payload, bool mask);

// May a message with this opening frame be HELD for edit/drop by the intercept
// path? Only an uncompressed text/binary DATA message qualifies: a control frame
// (opcode & 0x08) must pass through so ping/pong/close framing stays valid, and any
// RSV bit set means an extension (permessage-deflate via rsv1, or another) owns the
// bytes -- editing them would desync that extension's stateful stream. Everything
// this rejects is forwarded verbatim. Pure + flip-provable.
bool wsHoldEligible(quint8 opcode, bool rsv1, bool rsv2, bool rsv3);

// Stateful permessage-deflate (RFC 7692) inflater for ONE direction of a
// WebSocket stream. Maintains the zlib sliding window across messages so it
// decodes correctly under context-takeover (the negotiated default). This is
// display-only: the proxy forwards the original compressed bytes unchanged and
// inflates a copy so the operator can read the traffic. Backed by the zlib
// bundled in Qt6Core (raw DEFLATE, windowBits = -15); z_stream is hidden behind
// a void* so <zlib.h> stays out of this widely-included header.
class WsInflater {
public:
    WsInflater();
    ~WsInflater();
    WsInflater(const WsInflater &) = delete;
    WsInflater &operator=(const WsInflater &) = delete;

    // Inflate one COMPLETE compressed message (the concatenated payloads of all
    // its frames). Appends the RFC 7692 tail (00 00 FF FF) the sender strips.
    // Returns the decompressed bytes and sets *ok. On a corrupt stream or if the
    // output exceeds the anti-zip-bomb cap the inflater is permanently poisoned
    // (healthy() becomes false) since the shared window can no longer be trusted.
    QByteArray inflateMessage(const QByteArray &compressed, bool *ok);

    // False if init failed or a prior message corrupted the shared context.
    bool healthy() const { return m_ok; }

private:
    void *m_stream = nullptr;   // z_streamp
    bool  m_ok     = false;
};

} // namespace Nullock::Proxy

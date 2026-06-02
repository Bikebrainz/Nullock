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
    // Returns the number of bytes consumed if a complete frame was parsed
    // and filled *out, 0 if the buffer is incomplete, -1 on protocol error.
    qint64 tryParseOne(WsFrame *out);

    QByteArray m_buf;
    // Set true after the per-stream buffer cap was exceeded; future
    // feed() calls become no-ops so memory doesn't grow again.
    bool m_giveUp = false;
};

// Best-effort label for a frame opcode, useful for the GUI URL column.
const char *wsOpcodeLabel(quint8 opcode);

} // namespace Nullock::Proxy

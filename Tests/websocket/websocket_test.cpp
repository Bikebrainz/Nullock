// Regression corpus for the WebSocket frame parser (no network -- it parses
// attacker-controlled wire bytes). Locks the RFC 6455 frame decode AND the
// soundness fixes from the adversarial audit (5 findings / 3 issues):
//   - O(n^2) per-frame front-remove replaced by a moving cursor (a tiny-frame
//     flood used to be quadratic CPU DoS) -- a big multi-frame chunk still decodes
//     every frame and fully compacts the buffer;
//   - an absurd 64-bit length is now FATAL: m_giveUp is set so the parser can't be
//     kept in a wedged mis-resyncing loop (it previously cleared and kept parsing);
//   - the buffer cap is enforced BEFORE appending, so a single oversized chunk
//     can't transiently allocate past it.
//
// Run via:  ctest -R websocket -V

#include "websocket.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <zlib.h>       // synthesize permessage-deflate messages via z_deflate*
#include <cstdio>
#include <cstring>

using namespace Nullock::Proxy;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Compress `plain` into the on-wire permessage-deflate payload using a
// persistent raw-DEFLATE stream, then strip the trailing 00 00 FF FF empty
// block exactly as an RFC 7692 sender does. Reusing the same `ds` across calls
// exercises context-takeover (message N back-references message N-1's window).
QByteArray deflateMsg(z_stream *ds, const QByteArray &plain) {
    ds->next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(plain.constData()));
    ds->avail_in = static_cast<uInt>(plain.size());
    QByteArray out;
    char buf[16384];
    do {
        ds->next_out  = reinterpret_cast<Bytef *>(buf);
        ds->avail_out = sizeof(buf);
        deflate(ds, Z_SYNC_FLUSH);          // flush this message, keep stream open
        out.append(buf, sizeof(buf) - ds->avail_out);
    } while (ds->avail_out == 0);
    if (out.endsWith(QByteArray("\x00\x00\xFF\xFF", 4)))   // sender strips the tail
        out.chop(4);
    return out;
}
// Build one RFC 6455 frame. `payload` is the PLAINTEXT; when masked we XOR it onto
// the wire with `mask` (the parser must return the plaintext back).
QByteArray frame(quint8 opcode, const QByteArray &payload, bool fin = true,
                 bool masked = false, const char mask[4] = nullptr) {
    QByteArray f;
    f += char((fin ? 0x80 : 0) | (opcode & 0x0F));
    const qint64 len = payload.size();
    const quint8 mbit = masked ? 0x80 : 0;
    if (len <= 125) {
        f += char(mbit | quint8(len));
    } else if (len <= 0xFFFF) {
        f += char(mbit | 126);
        f += char((len >> 8) & 0xFF);
        f += char(len & 0xFF);
    } else {
        f += char(mbit | 127);
        for (int i = 7; i >= 0; --i) f += char((len >> (8 * i)) & 0xFF);
    }
    QByteArray onWire = payload;
    if (masked && mask) {
        f += QByteArray(mask, 4);
        for (int i = 0; i < onWire.size(); ++i)
            onWire[i] = char(quint8(onWire[i]) ^ quint8(mask[i & 3]));
    }
    f += onWire;
    return f;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== wsOpcodeLabel =================================================
    chk("opcode: 0x1 -> text", QByteArray(wsOpcodeLabel(0x1)) == "text");
    chk("opcode: 0x8 -> close", QByteArray(wsOpcodeLabel(0x8)) == "close");
    chk("opcode: 0xA -> pong", QByteArray(wsOpcodeLabel(0xA)) == "pong");
    chk("opcode: 0x3 -> reserved", QByteArray(wsOpcodeLabel(0x3)) == "reserved");

    // ===== happy path: unmasked text frame ==============================
    {
        WsFrameParser p;
        const auto fs = p.feed(frame(0x1, "hello"));
        chk("decode: one text frame", fs.size() == 1);
        chk("decode: opcode text", fs.value(0).opcode == 0x1);
        chk("decode: fin set", fs.value(0).fin);
        chk("decode: payload 'hello'", fs.value(0).payload == "hello");
        chk("decode: buffer fully consumed", p.bufferedBytes() == 0);
    }

    // ===== masked frame is unmasked back to plaintext ===================
    {
        WsFrameParser p;
        const char m[4] = { 0x12, 0x34, 0x56, 0x78 };
        const auto fs = p.feed(frame(0x2, "binary-data", true, true, m));
        chk("decode: masked frame -> 1 frame", fs.size() == 1);
        chk("decode: masked payload unmasked to plaintext", fs.value(0).payload == "binary-data");
    }

    // ===== 16-bit (126) extended length =================================
    {
        WsFrameParser p;
        const QByteArray big(300, 'A');           // > 125 -> 16-bit length path
        const auto fs = p.feed(frame(0x2, big));
        chk("decode: 126 (16-bit) length frame", fs.size() == 1 && fs.value(0).payload.size() == 300);
    }

    // ===== 64-bit (127) extended length, modest payload =================
    {
        WsFrameParser p;
        QByteArray f;
        f += char(0x82);                          // FIN + binary
        f += char(127);                           // 64-bit length follows, unmasked
        const qint64 len = 70000;                 // > 65535 -> forces the 127 path
        for (int i = 7; i >= 0; --i) f += char((len >> (8 * i)) & 0xFF);
        f += QByteArray(int(len), 'Z');
        const auto fs = p.feed(f);
        chk("decode: 127 (64-bit) length frame", fs.size() == 1 && fs.value(0).payload.size() == 70000);
    }

    // ===== partial frame: wait for more bytes ===========================
    {
        WsFrameParser p;
        const QByteArray full = frame(0x1, "abcdef");
        const auto a = p.feed(full.left(3));      // header + part of payload
        chk("partial: nothing emitted yet", a.isEmpty() && p.bufferedBytes() == 3);
        const auto b = p.feed(full.mid(3));       // the rest
        chk("partial: frame completes on the rest", b.size() == 1 && b.value(0).payload == "abcdef");
        chk("partial: buffer consumed", p.bufferedBytes() == 0);
    }

    // ===== multi-frame chunk + tiny-frame flood (the O(n^2) fix) ========
    {
        WsFrameParser p;
        const auto fs = p.feed(frame(0x1, "one") + frame(0x1, "two") + frame(0x9, ""));
        chk("multi: three frames from one chunk", fs.size() == 3);
        chk("multi: payloads in order", fs.value(0).payload == "one" && fs.value(1).payload == "two");
        chk("multi: third is an empty ping", fs.value(2).opcode == 0x9 && fs.value(2).payload.isEmpty());
    }
    {
        // A flood of minimal 2-byte frames (0x8A 0x00) -- the quadratic-DoS input.
        // With the moving cursor every frame still decodes and the buffer compacts.
        WsFrameParser p;
        QByteArray flood;
        const int N = 50000;
        for (int i = 0; i < N; ++i) { flood += char(0x8A); flood += char(0x00); }
        const auto fs = p.feed(flood);
        chk("flood: every tiny frame decoded (moving cursor)", fs.size() == N);
        chk("flood: buffer fully compacted", p.bufferedBytes() == 0);
    }

    // ===== absurd 64-bit length is FATAL (give-up, no resync) ===========
    {
        WsFrameParser p;
        QByteArray bad;
        bad += char(0x82); bad += char(0x7F);     // FIN+binary, 64-bit length
        for (int i = 0; i < 8; ++i) bad += char(0xFF);  // 0xFFFF... -> negative qint64
        bad += frame(0x1, "trailing");            // a valid frame behind the bad header
        const auto fs = p.feed(bad);
        chk("absurd-len: no frames emitted from the poisoned chunk", fs.isEmpty());
        // The parser must have GIVEN UP -- a subsequent valid frame yields nothing.
        const auto after = p.feed(frame(0x1, "later"));
        chk("absurd-len: parser gave up (subsequent valid frame ignored, no resync)",
            after.isEmpty() && p.bufferedBytes() == 0);
    }
    {
        // A positive but >16 MiB length is equally fatal.
        WsFrameParser p;
        QByteArray bad;
        bad += char(0x82); bad += char(0x7F);
        const qint64 huge = qint64(17) * 1024 * 1024;   // 17 MiB > 16 MiB cap
        for (int i = 7; i >= 0; --i) bad += char((huge >> (8 * i)) & 0xFF);
        const auto fs = p.feed(bad);
        chk("absurd-len: >16MiB declared length is fatal too", fs.isEmpty());
        chk("absurd-len: gave up after the >16MiB header", p.feed(frame(0x1, "x")).isEmpty());
    }

    // ===== buffer cap enforced BEFORE append (no transient over-alloc) ==
    {
        WsFrameParser p;
        const QByteArray oversized(33 * 1024 * 1024, 'x');   // > 32 MiB cap
        const auto fs = p.feed(oversized);
        chk("cap: an oversized chunk is rejected before growing the buffer",
            fs.isEmpty() && p.bufferedBytes() == 0);
        chk("cap: parser gave up after the oversized chunk", p.feed(frame(0x1, "x")).isEmpty());
    }

    // ===== RSV1 (permessage-deflate "compressed" bit) is surfaced =======
    {
        WsFrameParser p;
        QByteArray f;
        f += char(0xC1);          // FIN + RSV1 + text  (0x80|0x40|0x01)
        f += char(0x03);          // unmasked, len 3
        f += "abc";
        const auto fs = p.feed(f);
        chk("rsv1: frame parsed", fs.size() == 1);
        chk("rsv1: compressed bit read from 0x40", fs.value(0).rsv1);
        chk("rsv1: opcode masked to text (0x40 not folded in)", fs.value(0).opcode == 0x1);
    }
    {
        WsFrameParser p;
        const auto fs = p.feed(frame(0x1, "plain"));    // no RSV1
        chk("rsv1: uncompressed frame has rsv1=false", fs.size() == 1 && !fs.value(0).rsv1);
    }

    // ===== permessage-deflate inflate round-trips (RFC 7692) ============
    {
        z_stream ds; std::memset(&ds, 0, sizeof(ds));
        const int rc = deflateInit2(&ds, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                                    -15, 8, Z_DEFAULT_STRATEGY);
        chk("inflate: raw deflateInit2 ok", rc == Z_OK);

        WsInflater inf;
        chk("inflate: constructed healthy", inf.healthy());

        const QByteArray m1 = "Hello, permessage-deflate world!";
        const QByteArray c1 = deflateMsg(&ds, m1);
        bool ok1 = false;
        const QByteArray d1 = inf.inflateMessage(c1, &ok1);
        chk("inflate: message 1 ok", ok1);
        chk("inflate: message 1 round-trips", d1 == m1);

        // Message 2 under context-takeover: the deflater back-references the
        // window from message 1, so only a stateful inflater decodes it right.
        const QByteArray m2 = "Hello, permessage-deflate world! (again, compressible)";
        const QByteArray c2 = deflateMsg(&ds, m2);
        bool ok2 = false;
        const QByteArray d2 = inf.inflateMessage(c2, &ok2);
        chk("inflate: message 2 (context-takeover) ok", ok2);
        chk("inflate: message 2 round-trips", d2 == m2);
        chk("inflate: still healthy after two messages", inf.healthy());

        deflateEnd(&ds);
    }
    // A large, highly compressible message drives the multi-pass output loop.
    {
        z_stream ds; std::memset(&ds, 0, sizeof(ds));
        deflateInit2(&ds, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        WsInflater inf;
        const QByteArray big(512 * 1024, 'Q');     // 512 KiB
        const QByteArray c = deflateMsg(&ds, big);
        chk("inflate: 512KiB deflates small", c.size() < 4000);
        bool ok = false;
        const QByteArray d = inf.inflateMessage(c, &ok);
        chk("inflate: large message round-trips", ok && d == big);
        deflateEnd(&ds);
    }
    // Corrupt compressed bytes -> not ok AND the inflater is poisoned (the
    // shared window can no longer be trusted for subsequent messages).
    {
        WsInflater inf;
        const QByteArray garbage("\xDE\xAD\xBE\xEF\x01\x02\x03\x04", 8);
        bool ok = true;
        inf.inflateMessage(garbage, &ok);
        chk("inflate: corrupt input -> not ok", !ok);
        chk("inflate: corrupt input poisons the inflater", !inf.healthy());
        bool ok2 = true;
        inf.inflateMessage(QByteArray("anything"), &ok2);
        chk("inflate: poisoned inflater refuses further messages", !ok2);
    }

    std::fprintf(stderr, "websocket_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Security-boundary test for the WebSocket frame serializer + hold-eligibility.
// wsEncodeFrame is the ONE encoder for injected AND intercept-forwarded frames, so
// a framing/masking/length-boundary bug here is a wire-format bug on every path.
//
// Run via:  ctest -R ws_encode -V

#include "websocket.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Proxy;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
quint8 u(const QByteArray &b, int i) { return static_cast<quint8>(b.at(i)); }
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== unmasked text frame: exact byte layout =====
    {
        const QByteArray f = wsEncodeFrame(0x1, /*fin*/true, /*rsv1*/false, "hi", /*mask*/false);
        // 0x81 (FIN|text), 0x02 (unmasked len 2), 'h','i'
        chk("unmasked text: FIN|opcode byte == 0x81", u(f,0) == 0x81);
        chk("unmasked text: len byte == 2 (mask bit clear)", u(f,1) == 0x02);
        chk("unmasked text: payload appended raw", f.mid(2) == QByteArray("hi"));
        chk("unmasked text: total size == 4", f.size() == 4);
    }
    // ===== FIN and RSV1 bits =====
    {
        const QByteArray nf = wsEncodeFrame(0x2, /*fin*/false, /*rsv1*/false, "x", false);
        chk("fin=false clears 0x80", (u(nf,0) & 0x80) == 0 && (u(nf,0) & 0x0F) == 0x2);
        const QByteArray cf = wsEncodeFrame(0x1, /*fin*/true, /*rsv1*/true, "x", false);
        chk("rsv1=true sets 0x40 (compressed bit)", (u(cf,0) & 0x40) == 0x40);
        const QByteArray pf = wsEncodeFrame(0x1, /*fin*/true, /*rsv1*/false, "x", false);
        chk("rsv1=false clears 0x40", (u(pf,0) & 0x40) == 0);
    }
    // ===== length-boundary encoding (unmasked so bytes are deterministic) =====
    {
        auto lenOf = [](int n) { return wsEncodeFrame(0x2, true, false, QByteArray(n, 'a'), false); };
        const QByteArray a = lenOf(125);   // inline
        chk("len 125: single length byte == 125", u(a,1) == 125 && a.size() == 2 + 125);
        const QByteArray b = lenOf(126);   // 16-bit
        chk("len 126: marker 126 + 2 length bytes (00 7E)",
            u(b,1) == 126 && u(b,2) == 0x00 && u(b,3) == 0x7E && b.size() == 4 + 126);
        const QByteArray c = lenOf(65535); // 16-bit max
        chk("len 65535: marker 126 + FF FF",
            u(c,1) == 126 && u(c,2) == 0xFF && u(c,3) == 0xFF && c.size() == 4 + 65535);
        const QByteArray d = lenOf(65536); // 64-bit
        chk("len 65536: marker 127 + 8-byte length (…00 01 00 00)",
            u(d,1) == 127 && u(d,2) == 0 && u(d,6) == 0 && u(d,7) == 0x01
            && u(d,8) == 0x00 && u(d,9) == 0x00 && d.size() == 10 + 65536);
    }
    // ===== masked (client->server): mask bit + fresh key + recoverable payload =====
    {
        const QByteArray body = "SECRET-PAYLOAD-0123";
        const QByteArray f = wsEncodeFrame(0x1, true, false, body, /*mask*/true);
        chk("masked: mask bit set on length byte", (u(f,1) & 0x80) == 0x80);
        chk("masked: declared length is the body length", (u(f,1) & 0x7F) == body.size());
        // header(2) + key(4) + masked payload(len)
        chk("masked: total size == 2 + 4 + len", f.size() == 2 + 4 + body.size());
        // unmask with the emitted key -> recovers the original payload
        const quint8 k[4] = { u(f,2), u(f,3), u(f,4), u(f,5) };
        QByteArray un;
        for (int i = 0; i < body.size(); ++i) un.append(char(u(f, 6 + i) ^ k[i & 3]));
        chk("masked: XOR with the emitted key recovers the payload", un == body);
        // the key must not be the trivial all-zero (payload would be sent in clear)
        chk("masked: key is not all-zero", !(k[0]==0 && k[1]==0 && k[2]==0 && k[3]==0));
        // masked bytes actually differ from the plaintext somewhere (real masking)
        chk("masked: on-wire bytes differ from plaintext", f.mid(6) != body);
    }

    // ===== wsHoldEligible: only an uncompressed text/binary data message =====
    chk("eligible: text 0x1 uncompressed",   wsHoldEligible(0x1, false, false, false));
    chk("eligible: binary 0x2 uncompressed", wsHoldEligible(0x2, false, false, false));
    chk("NOT eligible: continuation 0x0",   !wsHoldEligible(0x0, false, false, false));
    chk("NOT eligible: close 0x8",          !wsHoldEligible(0x8, false, false, false));
    chk("NOT eligible: ping 0x9",           !wsHoldEligible(0x9, false, false, false));
    chk("NOT eligible: pong 0xA",           !wsHoldEligible(0xA, false, false, false));
    chk("NOT eligible: text but rsv1 (compressed)", !wsHoldEligible(0x1, true, false, false));
    chk("NOT eligible: text but rsv2",      !wsHoldEligible(0x1, false, true, false));
    chk("NOT eligible: text but rsv3",      !wsHoldEligible(0x1, false, false, true));

    std::fprintf(stderr, "ws_encode_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

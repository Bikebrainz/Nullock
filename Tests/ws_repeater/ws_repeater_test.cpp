// WebSocket Repeater: frame construction + the send dispatch contract.
//
// Two things are pinned here.
//
// 1. buildFrame(). It is private and static, so before sendFrame became
//    asynchronous there was no way to observe its output without a live
//    tunnel -- which is why this RFC 6455 encoder shipped untested. Now that
//    the frame travels out on frameQueued() the bytes are inspectable, so the
//    length forms, the mask, and the opcode truncation all get checked.
//
// 2. That sendFrame() does NOT touch the socket. It used to pull a raw pointer
//    out of a QPointer, dereference it for raw->thread(), and hand that same
//    pointer to invokeMethod as a BlockingQueuedConnection receiver -- all
//    after releasing the mutex, so the socket could be destroyed underneath it.
//    The sockets registered below are never connected to anything: under the
//    old implementation every send here returns false and emits nothing,
//    because raw->state() != ConnectedState. Under the current one the frame is
//    queued for the relay that owns the tunnel and the caller is not blocked.
//    That difference is what these cases are for.
//
// There is deliberately no event loop in this file. sendFrame must complete on
// the calling thread; if it ever goes back to waiting on another one, these
// cases hang instead of failing, which is itself the signal.

#include "ws_repeater.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QList>
#include <QTcpSocket>

#include <cstdio>

using namespace Nullock::Proxy;

static int pass = 0, fail = 0;
static void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Catches frameQueued for as long as it is in scope. This is deliberately a
// hand-rolled recorder rather than QSignalSpy: Qt6::Test is not among the
// components the top-level CMakeLists resolves, and adding it would make this
// suite the only one that needs it -- a configure-time failure risk for the
// whole build in exchange for nothing this five-line struct doesn't do.
//
// The connection is direct (emitter and receiver share this thread), so a frame
// is recorded by the time sendFrame returns.
struct Recorder {
    struct Frame { qint64 id; QByteArray bytes; bool toUpstream; };
    QList<Frame> frames;
    QMetaObject::Connection conn;

    explicit Recorder(WsRepeater *r) {
        conn = QObject::connect(r, &WsRepeater::frameQueued,
                                [this](qint64 id, const QByteArray &b, bool up) {
                                    frames.append({ id, b, up });
                                });
    }
    ~Recorder() { QObject::disconnect(conn); }

    int count() const { return int(frames.size()); }
};

// Pull the one frame a recorder captured. Returns false if the count isn't 1,
// so "exactly one frame" is checked everywhere the payload is.
static bool takeFrame(const Recorder &rec, qint64 *id, QByteArray *bytes, bool *toUpstream) {
    if (rec.count() != 1) return false;
    *id         = rec.frames.first().id;
    *bytes      = rec.frames.first().bytes;
    *toUpstream = rec.frames.first().toUpstream;
    return true;
}

// Undo the RFC 6455 client mask so the payload can be compared to what went in.
// `body` is the frame from the first payload byte on: 4 mask bytes, then data.
static QByteArray unmask(const QByteArray &body) {
    QByteArray out;
    if (body.size() < 4) return out;
    const quint8 m[4] = { quint8(body.at(0)), quint8(body.at(1)),
                          quint8(body.at(2)), quint8(body.at(3)) };
    for (int i = 4; i < body.size(); ++i)
        out.append(char(quint8(body.at(i)) ^ m[(i - 4) & 3]));
    return out;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    WsRepeater *r = WsRepeater::instance();

    // Never connected, never bound. They exist only as the identities the
    // session map records -- see the header comment.
    QTcpSocket client, upstream;

    // ---- no session -------------------------------------------------------
    {
        Recorder spy(r);
        chk("unknown session: sendFrame returns false",
            !r->sendFrame(999999, "up", 0x1, "hello"));
        chk("unknown session: nothing is queued", spy.count() == 0);
    }

    const qint64 id = r->registerSession(&client, &upstream, "example.test", 443);
    chk("register: returns a positive id", id > 0);

    // ---- the regression itself -------------------------------------------
    // Both sockets are UnconnectedState. The old socket-touching implementation
    // bailed out here; the current one queues for the owning relay instead.
    {
        Recorder spy(r);
        const bool ok = r->sendFrame(id, "up", 0x1, "hi");
        chk("live session, unconnected socket: still reports queued", ok);
        chk("live session: exactly one frame is queued", spy.count() == 1);
    }

    // ---- direction --------------------------------------------------------
    // "up"/"client"/"upstream" all mean client->server, which is the masked
    // direction. Anything else is server->client and must NOT be masked.
    {
        for (const char *up : { "up", "client", "upstream", "UP", "Client" }) {
            Recorder spy(r);
            r->sendFrame(id, QString::fromLatin1(up), 0x1, "x");
            qint64 gotId = 0; QByteArray bytes; bool toUpstream = false;
            chk("direction: one frame per send", takeFrame(spy, &gotId, &bytes, &toUpstream));
            chk("direction: recognised as client->server", toUpstream);
            chk("direction: client frames set the mask bit",
                bytes.size() > 1 && (quint8(bytes.at(1)) & 0x80));
        }
        for (const char *down : { "down", "server", "", "sideways" }) {
            Recorder spy(r);
            r->sendFrame(id, QString::fromLatin1(down), 0x1, "x");
            qint64 gotId = 0; QByteArray bytes; bool toUpstream = true;
            chk("direction: one frame per send", takeFrame(spy, &gotId, &bytes, &toUpstream));
            chk("direction: anything not 'up'-ish is server->client", !toUpstream);
            chk("direction: server frames must not be masked",
                bytes.size() > 1 && !(quint8(bytes.at(1)) & 0x80));
        }
    }

    // ---- the frame's id routes it to the right relay ----------------------
    {
        const qint64 second = r->registerSession(&client, &upstream, "other.test", 80);
        chk("register: a second session gets a distinct id", second != id);
        Recorder spy(r);
        r->sendFrame(second, "down", 0x1, "x");
        qint64 gotId = 0; QByteArray bytes; bool toUpstream = true;
        chk("routing: one frame", takeFrame(spy, &gotId, &bytes, &toUpstream));
        chk("routing: the frame carries the session it was sent to", gotId == second);
        r->deregisterSession(second);
        chk("deregister: sending to a closed session returns false",
            !r->sendFrame(second, "down", 0x1, "x"));
    }

    // ---- header byte: FIN + opcode ---------------------------------------
    {
        Recorder spy(r);
        r->sendFrame(id, "down", 0x2, "abc");   // binary
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("header: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("header: FIN is always set (we only build single-fragment frames)",
            b.size() > 0 && (quint8(b.at(0)) & 0x80));
        chk("header: RSV bits are clear", b.size() > 0 && !(quint8(b.at(0)) & 0x70));
        chk("header: opcode lands in the low nibble",
            b.size() > 0 && (quint8(b.at(0)) & 0x0F) == 0x2);
    }
    {
        // An opcode wider than 4 bits is truncated, not smeared into RSV/FIN.
        Recorder spy(r);
        r->sendFrame(id, "down", 0xF1, "x");
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("opcode: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("opcode: 0xF1 is masked down to 0x1", b.size() > 0 && quint8(b.at(0)) == 0x81);
    }

    // ---- payload length forms (RFC 6455 5.2) ------------------------------
    {
        // < 126: the length is the low 7 bits of byte 1, no extension.
        const QByteArray small(5, 'a');
        Recorder spy(r);
        r->sendFrame(id, "down", 0x1, small);
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("len<126: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("len<126: length is inline", b.size() > 1 && (quint8(b.at(1)) & 0x7F) == 5);
        chk("len<126: no extended length field", b.size() == 2 + 5);
        chk("len<126: payload is verbatim", b.mid(2) == small);
    }
    {
        // 126..65535: marker 126 then a 2-byte big-endian length.
        const QByteArray mid(200, 'b');
        Recorder spy(r);
        r->sendFrame(id, "down", 0x1, mid);
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("len=200: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("len=200: marker is 126", b.size() > 1 && (quint8(b.at(1)) & 0x7F) == 126);
        chk("len=200: 2-byte big-endian length follows",
            b.size() > 3 && quint8(b.at(2)) == 0x00 && quint8(b.at(3)) == 0xC8);
        chk("len=200: total size is 4 + payload", b.size() == 4 + 200);
        chk("len=200: payload is verbatim", b.mid(4) == mid);
    }
    {
        // The 125/126 boundary is where the encoding switches. Both sides.
        for (int n : { 125, 126 }) {
            const QByteArray p(n, 'c');
            Recorder spy(r);
            r->sendFrame(id, "down", 0x1, p);
            qint64 gotId = 0; QByteArray b; bool up = true;
            chk("boundary: one frame", takeFrame(spy, &gotId, &b, &up));
            if (n == 125) {
                chk("boundary: 125 still uses the inline length",
                    b.size() == 2 + 125 && (quint8(b.at(1)) & 0x7F) == 125);
            } else {
                chk("boundary: 126 switches to the 2-byte form",
                    b.size() == 4 + 126 && (quint8(b.at(1)) & 0x7F) == 126
                    && quint8(b.at(2)) == 0x00 && quint8(b.at(3)) == 0x7E);
            }
        }
    }
    {
        // > 65535: marker 127 then an 8-byte big-endian length whose top bit
        // must be 0 per the RFC.
        const QByteArray big(70000, 'd');
        Recorder spy(r);
        r->sendFrame(id, "down", 0x1, big);
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("len=70000: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("len=70000: marker is 127", b.size() > 1 && (quint8(b.at(1)) & 0x7F) == 127);
        chk("len=70000: high bit of the 64-bit length is clear",
            b.size() > 2 && !(quint8(b.at(2)) & 0x80));
        bool lenOk = b.size() >= 10;
        if (lenOk) {
            quint64 declared = 0;
            for (int i = 2; i < 10; ++i) declared = (declared << 8) | quint8(b.at(i));
            lenOk = (declared == 70000);
        }
        chk("len=70000: the declared 64-bit length matches the payload", lenOk);
        chk("len=70000: total size is 10 + payload", b.size() == 10 + 70000);
        chk("len=70000: payload is verbatim", b.mid(10) == big);
    }
    {
        // Empty payload is legal (a ping, a close with no reason).
        Recorder spy(r);
        r->sendFrame(id, "down", 0x9, QByteArray());
        qint64 gotId = 0; QByteArray b; bool up = true;
        chk("empty: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("empty: a 2-byte header and nothing else",
            b.size() == 2 && quint8(b.at(0)) == 0x89 && quint8(b.at(1)) == 0x00);
    }

    // ---- masking ----------------------------------------------------------
    {
        const QByteArray payload = "the quick brown fox";
        Recorder spy(r);
        r->sendFrame(id, "up", 0x1, payload);
        qint64 gotId = 0; QByteArray b; bool up = false;
        chk("mask: one frame", takeFrame(spy, &gotId, &b, &up));
        chk("mask: frame grows by exactly the 4-byte key",
            b.size() == 2 + 4 + payload.size());
        chk("mask: unmasking with the frame's own key restores the payload",
            unmask(b.mid(2)) == payload);
        chk("mask: the masked bytes are not just the plaintext",
            b.mid(6) != payload);
    }
    {
        // The key is drawn per frame; two identical sends must not produce
        // identical wire bytes, or the mask is not doing its job.
        const QByteArray payload(64, 'z');
        QByteArray first, second;
        {
            Recorder spy(r);
            r->sendFrame(id, "up", 0x1, payload);
            qint64 gid = 0; bool up = false;
            takeFrame(spy, &gid, &first, &up);
        }
        {
            Recorder spy(r);
            r->sendFrame(id, "up", 0x1, payload);
            qint64 gid = 0; bool up = false;
            takeFrame(spy, &gid, &second, &up);
        }
        chk("mask: a fresh key per frame", first != second);
        chk("mask: both still decode to the same payload",
            unmask(first.mid(2)) == payload && unmask(second.mid(2)) == payload);
    }

    // ---- counters ---------------------------------------------------------
    {
        r->noteFrame(id, true);
        r->noteFrame(id, true);
        r->noteFrame(id, false);
        bool found = false;
        for (const WsSessionInfo &s : r->sessions()) {
            if (s.id != id) continue;
            found = true;
            chk("counters: up frames counted", s.framesUp == 2);
            chk("counters: down frames counted separately", s.framesDown == 1);
            chk("counters: host survives registration", s.host == "example.test");
            chk("counters: port survives registration", s.port == 443);
        }
        chk("counters: the session is listed", found);
        r->noteFrame(123456, true);   // unknown id: must be a no-op, not a crash
    }

    // ---- teardown ---------------------------------------------------------
    {
        r->deregisterSession(id);
        Recorder spy(r);
        chk("teardown: closed session rejects sends", !r->sendFrame(id, "up", 0x1, "x"));
        chk("teardown: and queues nothing", spy.count() == 0);
        bool stillListed = false;
        for (const WsSessionInfo &s : r->sessions())
            if (s.id == id) stillListed = true;
        chk("teardown: the session is gone from sessions()", !stillListed);
        r->deregisterSession(id);   // double deregister: no-op
        chk("teardown: deregistering twice is harmless", r->sessions().isEmpty());
    }

    std::fprintf(stderr, "\nws_repeater: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

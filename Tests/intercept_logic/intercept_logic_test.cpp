// Regression corpus for the intercept controller's outgoing-byte resolver.
//
// An intercepting proxy must pass traffic through faithfully. The controller
// decodes each captured request to a QString for the editor and, on Forward,
// produced m_text.toUtf8(). That round-trip is LOSSY for any non-UTF-8 body
// (file upload, gzip, protobuf, raw 0x80..0xFF): each undecodable byte becomes
// U+FFFD, so the re-encoded body differs from the original AND its length no
// longer matches Content-Length -- silently corrupting the body and desyncing
// the upstream stream on a *passive* forward the operator never touched.
//
// resolveForwardBytes() fixes it: unedited -> forward the captured bytes
// verbatim; edited -> re-encode (the operator's explicit choice). This test
// first PROVES the naive round-trip corrupts (so the fix is necessary), then
// locks the corrected behaviour.
//
// Run via:  ctest -R intercept_logic -V

#include "intercept_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Proxy::InterceptLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// The naive round-trip the fix replaces -- used to prove the bug is real.
QByteArray naiveRoundTrip(const QByteArray &bytes) {
    return QString::fromUtf8(bytes).toUtf8();
}

// A request with a binary body and a matching Content-Length.
QByteArray binaryRequest(const QByteArray &body) {
    QByteArray req;
    req += "POST /upload HTTP/1.1\r\n";
    req += "Host: target.example\r\n";
    req += "Content-Type: application/octet-stream\r\n";
    req += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    return req;
}

// Extract the integer value of the (first) Content-Length header.
int declaredContentLength(const QByteArray &req) {
    const int h = req.indexOf("Content-Length: ");
    if (h < 0) return -1;
    const int v = h + int(sizeof("Content-Length: ") - 1);
    const int eol = req.indexOf("\r\n", v);
    return req.mid(v, eol - v).trimmed().toInt();
}

// Length of the body (everything past the blank line).
int actualBodyLength(const QByteArray &req) {
    const int sep = req.indexOf("\r\n\r\n");
    if (sep < 0) return -1;
    return req.size() - (sep + 4);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== ground truth: the naive round-trip really corrupts binary =====
    // A lone 0x80 / 0xFF is not valid UTF-8 -> fromUtf8 yields U+FFFD ->
    // toUtf8 emits 3 bytes (EF BF BD). The round-trip is lossy in BOTH content
    // and length. This is the bug the resolver exists to prevent.
    {
        QByteArray bin;
        bin.append(char(0x80)).append(char(0xFF)).append(char(0x00)).append(char(0xC0));
        chk("ground-truth: naive round-trip CHANGES a binary blob", naiveRoundTrip(bin) != bin);
        chk("ground-truth: naive round-trip GROWS the byte count", naiveRoundTrip(bin).size() != bin.size());
    }

    // ===== unedited forward preserves bytes verbatim =====================
    {
        // valid-UTF-8 request, operator did not edit it.
        const QByteArray req = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited ascii: bytes preserved exactly", out == req);
    }
    {
        // binary body, unedited -> MUST be byte-for-byte identical.
        QByteArray body;
        for (int b = 0; b < 256; ++b) body.append(char(b));   // every byte value
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited binary: full 0..255 body preserved verbatim", out == req);
        chk("unedited binary: not the corrupting naive path", out == req && out != naiveRoundTrip(req));
    }
    {
        // the Content-Length invariant the bug used to break.
        QByteArray body;
        body.append(char(0x80)).append(char(0x81)).append("PNG\x89", 4).append(char(0xFF));
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited binary: Content-Length still matches body", declaredContentLength(out) == actualBodyLength(out));
        chk("unedited binary: naive path WOULD have broken Content-Length",
            declaredContentLength(naiveRoundTrip(req)) != actualBodyLength(naiveRoundTrip(req)));
    }
    {
        // embedded NUL in body, unedited -> preserved.
        QByteArray body("a\0b\0c", 5);
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited: embedded NUL body preserved", out == req);
        chk("unedited: embedded NUL output keeps full length", out.size() == req.size());
    }
    {
        // multi-byte VALID UTF-8 (cafe with U+00E9), unedited -> preserved and
        // identical to the naive path (valid UTF-8 round-trips losslessly).
        QByteArray body;
        body.append("caf").append(char(0xC3)).append(char(0xA9));   // "café"
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited valid-utf8: preserved", out == req);
        chk("unedited valid-utf8: matches naive (lossless here)", out == naiveRoundTrip(req));
    }

    // ===== edited forward uses the operator's text =======================
    {
        const QByteArray req = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const QString edited = QString::fromUtf8("GET /b HTTP/1.1\r\nHost: x\r\nX-Edit: 1\r\n\r\n");
        const QByteArray out = resolveForwardBytes(req, edited);
        chk("edited: returns the edited text encoded", out == edited.toUtf8());
        chk("edited: differs from the original", out != req);
    }
    {
        // editing a binary-body request: the edit wins (operator's choice),
        // even though it is lossy -- we just confirm it is the edited text.
        QByteArray body; body.append(char(0x80)).append(char(0xFF));
        const QByteArray req = binaryRequest(body);
        const QString edited = QString::fromUtf8(req) + QString("X-Added: yes\r\n");
        const QByteArray out = resolveForwardBytes(req, edited);
        chk("edited binary: returns edited text's utf8", out == edited.toUtf8());
    }

    // ===== intercept queue backpressure cap =============================
    // The cap bounds simultaneously-parked intercepted requests so a flood of
    // in-scope traffic can't pin unbounded worker threads + secret-bearing
    // bytes. At/over the cap, the caller auto-forwards instead of enqueueing.
    chk("cap: empty queue has room", interceptQueueHasRoom(0));
    chk("cap: one below cap has room", interceptQueueHasRoom(kMaxPendingIntercepts - 1));
    chk("cap: exactly at cap is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts));
    chk("cap: over cap is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts + 1));
    chk("cap: a wildly-over count is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts * 10));
    chk("cap: negative count is defensive room (not full)", interceptQueueHasRoom(-1));
    chk("cap: the cap is a sane positive bound", kMaxPendingIntercepts > 0 && kMaxPendingIntercepts <= 4096);

    // ===== degenerate inputs ============================================
    chk("empty bytes + empty text -> empty", resolveForwardBytes(QByteArray(), QString()).isEmpty());
    {
        const QByteArray req = "x";
        // empty edit string is a real (if odd) edit -> NOT equal to fromUtf8("x")
        const QByteArray out = resolveForwardBytes(req, QString());
        chk("non-empty original + empty edit -> empty (treated as edit)", out.isEmpty());
    }
    {
        // unedited single byte preserved
        const QByteArray req = "x";
        chk("unedited single byte preserved", resolveForwardBytes(req, QString::fromUtf8(req)) == req);
    }

    std::fprintf(stderr, "intercept_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

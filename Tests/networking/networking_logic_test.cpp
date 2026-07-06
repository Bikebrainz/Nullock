// Unit coverage for the PURE HTTP-response parsing cores in
// networking_logic.cpp -- every byte they touch is attacker / MitM-controlled.
// Locks two findings against regression:
//   * FINDING A (Content-Length): a present-but-malformed CL (non-numeric,
//     negative, over-cap) must be REJECTED, not silently turned into an empty
//     or mis-sized body. parseContentLength enforces that.
//   * FINDING B / MED (chunked OOM): an endless chunk-size line or trailer with
//     NO terminating CRLF must be rejected once it passes kMaxChunkLineBytes,
//     and a peer can't grow `decoded` past kMaxBodyBytes. feedChunked enforces
//     those caps; the §2 "...-flood error" cases below pin them.
// Also exercises parseStatusLine / parseHeaders / findHeader / parseChunkSizeLine.
//
// Pure -- QByteArray/QString only, no socket -- so it compiles networking_logic.cpp
// directly and links Qt6::Core ALONE.
//
// Run via:  ctest -R networking_logic -V

#include "networking_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::NetworkingLogic;

namespace {
int pass = 0, fail = 0;

void chkb(const char *label, bool got, bool want) {
    if (got == want) { ++pass; return; }
    std::fprintf(stderr, "  FAIL  %s: got %d, want %d\n", label, int(got), int(want));
    ++fail;
}
void chki(const char *label, long long got, long long want) {
    if (got == want) { ++pass; return; }
    std::fprintf(stderr, "  FAIL  %s: got %lld, want %lld\n", label, got, want);
    ++fail;
}
void chks(const char *label, const QString &got, const QString &want) {
    if (got == want) { ++pass; return; }
    std::fprintf(stderr, "  FAIL  %s: got \"%s\", want \"%s\"\n",
                 label, got.toUtf8().constData(), want.toUtf8().constData());
    ++fail;
}
const char *dname(ChunkDecode d) {
    switch (d) {
    case ChunkDecode::NeedMore: return "NeedMore";
    case ChunkDecode::Done:     return "Done";
    case ChunkDecode::Error:    return "Error";
    }
    return "?";
}
void chkd(const char *label, ChunkDecode got, ChunkDecode want) {
    if (got == want) { ++pass; return; }
    std::fprintf(stderr, "  FAIL  %s: got %s, want %s\n", label, dname(got), dname(want));
    ++fail;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseStatusLine ===============================================
    {
        const auto s = parseStatusLine("HTTP/1.1 200 OK");
        chkb("status ok", s.ok, true);
        chks("status version", s.httpVersion, "HTTP/1.1");
        chki("status code", s.statusCode, 200);
        chks("status reason", s.reasonPhrase, "OK");
    }
    {
        const auto s = parseStatusLine("HTTP/1.1 404 Not Found");
        chkb("status multi-word reason ok", s.ok, true);
        chki("status 404", s.statusCode, 404);
        chks("status reason multi", s.reasonPhrase, "Not Found");
    }
    {
        // reason MAY be empty, but the 2nd SP must be present.
        const auto s = parseStatusLine("HTTP/1.1 204 ");
        chkb("status empty-reason ok", s.ok, true);
        chki("status 204", s.statusCode, 204);
        chks("status empty reason", s.reasonPhrase, "");
    }
    chkb("status empty => !ok",      parseStatusLine("").ok,          false);
    chkb("status no space => !ok",   parseStatusLine("HTTP/1.1").ok,  false);
    chkb("status one space => !ok",  parseStatusLine("HTTP/1.1 200").ok, false);
    {
        // structurally valid (two spaces) but a non-numeric code -> 0
        const auto s = parseStatusLine("HTTP/1.1 ?? x");
        chkb("status garbage-code structurally ok", s.ok, true);
        chki("status garbage-code => 0", s.statusCode, 0);
    }

    // ===== parseHeaders ==================================================
    {
        const QByteArray block =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Foo:  bar \r\nEmpty:";
        const auto h = parseHeaders(block);
        chki("headers count", h.size(), 3);
        chks("header 0 key", h[0].first, "Content-Type");
        chks("header 0 val", h[0].second, "text/html");
        chks("header 1 key trimmed", h[1].first, "X-Foo");
        chks("header 1 val trimmed", h[1].second, "bar");
        chks("header 2 empty val", h[2].second, "");
    }
    {
        // line 0 (status) skipped; no-colon dropped; colon-at-0 dropped.
        const QByteArray block =
            "STATUS LINE\r\nNoColonHere\r\n: leadingcolon\r\nA: b";
        const auto h = parseHeaders(block);
        chki("headers skip status+nocolon+leadcolon", h.size(), 1);
        chks("headers lone valid key", h[0].first, "A");
        chks("headers lone valid val", h[0].second, "b");
    }
    {
        const QByteArray block = "STATUS\nA: 1\nB: 2";   // bare-LF separated
        const auto h = parseHeaders(block);
        chki("headers bare-LF count", h.size(), 2);
        chks("headers bare-LF B", h[1].second, "2");
    }
    {
        // many headers: no crash, correct count (the byte bound is upstream).
        QByteArray block = "STATUS\r\n";
        for (int i = 0; i < 500; ++i) block += "H: v\r\n";
        chki("headers many", parseHeaders(block).size(), 500);
    }

    // ===== findHeader (case-insensitive, first wins) =====================
    {
        QList<QPair<QString, QString>> h{
            {"Content-Length", "5"}, {"content-length", "9"}, {"X", "y"}};
        chks("findHeader CI first wins", findHeader(h, "CONTENT-LENGTH"), "5");
        chks("findHeader miss => empty", findHeader(h, "Nope"), "");
    }

    // ===== parseContentLength (FINDING A fix) ============================
    {
        const auto c = parseContentLength("5");
        chkb("CL 5 ok", c.ok, true);
        chki("CL 5 value", c.value, 5);
    }
    chkb("CL 0 ok", parseContentLength("0").ok, true);
    {
        const auto c = parseContentLength("  42 ");   // trimmed
        chkb("CL trimmed ok", c.ok, true);
        chki("CL trimmed value", c.value, 42);
    }
    chkb("CL negative => !ok",       parseContentLength("-5").ok,       false);
    chkb("CL garbage => !ok",        parseContentLength("garbage").ok,  false);
    chkb("CL hex-ish 0x10 => !ok",   parseContentLength("0x10").ok,     false);
    chkb("CL trailing junk => !ok",  parseContentLength("5abc").ok,     false);
    chkb("CL empty => !ok",          parseContentLength("").ok,         false);
    chkb("CL at cap ok",
         parseContentLength(QString::number(kMaxBodyBytes)).ok, true);
    chkb("CL over cap => !ok",
         parseContentLength(QString::number(kMaxBodyBytes + 1)).ok, false);
    chkb("CL huge => !ok",           parseContentLength("999999999999").ok, false);

    // ===== parseChunkSizeLine ============================================
    {
        const auto c = parseChunkSizeLine("5");
        chkb("chunk 5 ok", c.ok, true);
        chki("chunk 5 value", c.size, 5);
    }
    chki("chunk ff => 255", parseChunkSizeLine("ff").size, 255);
    chki("chunk a => 10",   parseChunkSizeLine("a").size, 10);
    {
        const auto c = parseChunkSizeLine("5;foo=bar");   // extension stripped
        chkb("chunk ext ok", c.ok, true);
        chki("chunk ext value", c.size, 5);
    }
    {
        const auto c = parseChunkSizeLine("  1a  ");       // trimmed hex
        chkb("chunk trimmed ok", c.ok, true);
        chki("chunk trimmed value", c.size, 26);
    }
    chkb("chunk 0 ok",            parseChunkSizeLine("0").ok, true);
    chki("chunk 0 value",         parseChunkSizeLine("0").size, 0);
    chkb("chunk empty => !ok",    parseChunkSizeLine("").ok, false);
    chkb("chunk non-hex => !ok",  parseChunkSizeLine("xyz").ok, false);
    chkb("chunk negative => !ok", parseChunkSizeLine("-1").ok, false);
    // hex exactly at cap (128 MiB == 0x8000000) ok; +1 over cap.
    chkb("chunk at cap ok",       parseChunkSizeLine("8000000").ok, true);
    chki("chunk at cap value",    parseChunkSizeLine("8000000").size, kMaxBodyBytes);
    chkb("chunk over cap => !ok", parseChunkSizeLine("8000001").ok, false);
    chkb("chunk FFFFFFFF => !ok", parseChunkSizeLine("FFFFFFFF").ok, false);

    // ===== feedChunked: happy paths ======================================
    {
        QByteArray buf = "5\r\nhello\r\n0\r\n\r\n", dec;
        chkd("feed single done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed single decoded", QString::fromLatin1(dec), "hello");
        chki("feed single buffer drained", buf.size(), 0);
    }
    {
        QByteArray buf = "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", dec;
        chkd("feed multi done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed multi decoded", QString::fromLatin1(dec), "abcde");
    }
    {
        QByteArray buf = "5;x=1\r\nhello\r\n0\r\n\r\n", dec;   // ext in data path
        chkd("feed ext done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed ext decoded", QString::fromLatin1(dec), "hello");
    }
    {
        QByteArray buf = "0\r\n\r\n", dec;                    // immediately-empty body
        chkd("feed empty-term done", feedChunked(buf, dec), ChunkDecode::Done);
        chki("feed empty-term decoded size", dec.size(), 0);
    }
    {
        QByteArray buf = "3\r\nabc\r\n0\r\nX-Trailer: y\r\n\r\n", dec;  // term + trailer
        chkd("feed trailer done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed trailer decoded", QString::fromLatin1(dec), "abc");
    }

    // ===== feedChunked: NeedMore must NOT consume ========================
    {
        QByteArray buf = "5", dec;                            // partial size line
        chkd("feed partial-size needmore", feedChunked(buf, dec), ChunkDecode::NeedMore);
        chks("feed partial-size not consumed", QString::fromLatin1(buf), "5");
    }
    {
        QByteArray buf = "5\r\nhel", dec;                     // partial chunk data
        chkd("feed partial-data needmore", feedChunked(buf, dec), ChunkDecode::NeedMore);
        chki("feed partial-data not consumed", buf.size(), 6);
        chki("feed partial-data no decode yet", dec.size(), 0);
        buf += "lo\r\n0\r\n\r\n";                             // complete it
        chkd("feed completed done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed completed decoded", QString::fromLatin1(dec), "hello");
    }
    {
        QByteArray buf = "0\r\n", dec;                        // trailer not terminated
        chkd("feed partial-trailer needmore", feedChunked(buf, dec), ChunkDecode::NeedMore);
    }

    // ===== feedChunked: malformed ========================================
    {
        QByteArray buf = "zz\r\nhello\r\n0\r\n\r\n", dec;
        chkd("feed bad-size error", feedChunked(buf, dec), ChunkDecode::Error);
    }
    {
        // A chunk's trailing CRLF replaced by other bytes must be REJECTED, not
        // silently swallowed (would let a hostile upstream steer the decode).
        QByteArray buf = "5\r\nhelloXX3\r\nfoo\r\n0\r\n\r\n", dec;
        chkd("feed mis-framed inter-chunk CRLF -> error",
             feedChunked(buf, dec), ChunkDecode::Error);
    }
    {
        // Sanity: the same stream with the correct CRLF decodes cleanly.
        QByteArray buf = "5\r\nhello\r\n3\r\nfoo\r\n0\r\n\r\n", dec;
        chkd("feed two-chunk done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed two-chunk decoded", QString::fromLatin1(dec), "hellofoo");
    }

    // ===== feedChunked: the MED unbounded-stream LOCKS (§2) ==============
    {
        // Endless chunk-size line, NO CRLF anywhere -> Error past the cap.
        QByteArray buf(kMaxChunkLineBytes + 1, 'a'), dec;
        chkd("feed sizeline-flood error", feedChunked(buf, dec), ChunkDecode::Error);
    }
    {
        // Under the cap, no CRLF yet -> still a legit NeedMore.
        QByteArray buf(1024, 'a'), dec;
        chkd("feed sizeline-small needmore", feedChunked(buf, dec), ChunkDecode::NeedMore);
    }
    {
        // Endless trailer after the 0-chunk, NO terminating CRLF -> Error.
        QByteArray buf = QByteArray("0\r\n") + QByteArray(kMaxChunkLineBytes + 1, 'a');
        QByteArray dec;
        chkd("feed trailer-flood error", feedChunked(buf, dec), ChunkDecode::Error);
    }

    // ===== fuzz: feedChunked eats attacker-controlled response bodies, so it
    // must never crash / grow unbounded on arbitrary bytes, and always return a
    // valid outcome. Deterministic PRNG; a bias toward chunked-relevant chars
    // so many inputs actually reach the size-line / data / trailer logic. =====
    {
        uint32_t rng = 0x9e3779b9u;
        auto rnd = [&rng]() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; };
        const char pool[] = "0123456789abcdefABCDEF\r\n;xyz ";
        bool bounded = true, validOutcome = true;
        for (int iter = 0; iter < 8000; ++iter) {
            QByteArray buf;
            const int n = int(rnd() % 220);
            for (int i = 0; i < n; ++i) buf += pool[rnd() % (sizeof(pool) - 1)];
            QByteArray dec;
            const ChunkDecode r = feedChunked(buf, dec);   // must not crash (mutates buf)
            if (r != ChunkDecode::NeedMore && r != ChunkDecode::Done && r != ChunkDecode::Error)
                validOutcome = false;
            if (dec.size() > 64LL * 1024 * 1024) bounded = false;   // body cap holds
        }
        chkb("fuzz: feedChunked survived 8k random chunked-ish inputs (no crash)", true, true);
        chkb("fuzz: feedChunked always returned a valid outcome", validOutcome, true);
        chkb("fuzz: feedChunked decoded stayed within the body cap", bounded, true);
    }

    // ===== fuzz: parseStatusLine reads the origin's HTTP status line, which is
    // attacker-controlled upstream in a MITM, so it must never crash on arbitrary
    // bytes. Locked invariant: ok is true IFF the line carries >= 2 spaces (the
    // version / code / reason splitter needs both); the middle token parses to
    // whatever int it is (0 when non-numeric), never a crash. =====
    {
        uint32_t rng = 0x01234567u;
        auto rnd = [&rng]() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; };
        const char pool[] = "HTTP/1.0 209OKk \t\r\n?abc";   // two ' ' chars -> mixes ok / !ok
        bool okInvariant = true;
        for (int iter = 0; iter < 8000; ++iter) {
            QByteArray line;
            const int n = int(rnd() % 60);
            for (int i = 0; i < n; ++i) line += pool[rnd() % (sizeof(pool) - 1)];
            const auto s = parseStatusLine(line);           // must not crash
            if (s.ok != (line.count(' ') >= 2)) okInvariant = false;
        }
        chkb("fuzz: parseStatusLine survived 8k random status lines (no crash)", true, true);
        chkb("fuzz: parseStatusLine ok <=> line has >= 2 spaces", okInvariant, true);
    }

    std::fprintf(stderr, "networking_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

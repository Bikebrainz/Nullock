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
    {
        // audit-11: status-code is exactly 3DIGIT (RFC 9112 4). A bare toInt()
        // accepted "+200" / "\t200" / "0200" and reported 200, so a malformed status
        // line drove every downstream classifier as a well-formed 200.
        chki("status '+200' is not 200", parseStatusLine("HTTP/1.1 +200 OK").statusCode, 0);
        chki("status '\\t200' is not 200", parseStatusLine("HTTP/1.1 \t200 OK").statusCode, 0);
        chki("status '0200' (4 digits) is not 200", parseStatusLine("HTTP/1.1 0200 OK").statusCode, 0);
        chki("status '20' (2 digits) => 0", parseStatusLine("HTTP/1.1 20 OK").statusCode, 0);
        chki("status plain 3-digit still parses", parseStatusLine("HTTP/1.1 503 Nope").statusCode, 503);
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
    {
        // audit-11: obs-fold (RFC 9112 5.2) -- a line starting with SP/HTAB CONTINUES
        // the previous field-value and must NEVER become a standalone header. The
        // leading-whitespace strip used to FABRICATE a Content-Length here, so we
        // framed the body differently than a conformant recipient (attacker-controlled
        // framing divergence feeding every detection module).
        const auto ht = parseHeaders("HTTP/1.1 200 OK\r\nX-Junk: a\r\n\tContent-Length: 5\r\n");
        chks("obs-fold HTAB: no fabricated Content-Length", findHeader(ht, "Content-Length"), "");
        chki("obs-fold HTAB: continuation is not a new header", ht.size(), 1);
        chks("obs-fold HTAB: folded into the previous value", ht[0].second, "a Content-Length: 5");

        const auto hs = parseHeaders("HTTP/1.1 200 OK\r\nX-Junk: a\r\n Content-Length: 5\r\n");
        chks("obs-fold SP: no fabricated Content-Length", findHeader(hs, "Content-Length"), "");
        chki("obs-fold SP: continuation is not a new header", hs.size(), 1);

        // A fold with NO previous field is dropped, never promoted.
        chki("obs-fold with no previous header is dropped",
             parseHeaders("STATUS\r\n\tContent-Length: 5\r\n").size(), 0);

        // Non-regression: a normal (unfolded) block is untouched.
        const auto hOk = parseHeaders("HTTP/1.1 200 OK\r\nX-Junk: a\r\nContent-Length: 5\r\n");
        chki("plain block still parses both headers", hOk.size(), 2);
        chks("plain block keeps its real Content-Length", findHeader(hOk, "Content-Length"), "5");
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
    // audit-11: OWS is SP/HTAB ONLY. QString::trimmed() is Unicode-aware and also
    // strips U+00A0/U+0085, so a NBSP-padded value was accepted as a plain number and
    // framed the body where a conformant recipient sees a malformed Content-Length.
    chkb("CL NBSP-padded => !ok (OWS is SP/HTAB only)",
         parseContentLength(QString(QChar(0x00A0)) + "5").ok, false);
    chkb("CL NEL-padded => !ok",
         parseContentLength(QString(QChar(0x0085)) + "5").ok, false);
    chkb("CL SP/HTAB padding still ok (non-regression)",
         parseContentLength(" \t42 \t").ok, true);

    // ===== transferEncodingIsChunked (audit-11: FINAL coding, not contains) =====
    // A bare contains("chunked") also fired on "chunked, gzip" (NOT chunk-framed --
    // close-delimited) and on lookalikes, making the chunk reader fail and DISCARD the
    // whole attacker-influenced response: a silent false negative for every module.
    chkb("TE 'gzip, chunked' => chunked (final)",  transferEncodingIsChunked("gzip, chunked"), true);
    chkb("TE 'chunked, gzip' => NOT chunked",      transferEncodingIsChunked("chunked, gzip"), false);
    chkb("TE 'xchunked' lookalike => NOT chunked", transferEncodingIsChunked("xchunked"), false);
    chkb("TE 'chunkedx' lookalike => NOT chunked", transferEncodingIsChunked("chunkedx"), false);
    chkb("TE ' CHUNKED ' => chunked (OWS + case)", transferEncodingIsChunked(" CHUNKED "), true);
    chkb("TE empty => NOT chunked",                transferEncodingIsChunked(""), false);
    chkb("CL at cap ok",
         parseContentLength(QString::number(kMaxBodyBytes)).ok, true);
    chkb("CL over cap => !ok",
         parseContentLength(QString::number(kMaxBodyBytes + 1)).ok, false);
    chkb("CL huge => !ok",           parseContentLength("999999999999").ok, false);
    chkb("CL leading-plus => !ok",   parseContentLength("+5").ok,           false);  // audit-4

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
    // audit-4: chunk-size is 1*HEXDIG -- reject a 0x prefix / +sign (Qt toLongLong
    // honors both, which would truncate or desync the decoded body).
    chkb("chunk 0x0 => !ok (no 0x prefix)", parseChunkSizeLine("0x0").ok,  false);
    chkb("chunk 0x1f => !ok",               parseChunkSizeLine("0x1f").ok, false);
    chkb("chunk +1f => !ok (no sign)",      parseChunkSizeLine("+1f").ok,  false);

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
    {
        // audit-11: a trailer FIELD-LINE with no terminating empty line is still an
        // INCOMPLETE body -- stopping at the first CRLF returned Done early.
        QByteArray buf = "3\r\nabc\r\n0\r\nA: 1\r\n", dec;
        chkd("feed unterminated trailer field -> needmore (not premature done)",
             feedChunked(buf, dec), ChunkDecode::NeedMore);
        buf += "\r\n";                                        // now terminate it
        chkd("feed terminated trailer -> done", feedChunked(buf, dec), ChunkDecode::Done);
        chks("feed trailer decoded intact", QString::fromLatin1(dec), "abc");
        chki("feed trailer fully consumed", buf.size(), 0);
    }
    {
        // audit-11: a MULTI-field trailer must be consumed whole -- leftover lines
        // would be read as the start of the next response on a reused connection.
        QByteArray buf = "3\r\nabc\r\n0\r\nA: 1\r\nB: 2\r\n\r\n", dec;
        chkd("feed multi-field trailer done", feedChunked(buf, dec), ChunkDecode::Done);
        chki("feed multi-field trailer fully consumed", buf.size(), 0);
        chks("feed multi-field trailer decoded", QString::fromLatin1(dec), "abc");
    }
    {
        // audit-11: the documented contract said "on NeedMore nothing is consumed",
        // which was never true -- COMPLETE chunks are consumed incrementally and the
        // caller must not re-supply them. Lock the real behavior.
        QByteArray buf = "3\r\nabc\r\n5\r\nhe", dec;
        chkd("feed complete-then-partial -> needmore", feedChunked(buf, dec), ChunkDecode::NeedMore);
        chks("feed NeedMore still consumed the COMPLETE chunk", QString::fromLatin1(dec), "abc");
        chks("feed NeedMore left only the partial chunk", QString::fromLatin1(buf), "5\r\nhe");
    }
    {
        // audit-12: the size-line cap only fired while the line was UNTERMINATED, so a
        // CRLF-TERMINATED but absurdly long chunk-extension slid past it and was parsed
        // whole. (The existing flood test omits the CRLF, exercising only that branch.)
        QByteArray buf = "1;" + QByteArray(2 * int(kMaxChunkLineBytes), 'x') + "\r\nA\r\n0\r\n\r\n", dec;
        chkd("feed oversized TERMINATED size line -> error",
             feedChunked(buf, dec), ChunkDecode::Error);
    }
    {
        // audit-12: the trailer cap bounded ONE field-line but never the ACCUMULATION,
        // so a terminated trailer of unbounded TOTAL size (N tiny lines) was walked and
        // accepted as Done -- megabytes buffered carrying zero body bytes.
        QByteArray buf = "3\r\nabc\r\n0\r\n", dec;
        while (buf.size() < 4 * int(kMaxChunkLineBytes)) buf += "A: 1\r\n";
        buf += "\r\n";                                    // terminate the trailer
        chkd("feed oversized TERMINATED trailer -> error", feedChunked(buf, dec), ChunkDecode::Error);
    }
    {
        // ...and the total cap must not be over-tight: a normal multi-field trailer
        // well under it still completes and is fully consumed.
        QByteArray buf = "3\r\nabc\r\n0\r\n", dec;
        while (buf.size() < 8 * 1024) buf += "A: 1\r\n";
        buf += "\r\n";
        chkd("feed small terminated trailer still done", feedChunked(buf, dec), ChunkDecode::Done);
        chki("feed small terminated trailer fully consumed", buf.size(), 0);
        chks("feed small terminated trailer decoded", QString::fromLatin1(dec), "abc");
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

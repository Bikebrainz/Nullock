// Regression corpus for the proxy's pure HTTP/1.1 framing logic (no network -- it
// runs on attacker-influenceable client requests AND upstream responses). Locks the
// request-smuggling fixes from the adversarial audit (8 findings / 3 issues):
//   - isFramingSafe now VALIDATES Transfer-Encoding (last coding must be exactly
//     "chunked") and rejects ANY TE on a request (no request chunked decoder), so
//     a TE-obfuscation can't pass the guard and desync the origin;
//   - isFramingSafe rejects a parsed header whose name/value carries an interior
//     CR/LF/NUL (it would inject a header line on re-serialization -> a CL/TE the
//     guard never saw);
//   - decodeChunkedAvailable is bounded + overflow-safe: a negative, non-hex,
//     >16 MiB, or total-exceeding chunk size is an Error (validated BEFORE any
//     chunkSize+2 math), closing the integer-overflow + unbounded-memory DoS.
//
// Run via:  ctest -R proxy_logic -V

#include "proxy_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Proxy::HttpLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using HV = QList<QPair<QString, QString>>;
HV H(std::initializer_list<QPair<QString, QString>> xs) { HV h; for (const auto &p : xs) h.append(p); return h; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseHeaders + findHeader ====================================
    {
        const QByteArray block = "GET / HTTP/1.1\r\nHost: a.com\r\nX-Token: abc\r\nContent-Length: 5";
        const auto hs = parseHeaders(block);
        chk("parse: request line skipped, headers parsed", hs.size() == 3);
        chk("parse: findHeader case-insensitive", findHeader(hs, "host") == "a.com");
        chk("parse: value trimmed", findHeader(hs, "X-Token") == "abc");
        chk("parse: missing -> empty", findHeader(hs, "Nope").isEmpty());
    }

    // ===== isChunkedTransfer: last coding must be 'chunked' =============
    chk("chunked: 'chunked' -> true", isChunkedTransfer("chunked"));
    chk("chunked: case-insensitive", isChunkedTransfer("Chunked"));
    chk("chunked: 'gzip, chunked' -> true (last is chunked)", isChunkedTransfer("gzip, chunked"));
    chk("chunked: 'chunked, gzip' -> false (chunked not last)", !isChunkedTransfer("chunked, gzip"));
    chk("chunked: 'identity' -> false", !isChunkedTransfer("identity"));
    chk("chunked: empty -> false", !isChunkedTransfer(""));

    // ===== isFramingSafe: CL/TE smuggling defence =======================
    chk("framing: a clean request (CL only) is safe",
        isFramingSafe(H({{"Host", "a"}, {"Content-Length", "5"}}), true));
    chk("framing: a clean response (CL only) is safe",
        isFramingSafe(H({{"Content-Length", "5"}}), false));
    chk("framing: Content-Length + Transfer-Encoding -> unsafe",
        !isFramingSafe(H({{"Content-Length", "5"}, {"Transfer-Encoding", "chunked"}}), false));
    chk("framing: duplicate CL with DIFFERENT values -> unsafe",
        !isFramingSafe(H({{"Content-Length", "5"}, {"Content-Length", "6"}}), false));
    chk("framing: duplicate CL with SAME value -> safe",
        isFramingSafe(H({{"Content-Length", "5"}, {"Content-Length", "5"}}), false));
    chk("framing: a CL list '12, 12' (equal) -> safe",
        isFramingSafe(H({{"Content-Length", "12, 12"}}), false));
    chk("framing: a CL list '12, 13' (conflict) -> unsafe",
        !isFramingSafe(H({{"Content-Length", "12, 13"}}), false));
    chk("framing: a non-numeric / negative CL -> unsafe",
        !isFramingSafe(H({{"Content-Length", "-1"}}), false));

    // ===== isFramingSafe: Transfer-Encoding validation (the FN fix) =====
    chk("framing: TE:chunked on a RESPONSE is safe", isFramingSafe(H({{"Transfer-Encoding", "chunked"}}), false));
    chk("framing: ANY TE on a REQUEST is rejected (no request chunked decoder)",
        !isFramingSafe(H({{"Transfer-Encoding", "chunked"}}), true));
    chk("framing: TE:identity (last not chunked) -> unsafe even on a response",
        !isFramingSafe(H({{"Transfer-Encoding", "identity"}}), false));
    chk("framing: TE 'chunked, identity' (chunked not last) -> unsafe (obfuscation)",
        !isFramingSafe(H({{"Transfer-Encoding", "chunked, identity"}}), false));
    chk("framing: TE 'chunked, chunked' (duplicate coding) -> unsafe",
        !isFramingSafe(H({{"Transfer-Encoding", "chunked, chunked"}}), false));

    // ===== isFramingSafe: CRLF re-injection guard (interior control) ====
    chk("framing: a header VALUE with an interior CR -> unsafe (CRLF re-injection)",
        !isFramingSafe(H({{"X", "1\rContent-Length: 999"}, {"Content-Length", "5"}}), false));
    chk("framing: a header VALUE with an interior LF -> unsafe",
        !isFramingSafe(H({{"X", "a\nInjected: 1"}}), false));
    chk("framing: a header NAME with an interior CR -> unsafe",
        !isFramingSafe(H({{"X\rEvil", "1"}}), false));
    chk("framing: a header VALUE with a NUL -> unsafe",
        !isFramingSafe(H({{"X", QString("a") + QChar(0) + QString("b")}}), false));
    // End-to-end: an interior bare CR survives parseHeaders and is then rejected.
    {
        const QByteArray block =
            "GET / HTTP/1.1\r\nHost: a\r\nX: 1\rContent-Length: 999\r\nContent-Length: 5";
        chk("framing: parsed interior-CR header is rejected (end-to-end CRLF-injection guard)",
            !isFramingSafe(parseHeaders(block), true));
    }

    // ===== decodeChunkedAvailable: bounded + overflow-safe ==============
    {
        QByteArray buf = "5\r\nhello\r\n0\r\n\r\n", dec;
        chk("chunk: a complete chunked body decodes",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Complete && dec == "hello");
    }
    {
        QByteArray buf = "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", dec;
        chk("chunk: multiple chunks concatenate",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Complete && dec == "abcde");
    }
    {
        QByteArray buf = "5;ext=foo\r\nhello\r\n0\r\n\r\n", dec;
        chk("chunk: a chunk extension is stripped",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Complete && dec == "hello");
    }
    {
        QByteArray buf = "5\r\nhel", dec;       // chunk data not all here yet
        chk("chunk: an incomplete chunk -> NeedMore", decodeChunkedAvailable(buf, dec) == ChunkResult::NeedMore);
    }
    {
        QByteArray buf = "-1\r\nx\r\n", dec;     // toLongLong accepts '-1'
        chk("chunk: a NEGATIVE chunk size -> Error (no left(neg)/overflow)",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Error);
    }
    {
        QByteArray buf = "1000001\r\n", dec;     // 0x1000001 = 16 MiB + 1 > cap
        chk("chunk: a chunk size over 16 MiB -> Error", decodeChunkedAvailable(buf, dec) == ChunkResult::Error);
    }
    {
        QByteArray buf = "7FFFFFFFFFFFFFFF\r\n", dec;   // INT64_MAX -- would overflow +2
        chk("chunk: an INT64_MAX chunk size -> Error (overflow-safe)",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Error);
    }
    {
        QByteArray buf = "zzz\r\n", dec;         // non-hex
        chk("chunk: a non-hex chunk size -> Error", decodeChunkedAvailable(buf, dec) == ChunkResult::Error);
    }
    // audit-7: the terminating chunk must consume the WHOLE trailer section through
    // its blank-line CRLF -- leaving the final CRLF (or consuming a partial trailer)
    // desyncs a reused keepalive socket into the next upstream response.
    {
        QByteArray buf = "5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n", dec;
        chk("chunk: a trailer section is fully consumed (no keepalive desync)",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Complete && dec == "hello" && buf.isEmpty());
    }
    {
        QByteArray buf = "5\r\nhello\r\n0\r\nA: 1\r\nB: 2\r\n\r\n", dec;
        chk("chunk: a multi-line trailer leaves no leftover bytes",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Complete && buf.isEmpty());
    }
    {
        QByteArray buf = "0\r\nA: 1\r\n", dec;    // a trailer line, final blank CRLF not yet
        chk("chunk: a trailer without its final CRLF -> NeedMore (not premature Complete)",
            decodeChunkedAvailable(buf, dec) == ChunkResult::NeedMore);
    }
    {
        QByteArray buf = "5\r\nhelloXX0\r\n\r\n", dec;   // 'XX' where the chunk-data CRLF must be
        chk("chunk: a non-CRLF chunk-data terminator -> Error (framing validated)",
            decodeChunkedAvailable(buf, dec) == ChunkResult::Error);
    }

    // ===== memory-safety + anti-smuggling fuzz over the header/framing parser =====
    // parseHeaders / isFramingSafe run on attacker-controlled upstream RESPONSE
    // (and client REQUEST) header blocks in the MITM path. Throw thousands of
    // hostile byte blobs at the full chain and assert three things:
    //   (a) it never crashes / hangs on arbitrary bytes;
    //   (b) the parsed header count stays bounded by the line count (no blowup);
    //   (c) the load-bearing anti-smuggling invariant holds -- if isFramingSafe()
    //       blesses a header set as safe to re-serialize, NO parsed name/value may
    //       still carry a CR/LF/NUL. A survivor would inject a header line the
    //       framing guard never saw (a duplicate CL/TE) -> request smuggling.
    // Deterministic xorshift so a failure is reproducible; mirrors the feedChunked
    // and WsFrameParser fuzz loops.
    {
        auto hasCtl = [](const QString &x) {
            for (const QChar c : x) {
                const ushort u = c.unicode();
                if (u == '\r' || u == '\n' || u == '\0') return true;
            }
            return false;
        };
        uint32_t s = 0x9e3779b9u;
        auto rnd = [&s]() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; };
        static const char pool[] = {
            'G','E','T',' ','/','H','T','P','1','.','a','b','c','X','-',
            ':',';',',','=','\r','\n','\t','\0','\x01','\x0b','\x7f',
            'C','o','n','t','e','L','g','h','k','d','2','5','0','q'
        };
        const int poolN = int(sizeof(pool));
        const int iters = 12000;
        int  bounded = 0;
        bool invariantHeld = true;
        for (int it = 0; it < iters; ++it) {
            const int len = int(rnd() % 220);
            QByteArray block;
            block.reserve(len + 16);
            for (int i = 0; i < len; ++i) block.append(pool[rnd() % poolN]);
            // 1-in-4 gets a realistic status/request line so the happy path (and
            // a real Content-Length / Transfer-Encoding) is exercised too.
            if ((rnd() & 3) == 0) block.prepend("HTTP/1.1 200 OK\nContent-Length: 12\n");

            const auto hs = parseHeaders(block);
            if (hs.size() <= block.count('\n') + 1) ++bounded;   // never more than the lines

            for (int req = 0; req <= 1; ++req) {
                if (!isFramingSafe(hs, req != 0)) continue;
                for (const auto &h : hs)
                    if (hasCtl(h.first) || hasCtl(h.second)) invariantHeld = false;
            }
            (void)isChunkedTransfer(findHeader(hs, "Transfer-Encoding"));
        }
        // Reaching this line at all means no blob crashed or hung the parser.
        chk("fuzz: header/framing parser survived 12000 hostile blobs (no crash)", true);
        chk("fuzz: parsed header count stayed bounded by line count", bounded == iters);
        chk("fuzz: isFramingSafe(safe) => no CR/LF/NUL survives in any name/value", invariantHeld);
    }

    std::fprintf(stderr, "proxy_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

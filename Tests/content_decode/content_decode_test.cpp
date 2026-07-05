// Tests for HTTP Content-Encoding decode (gzip / deflate) used to give the
// history/search/passive-scanner a readable view of compressed response bodies.
// Compresses inputs with zlib here, then round-trips them through
// decodeContentEncoding, and checks the safety behaviours (unknown/identity ->
// empty, garbage -> empty no crash, decompression-bomb cap).
//
// Run via:  ctest -R content_decode -V

#include "content_decode.hpp"

#include <zlib.h>

#include <QByteArray>

#include <cstdio>
#include <cstring>

using namespace Nullock::Proxy;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Compress `in` with the given zlib windowBits (15+16 = gzip, 15 = zlib-wrapped
// deflate, -15 = raw deflate) so we can feed decodeContentEncoding real streams.
QByteArray deflateWith(const QByteArray &in, int windowBits) {
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY);
    zs.next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(in.constData()));
    zs.avail_in = static_cast<uInt>(in.size());
    QByteArray out;
    char buf[16384];
    int rc;
    do {
        zs.next_out  = reinterpret_cast<Bytef *>(buf);
        zs.avail_out = sizeof(buf);
        rc = deflate(&zs, Z_FINISH);
        out.append(buf, static_cast<int>(sizeof(buf)) - static_cast<int>(zs.avail_out));
    } while (rc != Z_STREAM_END);
    deflateEnd(&zs);
    return out;
}
} // namespace

int main() {
    const QByteArray plain =
        "The quick brown fox jumps over the lazy dog. "
        "<html><body>__schema secret=AKIA reflected</body></html>";

    // gzip
    chk("gzip round-trips",         decodeContentEncoding("gzip",   deflateWith(plain, 15 + 16)) == plain);
    chk("x-gzip round-trips",       decodeContentEncoding("x-gzip", deflateWith(plain, 15 + 16)) == plain);
    chk("gzip case-insensitive",    decodeContentEncoding("GZIP",   deflateWith(plain, 15 + 16)) == plain);
    chk("gzip whitespace-trimmed",  decodeContentEncoding("  gzip ", deflateWith(plain, 15 + 16)) == plain);

    // deflate: RFC says zlib-wrapped, but many servers send raw -- handle both.
    chk("deflate(zlib) round-trips", decodeContentEncoding("deflate", deflateWith(plain, 15))  == plain);
    chk("deflate(raw) round-trips",  decodeContentEncoding("deflate", deflateWith(plain, -15)) == plain);

    // No-ops -> empty (caller falls back to the raw body).
    chk("identity -> empty",        decodeContentEncoding("identity", plain).isEmpty());
    chk("empty encoding -> empty",  decodeContentEncoding("",         plain).isEmpty());
    chk("br unsupported -> empty",  decodeContentEncoding("br",       plain).isEmpty());
    chk("zstd unsupported -> empty",decodeContentEncoding("zstd",     plain).isEmpty());
    chk("unknown -> empty",         decodeContentEncoding("weird",    plain).isEmpty());
    chk("stacked list not decoded", decodeContentEncoding("gzip, br", deflateWith(plain, 15 + 16)).isEmpty());
    chk("empty body -> empty",      decodeContentEncoding("gzip", QByteArray()).isEmpty());

    // Garbage / truncated: never crash.
    chk("garbage gzip -> empty",    decodeContentEncoding("gzip", QByteArray("not gzip at all, really")).isEmpty());
    {
        QByteArray g = deflateWith(plain, 15 + 16);
        g = g.left(g.size() / 2);                        // truncate mid-stream
        const QByteArray d = decodeContentEncoding("gzip", g);
        chk("truncated gzip: no crash, bounded", d.size() <= plain.size());
    }

    // Decompression-bomb guard: 10 MiB of zeros gzips to a few KB.
    {
        const QByteArray big(10 * 1024 * 1024, '\0');
        const QByteArray g = deflateWith(big, 15 + 16);
        chk("bomb guard trips at 1 MiB cap", decodeContentEncoding("gzip", g, 1024 * 1024).isEmpty());
        chk("decodes fully under 32 MiB cap",
            decodeContentEncoding("gzip", g, 32LL * 1024 * 1024).size() == big.size());
    }

    std::fprintf(stderr, "content_decode_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

#include "content_decode.hpp"

#include <zlib.h>   // Qt6Core's bundled zlib (Z_PREFIX -> z_inflate*), same as websocket.cpp

#include <cstring>

namespace Nullock::Proxy {
namespace {

// Inflate `in` with the given zlib windowBits:
//   15 + 16 -> gzip wrapper, 15 -> zlib wrapper, -15 -> raw DEFLATE.
// Single-shot (all input available up front). Returns the decompressed bytes,
// or an EMPTY QByteArray on a hard error or if the output would exceed maxOut.
// A truncated stream still returns whatever decompressed cleanly (useful for
// inspection) rather than nothing.
QByteArray inflateWith(const QByteArray &in, int windowBits, qint64 maxOut) {
    if (in.isEmpty()) return {};
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, windowBits) != Z_OK) return {};

    zs.next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(in.constData()));
    zs.avail_in = static_cast<uInt>(in.size());

    QByteArray out;
    char buf[64 * 1024];
    int rc = Z_OK;
    do {
        zs.next_out  = reinterpret_cast<Bytef *>(buf);
        zs.avail_out = sizeof(buf);
        rc = inflate(&zs, Z_NO_FLUSH);
        // Z_BUF_ERROR (no progress possible, e.g. truncated input) is not fatal;
        // the rest are.
        if (rc == Z_NEED_DICT || rc == Z_DATA_ERROR
            || rc == Z_MEM_ERROR || rc == Z_STREAM_ERROR) {
            inflateEnd(&zs);
            return {};
        }
        const int have = static_cast<int>(sizeof(buf)) - static_cast<int>(zs.avail_out);
        if (have > 0) {
            if (out.size() + static_cast<qint64>(have) > maxOut) {  // decompression-bomb guard
                inflateEnd(&zs);
                return {};
            }
            out.append(buf, have);
        }
        // Keep going only while the output buffer was completely filled (more to
        // come) and we haven't hit the stream end. Once inflate leaves output
        // room, it has consumed all it can from the available input.
    } while (rc != Z_STREAM_END && zs.avail_out == 0);

    inflateEnd(&zs);
    return out;
}

} // namespace

QByteArray decodeContentEncoding(const QString &encoding, const QByteArray &body, qint64 maxOut) {
    const QString e = encoding.trimmed().toLower();
    if (e.isEmpty() || e == QLatin1String("identity")) return {};

    if (e == QLatin1String("gzip") || e == QLatin1String("x-gzip"))
        return inflateWith(body, 15 + 16, maxOut);

    if (e == QLatin1String("deflate")) {
        // RFC 7230 says "deflate" is zlib-wrapped, but plenty of servers send
        // RAW DEFLATE. Try the zlib wrapper first, fall back to raw.
        const QByteArray z = inflateWith(body, 15, maxOut);
        if (!z.isEmpty()) return z;
        return inflateWith(body, -15, maxOut);
    }

    // br (brotli) / zstd and any stacked/unknown coding: not decodable here.
    return {};
}

} // namespace Nullock::Proxy

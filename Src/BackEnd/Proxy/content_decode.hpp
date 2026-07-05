#pragma once

#include <QByteArray>
#include <QString>

namespace Nullock::Proxy {

// Decode an HTTP body that was compressed with Content-Encoding `encoding`
// (gzip / x-gzip / deflate) for INSPECTION only -- history search, passive
// scanning, evidence capture, reporting. Returns the decompressed bytes on
// success, or an EMPTY QByteArray when:
//   * the encoding is identity / empty / unknown (nothing to do), or
//   * the encoding is br (brotli) / zstd -- not yet supported (no bundled
//     decoder; folding brotli in needs a separate library), or
//   * decoding fails, or the output would exceed maxOut (decompression-bomb
//     guard: a few KB of gzip can expand to gigabytes).
//
// This is NEVER used to alter the bytes forwarded on the wire -- the proxy
// keeps the original compressed body and re-encoding stays the browser's job.
// Callers store the result alongside the raw body (HttpResponse::decodedBody)
// and read it via HttpResponse::bodyForInspection().
QByteArray decodeContentEncoding(const QString &encoding, const QByteArray &body,
                                 qint64 maxOut = 128LL * 1024 * 1024);

} // namespace Nullock::Proxy

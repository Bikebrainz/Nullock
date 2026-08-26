#pragma once

// Pure HTTP/1.1 framing logic for the proxy, split out of proxy_server.cpp so a
// unit test can link it against Qt6::Core alone (proxy_server.cpp is a large
// QObject pulling QtNetwork/Qml/nghttp2). These run on ATTACKER-INFLUENCEABLE
// bytes -- a client request OR an upstream response through the MITM proxy -- and
// are the request-smuggling defence: header parsing, the CL/TE framing-safety
// guard, the canonical chunked-vs-not decision, and a bounded chunked decoder.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Proxy::HttpLogic {

// Chunked-decode caps (a hostile chunked stream must not exhaust memory).
constexpr qint64 kMaxChunkBytes   = 16 * 1024 * 1024;    // per chunk
constexpr qint64 kMaxDecodedBytes = 256 * 1024 * 1024;   // total decoded body

// Parse a header block (the first line -- request/status line -- is skipped) into
// name/value pairs. Tolerant of CRLF and bare-LF line endings; trims each side.
QList<QPair<QString, QString>> parseHeaders(const QByteArray &headerBlock);

// First header value matching `name` (case-insensitive), or "".
QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name);

// Is the message chunk-framed? True iff the LAST Transfer-Encoding coding (trimmed,
// lower-cased) is exactly "chunked". The framing-safety guard AND the body decoder
// MUST both use this so they cannot disagree about where the body ends.
bool isChunkedTransfer(const QString &transferEncodingValue);

// RFC 7230/9112 framing-safety on the PARSED headers. Returns false (collapse the
// connection) when the message is unsafe to forward:
//   - any header NAME/VALUE carries an interior CR/LF/NUL -- it would inject a
//     header line when the proxy re-serializes (CRLF / request-smuggling);
//   - Content-Length AND Transfer-Encoding together, or conflicting/duplicate CL;
//   - a malformed/obfuscated Transfer-Encoding (last coding not exactly "chunked",
//     or "chunked" appearing more than once / not last);
//   - for a REQUEST (isRequest), ANY Transfer-Encoding -- the proxy has no request-
//     side chunked decoder, so forwarding TE verbatim with a dropped body desyncs
//     the origin; reject rather than silently corrupt.
bool isFramingSafe(const QList<QPair<QString, QString>> &headers, bool isRequest);

// Decode every COMPLETE chunk at the front of `buffer`, consuming them and
// appending payload to `decoded`. Bounded and overflow-safe: a chunk size that is
// non-hex, negative, > kMaxChunkBytes, or that would push the total past
// kMaxDecodedBytes is an Error (the size is validated BEFORE any chunkSize+2 math).
enum class ChunkResult { Complete, NeedMore, Error };
ChunkResult decodeChunkedAvailable(QByteArray &buffer, QByteArray &decoded);

// A REQUEST header the proxy must NOT forward to the ORIGIN because it is scoped
// to the proxy hop: Proxy-Connection (hop-by-hop control) and Proxy-Authorization
// (the CLIENT's credentials for THIS proxy -- forwarding them to the target leaks
// the proxy password to the origin). Case-insensitive.
bool isProxyHopRequestHeader(const QString &name);

} // namespace Nullock::Proxy::HttpLogic

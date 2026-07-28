#pragma once

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

// Pure parsing cores for HttpClient::send (networking.cpp). Every byte these
// touch is attacker / MitM-controlled (status line, headers, chunk framing,
// Content-Length), so they are the security-critical heart of the shared HTTP
// response parser. Lifted out of the socket TU so they can be unit-tested
// against Qt6::Core ALONE -- no socket, no event loop, no Qt6::Network. See
// Tests/networking (networking_logic_test).
namespace Nullock::Core::NetworkingLogic {

// Hard cap on a single response body / decoded chunked stream. A hostile or
// MitM upstream announcing Content-Length: 10 GiB, or streaming chunks
// forever, would otherwise OOM us. 128 MB is comfortably larger than any real
// recon/replay payload; anything bigger we reject. networking.cpp's kMaxBodyBytes
// is defined from THIS value so the cap has a single source of truth.
constexpr qint64 kMaxBodyBytes = 128LL * 1024 * 1024;

// A chunk-size line (hex size + optional ";extensions") or a chunked trailer
// block is never legitimately large. We bound the UNFRAMED bytes buffered while
// waiting for a size-line / trailer's terminating CRLF, so a peer that dribbles
// an endless extension or trailer with NO CRLF (under the per-read timeout)
// cannot grow our buffers without limit. 64 KiB mirrors readHeaderBlock's cap.
constexpr qint64 kMaxChunkLineBytes = 64 * 1024;

// --- status line: "HTTP/1.1 200 OK" -------------------------------------
struct StatusLine {
    bool    ok = false;            // false => no second SP => malformed; reject
    QString httpVersion;
    int     statusCode = 0;
    QString reasonPhrase;
};
// Requires the RFC 9112 form "<version> SP <code> SP <reason>": both spaces
// must be present (reason may be empty). Missing either space => ok=false.
StatusLine parseStatusLine(const QByteArray &line);

// --- 1xx interim-response policy -----------------------------------------
// A server may emit any number of interim (1xx) header blocks -- 100 Continue,
// 103 Early Hints -- before the real final response. The reader skips them, but
// it must bound the skipping, and running OUT of that bound is an ERROR, not a
// final response: the 1xx in hand is NOT the answer to the request, and treating
// it as one reports the interim's status/headers while the real response lands in
// the body. A hostile target can trigger that at will to blind every status- and
// header-keyed check, so the exhausted case gets its own verdict.
enum class InterimAction {
    Final,            // this IS the final response (or malformed -- caller decides)
    SkipToNext,       // a 1xx within budget: re-seed and read the next header block
    TooManyInterim,   // budget exhausted and STILL 1xx: no final response exists
};
// `seen` is the number of interim responses already skipped.
constexpr int kMaxInterimResponses = 8;
InterimAction classifyInterimResponse(const StatusLine &status, int seen,
                                      int maxInterim = kMaxInterimResponses);

// --- header block (the bytes AFTER the status line, up to CRLFCRLF) ------
// lines[0] is the status line and is skipped (i starts at 1). A line with no
// ':' (or ':' at column 0) is ignored. Header COUNT is bounded upstream by
// readHeaderBlock's 64 KiB cap, not here.
QList<QPair<QString, QString>> parseHeaders(const QByteArray &block);
QString findHeader(const QList<QPair<QString, QString>> &h, const QString &name);

// --- Content-Length validation ------------------------------------------
struct ContentLength {
    bool   ok = false;   // false => header present but malformed/over-cap; reject
    qint64 value = 0;
};
// Rejects non-numeric ("garbage", "0x10"), negative ("-5"), and over-cap
// values. A present-but-malformed Content-Length is a framing error: callers
// must reject it, NOT silently fall back to an empty / close-delimited body.

// --- Content-Length across the WHOLE message (RFC 9112 6.3) --------------
// A message may carry more than one Content-Length field line, and a single
// field line may carry a comma-separated list. That is valid ONLY when every
// value is identical; two DIFFERING values are an unrecoverable framing error --
// the classic smuggling desync, where each party frames a different number of
// bytes. Reading the length with findHeader() takes FIRST-wins, so a deliberate
// disagreement ("Content-Length: 5" then "Content-Length: 9") was silently
// resolved in the sender's favour and the body framed from one side of it.
//
// Mirrors the policy the proxy path already enforces (HttpLogic::isFramingSafe)
// but keeps THIS module's stricter element validation: every element goes
// through parseContentLength above, so "+5" / "0x10" / NBSP-prefixed values are
// still rejected here even though a bare toLongLong would take them.
struct ContentLengthAll {
    bool       present = false;   // at least one Content-Length field line exists
    bool       ok      = false;   // every element parsed AND all agreed
    qint64     value   = 0;       // the agreed length (only when ok)
    QStringList values;           // raw elements as seen, for the error message
};
ContentLengthAll parseContentLengthHeaders(const QList<QPair<QString, QString>> &headers);
// True only when "chunked" is the FINAL transfer-coding (RFC 9112 6.1) -- "gzip,
// chunked" is chunk-framed, "chunked, gzip" and "xchunked" are NOT.
bool transferEncodingIsChunked(const QString &transferEncodingValue);

ContentLength parseContentLength(const QString &cl);

// --- chunked transfer-encoding ------------------------------------------
struct ChunkSize {
    bool   ok = false;
    qint64 size = 0;
};
// Strips a ";ext" suffix, parses the hex size, and rejects negative / over-cap
// sizes (which would otherwise overflow the `size + 2` framing arithmetic).
ChunkSize parseChunkSizeLine(const QByteArray &sizeLine);

enum class ChunkDecode { NeedMore, Done, Error };
// Pure incremental chunked-body decoder. Consumes every COMPLETE chunk present
// in `buffer` (removing its bytes in place), appending chunk-data to `decoded`.
// Returns:
//   Done     -- the terminating 0-size chunk was consumed; `decoded` is final.
//   NeedMore -- buffer holds a partial chunk; caller must read more and re-call.
//               Any COMPLETE chunks already present are still consumed (and their
//               data appended to `decoded`) before NeedMore is returned -- only the
//               trailing partial chunk is left in the buffer. (This previously
//               claimed "nothing is consumed", which was never true: incremental
//               consumption is the design, and the caller must not re-supply bytes
//               feedChunked has already taken.)
//   Error    -- malformed framing, a bad/over-cap chunk size, decoded would
//               exceed kMaxBodyBytes, OR an unterminated size line / trailer
//               grew past kMaxChunkLineBytes (the unbounded-stream guard).
// No socket, no I/O -- the caller owns the read loop and the raw-byte cap.
ChunkDecode feedChunked(QByteArray &buffer, QByteArray &decoded);

} // namespace Nullock::Core::NetworkingLogic

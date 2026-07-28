#include "networking_logic.hpp"

namespace Nullock::Core::NetworkingLogic {

StatusLine parseStatusLine(const QByteArray &line) {
    StatusLine out;
    const int sp1 = line.indexOf(' ');
    const int sp2 = sp1 < 0 ? -1 : line.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) return out;   // ok stays false
    // RFC 9112 4: status-code is exactly 3DIGIT. A bare toInt() accepts "+200",
    // "\t200" and "0200" (all -> 200), so a malformed status line would be graded as
    // a well-formed 200 and drive every downstream classifier. Accept only three
    // ASCII digits; anything else leaves statusCode 0 -- keeping this module's
    // existing contract that a structurally-parseable line stays ok with code 0.
    const QByteArray code = line.mid(sp1 + 1, sp2 - sp1 - 1);
    bool codeOk = (code.size() == 3);
    if (codeOk)
        for (const char c : code) if (c < '0' || c > '9') { codeOk = false; break; }
    out.httpVersion  = QString::fromLatin1(line.left(sp1));
    out.statusCode   = codeOk ? code.toInt() : 0;
    out.reasonPhrase = QString::fromLatin1(line.mid(sp2 + 1));
    out.ok = true;
    return out;
}

QList<QPair<QString, QString>> parseHeaders(const QByteArray &block) {
    QList<QPair<QString, QString>> out;
    const QList<QByteArray> lines = block.split('\n');
    for (int i = 1; i < lines.size(); ++i) {
        QByteArray line = lines[i];
        if (line.endsWith('\r')) line.chop(1);
        if (line.isEmpty()) continue;
        // obs-fold (RFC 9112 5.2): a line starting with SP/HTAB CONTINUES the previous
        // field-value -- it is NEVER a new header. Without this, ".trimmed()" below
        // strips the leading HTAB/SP off "\tContent-Length: 5" and FABRICATES a
        // standalone Content-Length, so we would frame the body differently than a
        // conformant recipient (which folds it into the previous value) -- an
        // attacker-controlled framing divergence feeding every detection module.
        if (line.startsWith(' ') || line.startsWith('\t')) {
            if (!out.isEmpty()) {
                const QString cont = QString::fromLatin1(line).trimmed();
                if (!cont.isEmpty())
                    out.last().second = out.last().second.isEmpty()
                        ? cont : out.last().second + QLatin1Char(' ') + cont;
            }
            continue;   // no previous field to fold into -> drop, never a new header
        }
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        out.append({
            QString::fromLatin1(line.left(colon)).trimmed(),
            QString::fromLatin1(line.mid(colon + 1)).trimmed(),
        });
    }
    return out;
}

QString findHeader(const QList<QPair<QString, QString>> &h, const QString &name) {
    for (const auto &kv : h)
        if (kv.first.compare(name, Qt::CaseInsensitive) == 0)
            return kv.second;
    return {};
}

bool transferEncodingIsChunked(const QString &transferEncodingValue) {
    // RFC 9112 6.1: the body is chunk-framed only when "chunked" is the FINAL coding.
    // A bare contains("chunked") also fires on "chunked, gzip" (NOT chunk-framed --
    // close-delimited) and on lookalike tokens ("xchunked"), making the chunk reader
    // fail and DISCARD an entire attacker-influenced response (silent false negative
    // for every detection module). Mirrors HttpLogic::isChunkedTransfer.
    const QStringList codings = transferEncodingValue.toLower().split(QLatin1Char(','), Qt::SkipEmptyParts);
    if (codings.isEmpty()) return false;
    return codings.last().trimmed() == QLatin1String("chunked");
}

ContentLength parseContentLength(const QString &cl) {
    ContentLength out;
    // Trim ONLY the RFC OWS (SP / HTAB). QString::trimmed() is Unicode-aware and also
    // strips U+00A0 / U+0085 etc., so a value like "\xA05" (NBSP + '5', reachable via
    // fromLatin1 of the raw header bytes) would be accepted as a plain "5" and frame
    // the body -- where a conformant recipient sees a malformed Content-Length.
    qsizetype b = 0, e = cl.size();
    while (b < e && (cl[b] == QLatin1Char(' ') || cl[b] == QLatin1Char('\t'))) ++b;
    while (e > b && (cl[e - 1] == QLatin1Char(' ') || cl[e - 1] == QLatin1Char('\t'))) --e;
    const QString t = cl.mid(b, e - b);
    // RFC 9112: Content-Length is 1*DIGIT. Reject empty and any sign/hex/junk up
    // front -- toLongLong() alone accepts a leading '+' ("+5"), which would frame
    // the response as well-formed instead of a protocol error.
    if (t.isEmpty()) return out;
    for (const QChar c : t) { const ushort u = c.unicode(); if (u < '0' || u > '9') return out; }
    bool ok = false;
    const qint64 n = t.toLongLong(&ok);
    if (!ok || n < 0 || n > kMaxBodyBytes) return out;   // ok stays false
    out.ok    = true;
    out.value = n;
    return out;
}

ChunkSize parseChunkSizeLine(const QByteArray &sizeLine) {
    ChunkSize out;
    QByteArray s = sizeLine;
    const int semi = s.indexOf(';');
    if (semi >= 0) s = s.left(semi);
    s = s.trimmed();
    // RFC 9112: chunk-size is 1*HEXDIG. Reject empty and any 0x-prefix / sign / junk
    // up front -- toLongLong(&ok,16) accepts "0x0" (Qt honors the 0x prefix and a
    // leading +/-), which would truncate or desync the decoded body vs ground truth.
    if (s.isEmpty()) return out;
    for (const char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return out;
    bool ok = false;
    const qint64 sz = s.toLongLong(&ok, 16);
    if (!ok || sz < 0 || sz > kMaxBodyBytes) return out;   // ok stays false
    out.ok   = true;
    out.size = sz;
    return out;
}

ChunkDecode feedChunked(QByteArray &buffer, QByteArray &decoded) {
    while (true) {
        const int crlf = buffer.indexOf("\r\n");
        if (crlf < 0) {
            // Size line not yet terminated. Bound the unframed buffer so a peer
            // streaming an endless chunk-extension with no CRLF can't OOM us.
            return buffer.size() > kMaxChunkLineBytes ? ChunkDecode::Error
                                                      : ChunkDecode::NeedMore;
        }
        const ChunkSize cs = parseChunkSizeLine(buffer.left(crlf));
        if (!cs.ok) return ChunkDecode::Error;
        if (decoded.size() + cs.size > kMaxBodyBytes) return ChunkDecode::Error;
        if (cs.size == 0) {
            // Terminating chunk. RFC 9112 7.1: last-chunk is followed by an OPTIONAL
            // trailer section of field-lines and then a FINAL empty line. Stopping at
            // the FIRST CRLF ended the message early -- "0\r\nA: 1\r\n" (trailer not
            // yet terminated) returned Done on an INCOMPLETE body, and a multi-field
            // trailer left its remaining lines in the buffer, where they would be read
            // as the start of the next response. Scan field-lines to the empty line.
            int pos = crlf + 2;                       // first byte after "0\r\n"
            while (true) {
                const int e = buffer.indexOf("\r\n", pos);
                if (e < 0)                            // trailer not terminated yet
                    return buffer.size() > kMaxChunkLineBytes ? ChunkDecode::Error
                                                              : ChunkDecode::NeedMore;
                if (e == pos) {                       // empty line -> trailer complete
                    buffer.remove(0, e + 2);
                    return ChunkDecode::Done;
                }
                if (e - pos > kMaxChunkLineBytes) return ChunkDecode::Error;
                pos = e + 2;                          // next trailer field-line
            }
        }
        // Need the full chunk data + its trailing CRLF before consuming. cs.size
        // is already <= kMaxBodyBytes, so this sum cannot overflow qint64.
        const qint64 need = qint64(crlf) + 2 + cs.size + 2;
        if (buffer.size() < need) return ChunkDecode::NeedMore;
        // RFC 9112: chunk-data MUST be followed by CRLF. Validate it rather than
        // blindly removing two bytes -- a hostile upstream that replaces the
        // trailing CRLF with other bytes would otherwise be silently swallowed,
        // resuming the next chunk-size parse at the wrong offset and steering
        // which bytes land in the decoded body (a response-desync integrity bug).
        if (buffer.mid(crlf + 2 + cs.size, 2) != QByteArrayLiteral("\r\n"))
            return ChunkDecode::Error;
        decoded.append(buffer.mid(crlf + 2, cs.size));
        buffer.remove(0, crlf + 2 + cs.size + 2);
    }
}

} // namespace Nullock::Core::NetworkingLogic

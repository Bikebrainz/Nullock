#include "networking_logic.hpp"

namespace Nullock::Core::NetworkingLogic {

StatusLine parseStatusLine(const QByteArray &line) {
    StatusLine out;
    const int sp1 = line.indexOf(' ');
    const int sp2 = sp1 < 0 ? -1 : line.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) return out;   // ok stays false
    out.httpVersion  = QString::fromLatin1(line.left(sp1));
    out.statusCode   = line.mid(sp1 + 1, sp2 - sp1 - 1).toInt();
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

ContentLength parseContentLength(const QString &cl) {
    ContentLength out;
    bool ok = false;
    const qint64 n = cl.trimmed().toLongLong(&ok);
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
    bool ok = false;
    const qint64 sz = s.trimmed().toLongLong(&ok, 16);
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
            // Terminating chunk. Consume the optional trailer up to its CRLF.
            // Same kMaxChunkLineBytes guard against an unterminated trailer.
            const int end = buffer.indexOf("\r\n", crlf + 2);
            if (end < 0)
                return buffer.size() > kMaxChunkLineBytes ? ChunkDecode::Error
                                                          : ChunkDecode::NeedMore;
            buffer.remove(0, end + 2);
            return ChunkDecode::Done;
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

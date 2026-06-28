// Pure HTTP/1.1 framing logic (see proxy_logic.hpp). No I/O; Qt6::Core only.

#include "proxy_logic.hpp"

#include <QStringList>

namespace Nullock::Proxy::HttpLogic {

namespace {
bool hasControlByte(const QString &s) {
    for (const QChar c : s) {
        const ushort u = c.unicode();
        if (u == '\r' || u == '\n' || u == '\0') return true;   // header-line break / NUL
    }
    return false;
}
} // namespace

QList<QPair<QString, QString>> parseHeaders(const QByteArray &headerBlock) {
    QList<QPair<QString, QString>> headers;
    const QList<QByteArray> lines = headerBlock.split('\n');
    for (int i = 1; i < lines.size(); ++i) {           // line 0 is the request/status line
        QByteArray line = lines[i];
        if (line.endsWith('\r')) line.chop(1);
        if (line.isEmpty()) continue;
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        headers.append({
            QString::fromLatin1(line.left(colon)).trimmed(),
            QString::fromLatin1(line.mid(colon + 1)).trimmed()
        });
    }
    return headers;
}

QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0)
            return h.second;
    return {};
}

bool isChunkedTransfer(const QString &transferEncodingValue) {
    const QStringList codings = transferEncodingValue.toLower().split(',', Qt::SkipEmptyParts);
    if (codings.isEmpty()) return false;
    return codings.last().trimmed() == QLatin1String("chunked");
}

bool isFramingSafe(const QList<QPair<QString, QString>> &headers, bool isRequest) {
    bool sawTE = false;
    QString cl;
    for (const auto &h : headers) {
        // CRLF re-injection guard: an interior control byte in a parsed name/value
        // would become a header-line break when the proxy re-serializes the message
        // (the duplicate Content-Length / TE the guard then never saw).
        if (hasControlByte(h.first) || hasControlByte(h.second)) return false;

        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) {
            sawTE = true;
            // Accept ONLY a Transfer-Encoding the proxy decodes identically to how
            // it forwards: the last coding must be exactly "chunked", appearing
            // once. Anything else (identity-only, unknown coding, chunked-not-last,
            // duplicate chunked) is an obfuscation vector -> reject.
            QStringList codings;
            for (const QString &c : h.second.toLower().split(',', Qt::SkipEmptyParts))
                codings << c.trimmed();
            if (codings.isEmpty() || codings.last() != QLatin1String("chunked")
                || codings.count(QLatin1String("chunked")) != 1)
                return false;
            // The request path has NO chunked decoder; forwarding TE verbatim with a
            // dropped body desyncs the origin. Reject chunked requests outright.
            if (isRequest) return false;
        } else if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) {
            const QStringList vals = h.second.split(',', Qt::SkipEmptyParts);
            for (QString v : vals) {
                v = v.trimmed();
                if (v.isEmpty()) return false;
                bool ok = false;
                const qint64 n = v.toLongLong(&ok);
                if (!ok || n < 0) return false;
                if (cl.isEmpty()) cl = v;
                else if (cl != v) return false;       // conflicting/duplicate CL
            }
        }
    }
    if (sawTE && !cl.isEmpty()) return false;          // Content-Length + Transfer-Encoding
    return true;
}

ChunkResult decodeChunkedAvailable(QByteArray &buffer, QByteArray &decoded) {
    while (true) {
        const int crlf = buffer.indexOf("\r\n");
        if (crlf < 0) return ChunkResult::NeedMore;    // size line not yet complete

        QByteArray sizeLine = buffer.left(crlf);
        const int semi = sizeLine.indexOf(';');        // strip a chunk extension
        if (semi >= 0) sizeLine = sizeLine.left(semi);

        bool ok = false;
        const qint64 chunkSize = sizeLine.trimmed().toLongLong(&ok, 16);
        // Validate the size BEFORE any chunkSize+2 arithmetic: a non-hex, negative,
        // or absurd value would otherwise overflow the availability check and run
        // left()/remove() on a bad length.
        if (!ok || chunkSize < 0 || chunkSize > kMaxChunkBytes) return ChunkResult::Error;

        if (chunkSize == 0) {
            // Terminating chunk: consume the size line and the trailer's final CRLF.
            const int trailerCrlf = buffer.indexOf("\r\n", crlf + 2);
            if (trailerCrlf < 0) return ChunkResult::NeedMore;
            buffer.remove(0, trailerCrlf + 2);
            return ChunkResult::Complete;
        }

        if (decoded.size() + chunkSize > kMaxDecodedBytes) return ChunkResult::Error;
        // size line + its CRLF + chunkSize data bytes + the trailing CRLF.
        if (buffer.size() < crlf + 2 + chunkSize + 2) return ChunkResult::NeedMore;

        buffer.remove(0, crlf + 2);
        decoded.append(buffer.left(chunkSize));
        buffer.remove(0, chunkSize + 2);
    }
}

} // namespace Nullock::Proxy::HttpLogic

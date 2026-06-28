// Pure request/response-mutation helpers for the Repeater-chain engine, split out
// of chain_runner.cpp so a unit test can link them against Qt6::Core alone --
// extractOne()/run() and their HttpClient I/O stay in chain_runner.cpp.
//
// These are the security core: an extracted value comes from the TARGET response
// (attacker-influenced) and is substituted into the NEXT on-the-wire request, so a
// raw CR/LF in a value is a header-injection / request-splitting / Content-Length-
// desync primitive (request smuggling). sanitizeExtractedValue() neutralises it;
// normalizeContentLength() additionally reconciles Transfer-Encoding and collapses
// duplicate Content-Length headers so the engine can't emit a smuggling-ambiguous
// request; jsonPathGet() preserves exact integer text (a 64-bit id/token must not
// be mangled to scientific notation). Mirrors session_rules_logic.

#include "chain_runner.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>

namespace Nullock::Core::ChainRunner {

QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QString findCookieValue(const QString &raw, const QString &name) {
    for (const QString &seg : raw.split(';')) {
        const QString s = seg.trimmed();
        const int eq = s.indexOf('=');
        if (eq <= 0) continue;
        if (s.left(eq).trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return s.mid(eq + 1).trimmed();
    }
    return {};
}

QString jsonPathGet(const QByteArray &body, const QString &path) {
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(body, &err);
    if (err.error != QJsonParseError::NoError) return {};
    QJsonValue cur = doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object());
    QString p = path;
    if (p.startsWith("$.")) p = p.mid(2);
    else if (p.startsWith("$")) p = p.mid(1);
    for (const QString &seg : p.split('.', Qt::SkipEmptyParts)) {
        if (cur.isObject()) {
            cur = cur.toObject().value(seg);
        } else if (cur.isArray()) {
            bool ok = false;
            const int idx = seg.toInt(&ok);
            if (!ok || idx < 0 || idx >= cur.toArray().size()) return {};
            cur = cur.toArray().at(idx);
        } else {
            return {};
        }
    }
    if (cur.isString()) return cur.toString();
    if (cur.isDouble()) {
        // Preserve exact integer text -- a bare QString::number(double) emits
        // scientific notation / drops digits for epoch timestamps and 64-bit IDs
        // (a mangled token substituted into the next request is silently wrong).
        const double d = cur.toDouble();
        const qint64 i = cur.toInteger();
        if (static_cast<double>(i) == d) return QString::number(i);
        return QString::number(d, 'g', 17);
    }
    if (cur.isBool()) return cur.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    return {};
}

QString sanitizeExtractedValue(const QString &v) {
    // A value pulled from a TARGET response is substituted into the NEXT request.
    // A raw CR/LF (legal inside a JSON string or a regex capture over a body) would
    // inject headers, split the request, or move the head/body boundary -- so strip
    // CR, LF and other C0 control chars. A real id/token/header/cookie value never
    // contains them; '\t' is kept (it is legal header whitespace).
    QString out;
    out.reserve(v.size());
    for (const QChar c : v)
        if (c.unicode() >= 0x20 || c == QChar('\t')) out += c;
    return out;
}

QString substituteStr(const QString &in, const QHash<QString, QString> &vars) {
    QString out = in;
    static const QRegularExpression rx(QStringLiteral(R"(\{\{([A-Za-z_][A-Za-z0-9_]*)\}\})"));
    int offset = 0;
    while (true) {
        auto m = rx.match(out, offset);
        if (!m.hasMatch()) break;
        auto it = vars.find(m.captured(1));
        if (it == vars.end()) { offset = m.capturedEnd(); continue; }
        out.replace(m.capturedStart(), m.capturedLength(), *it);
        offset = m.capturedStart() + it->size();    // no re-scan of the inserted value
    }
    return out;
}

QByteArray normalizeContentLength(const QByteArray &req) {
    // Locate the header/body boundary tolerant of CRLF *and* bare-LF framing -- a
    // bare-LF request must not bypass normalization (a desync source); use the
    // EARLIEST blank line by either terminator.
    const int crlf = req.indexOf("\r\n\r\n");
    const int lf   = req.indexOf("\n\n");
    int sep = -1, sepLen = 0;
    if (crlf >= 0 && (lf < 0 || crlf <= lf)) { sep = crlf; sepLen = 4; }
    else if (lf >= 0)                        { sep = lf;   sepLen = 2; }
    if (sep < 0) return req;                            // no header/body split at all

    const QByteArray head = req.left(sep);
    const QByteArray bodyAndTail = req.mid(sep + sepLen);
    const int bodyLen = bodyAndTail.size();

    // Transfer-Encoding: chunked is authoritative framing -- emitting Content-Length
    // alongside it is a CL.TE / TE.CL request-smuggling vector, so when chunked is
    // declared we DROP Content-Length entirely (and never add one).
    bool teChunked = false;
    for (QByteArray line : head.split('\n')) {
        if (line.endsWith('\r')) line.chop(1);
        const int colon = line.indexOf(':');
        if (colon > 0 && line.left(colon).trimmed().toLower() == "transfer-encoding"
            && line.mid(colon + 1).toLower().contains("chunked"))
            teChunked = true;
    }

    QByteArray rebuilt;
    bool emittedCl = false;
    for (QByteArray line : head.split('\n')) {
        if (line.endsWith('\r')) line.chop(1);
        const int colon = line.indexOf(':');
        if (colon > 0 && line.left(colon).trimmed().toLower() == "content-length") {
            if (teChunked) continue;                   // chunked wins -> drop CL
            if (emittedCl)  continue;                   // collapse duplicate CL to exactly one
            rebuilt += "Content-Length: " + QByteArray::number(bodyLen) + "\r\n";
            emittedCl = true;
            continue;
        }
        rebuilt += line + "\r\n";
    }
    if (!teChunked && !emittedCl && bodyLen > 0)
        rebuilt += "Content-Length: " + QByteArray::number(bodyLen) + "\r\n";
    rebuilt += "\r\n";
    rebuilt += bodyAndTail;
    return rebuilt;
}

} // namespace Nullock::Core::ChainRunner

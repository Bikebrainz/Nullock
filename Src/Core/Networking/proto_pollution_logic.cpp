// Pure (no-network) logic for the server-side prototype-pollution probe:
// sentinel/cache-buster generation, JSON-object sniffing, the structural
// exactly-N-space indent detector, the unreadable-encoding check, and the
// GET/POST builders' CR/LF guards. Split out of proto_pollution.cpp so
// Tests/proto_pollution links Qt6::Core alone (no HttpClient / Network / GUI).

#include "proto_pollution.hpp"

#include <QRandomGenerator>
#include <QUrlQuery>

namespace Nullock::Core::ProtoPollution {

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("pp");
    for (int i = 0; i < 10; ++i)
        s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

QString withBuster(const QString &query) {
    // Double-underscore prefix so it is exceedingly unlikely to clobber a real
    // application parameter on the observation endpoint.
    QUrlQuery q(query);
    q.removeAllQueryItems(QStringLiteral("__nlcb"));
    q.addQueryItem(QStringLiteral("__nlcb"), randTok());
    return q.toString(QUrl::FullyEncoded);
}

bool looksJsonObject(const QByteArray &body) {
    for (char c : body) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        return c == '{';
    }
    return false;
}

bool indentedByN(const QByteArray &body, int n) {
    // Anchor on the root object opening: `{` + newline + exactly n spaces + `"`.
    // Pinning to EXACTLY n spaces (a deeper level is 2*n, so the byte after n
    // spaces there is a space, not the quote) detects "indented by our injected
    // value" rather than "indented somehow"; the quote anchor stops a run-of-
    // spaces inside a string value from matching. Handles LF and CRLF.
    const QByteArray sp(n, ' ');
    return body.indexOf(QByteArray("{\n")   + sp + "\"") >= 0
        || body.indexOf(QByteArray("{\r\n") + sp + "\"") >= 0;
}

bool encodingUnreadable(const QString &contentEncoding) {
    const QString enc = contentEncoding.trimmed().toLower();
    return !enc.isEmpty() && enc != "identity";
}

namespace {
QByteArray writeHeaders(const Request &req, bool withContentType) {
    QByteArray out;
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/proto-pollution\r\n";
    out += "Accept: application/json, */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    if (withContentType)
        out += "Content-Type: application/json\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding: line 61 forces "identity" so jsonSpacesReflected
        // scans a PLAINTEXT body; a surviving "gzip,.." lets the server compress (client
        // never inflates) -> encodingUnreadable() flags it and test() bails
        // vulnerable=false (silent false clean). And drop a carried Transfer-Encoding: on
        // buildPollute it would coexist with the computed Content-Length (CL.TE desync).
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (withContentType && h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    return out;
}
} // namespace

QByteArray buildGet(const Request &req, const QString &path, const QString &query) {
    // host/path flow raw; a CR/LF in either would smuggle a second request line
    // or header -- refuse to build. (The query is FullyEncoded by withBuster.)
    if (req.host.contains('\r') || req.host.contains('\n')) return QByteArray();
    if (path.contains('\r') || path.contains('\n')) return QByteArray();
    const QString q = withBuster(query);
    const QString target = q.isEmpty() ? path : path + "?" + q;
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += writeHeaders(req, /*withContentType*/ false);
    out += "Connection: close\r\n\r\n";
    return out;
}

QByteArray buildPollute(const Request &req, const QString &path, const QByteArray &body) {
    if (req.host.contains('\r') || req.host.contains('\n')) return QByteArray();
    if (path.contains('\r') || path.contains('\n')) return QByteArray();
    QByteArray out = "POST " + path.toUtf8() + " HTTP/1.1\r\n";
    out += writeHeaders(req, /*withContentType*/ true);
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace Nullock::Core::ProtoPollution

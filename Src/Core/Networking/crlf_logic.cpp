// Pure CRLF-injection logic, split out of crlf_injection.cpp so a unit test can
// link it (via Networking) against Qt6::Core alone -- test() and its HttpClient
// (the Qt6::Network chain via Proxy::HttpResponse) stay in crlf_injection.cpp.
// Mirrors the established sibling pattern (http_fingerprint_logic.cpp, ...).
// Everything here is I/O-free: the request builders, query/body/path assembly,
// and the split-confirmation matcher operate on primitives (a raw response
// QByteArray, a parsed header list, the plain Request struct), never on a
// response object.

#include "crlf_injection.hpp"

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::CrlfInjection {

QByteArray buildRequest(const Request &req, const QString &query, const QByteArray &body) {
    // Self-protect the request line + Host against CR/LF regardless of caller: a
    // deep-audit path (HAR import / fromHistory) could carry a crafted
    // method/host/basePath, and the baseline query is spliced in raw.
    QString method = req.method;     method.remove('\r'); method.remove('\n');
    QString host = req.host;         host.remove('\r'); host.remove('\n');
    QString basePath = req.basePath; basePath.remove('\r'); basePath.remove('\n');
    QString q = query;               q.remove('\r'); q.remove('\n');
    const QString target = q.isEmpty() ? basePath : basePath + "?" + q;
    // Only a body-bearing method (POST/PUT/PATCH/...) carries a body, and only
    // when one is supplied -- a GET/HEAD caller passing a stray body gets none, so
    // the GET path stays byte-identical to before.
    const bool withBody = !body.isEmpty()
        && method.compare(QStringLiteral("GET"),  Qt::CaseInsensitive) != 0
        && method.compare(QStringLiteral("HEAD"), Qt::CaseInsensitive) != 0;
    QByteArray out;
    out  = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/crlf\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    bool haveContentType = false;
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // We emit our own Content-Length for the body; never carry a caller's
        // (it would mismatch and desync the request).
        if (withBody && h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) haveContentType = true;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (withBody) {
        if (!haveContentType)
            out += "Content-Type: application/x-www-form-urlencoded\r\n";
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    if (withBody) out += body;
    return out;
}

// Build the query string with `param` set to `rawValue`, preserving any other
// existing params. rawValue is spliced in RAW (already percent-encoded) so the
// CRLF escapes survive to the server -- QUrlQuery would re-encode the '%'.
QString queryWith(const QString &existing, const QString &param, const QString &rawValue) {
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        // Compare decoded names so an exotically-encoded existing key matching
        // the target isn't left in place alongside our injected copy.
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + rawValue;
    return parts.join('&');
}

// An x-www-form-urlencoded body is the same key=value&... grammar as a query
// string, so setting a body param reuses the query splicer: the RAW (already-
// encoded) value is spliced verbatim so the CR/LF escapes survive to the server.
QString bodyWith(const QString &existingBody, const QString &param, const QString &rawValue) {
    return queryWith(existingBody, param, rawValue);
}

// Splice a RAW (already percent-encoded) payload as a trailing path segment, so an
// encoded CR/LF reaches a path-reflecting sink (a path echoed into a Location /
// custom header). basePath keeps its leading slash and we never emit a double
// slash. The encoded CR/LF survives buildRequest's basePath strip (it removes
// LITERAL CR/LF only), exactly as the encoded query payload does.
QString pathWith(const QString &basePath, const QString &rawValue) {
    QString p = basePath.isEmpty() ? QStringLiteral("/") : basePath;
    if (!p.endsWith('/')) p += '/';
    return p + rawValue;
}

// OPT-IN raw-send builder for the reflected request-HEADER point. Unlike
// buildRequest -- which DROPS any carried header whose value holds CR/LF (the
// self-guard that keeps the shared audit/HAR replay path safe) -- this writes the
// single named probe header's value VERBATIM, so a marker-bearing CR/LF payload
// reaches a server that echoes an incoming header into a response header. The
// request line (method/host/path) and the header NAME are still CR/LF-stripped,
// and every OTHER carried header keeps the drop-guard, so only the one chosen
// probe header is ever carried raw -- this cannot be repurposed for request-line
// or extra-header smuggling.
QByteArray buildHeaderProbe(const Request &req, const QString &headerName,
                            const QString &rawValue) {
    QString method = req.method;     method.remove('\r'); method.remove('\n');
    QString host = req.host;         host.remove('\r'); host.remove('\n');
    QString basePath = req.basePath; basePath.remove('\r'); basePath.remove('\n');
    QString q = req.query;           q.remove('\r'); q.remove('\n');
    QString name = headerName;       name.remove('\r'); name.remove('\n');
    if (name.isEmpty()) return {};
    const QString target = q.isEmpty() ? basePath : basePath + "?" + q;
    QByteArray out;
    out  = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/crlf\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) continue;   // probe header wins
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += name.toUtf8() + ": " + rawValue.toUtf8() + "\r\n";   // the opt-in raw line
    out += "Connection: close\r\n\r\n";
    return out;
}

QStringList defaultHeaderNames() {
    return { "Referer", "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto",
             "X-Forwarded-Server", "X-Host", "X-Original-URL", "X-Forwarded-Prefix" };
}

QStringList selectedPoints(const QString &in) {
    const QString s = in.trimmed().toLower();
    if (s.isEmpty() || s == "query") return { QStringLiteral("query") };
    if (s == "all")
        return { QStringLiteral("query"), QStringLiteral("body"),
                 QStringLiteral("path"),  QStringLiteral("header") };
    static const QStringList valid = { "query", "body", "path", "header" };
    QStringList out;
    const auto parts = s.split(',', Qt::SkipEmptyParts);
    for (QString p : parts) {
        p = p.trimmed();
        if (valid.contains(p) && !out.contains(p)) out << p;
    }
    if (out.isEmpty()) out << QStringLiteral("query");   // unknown selector => safe default
    return out;
}

// Did the server split our CR/LF into a real new header line?
//   Primary: the parser surfaced our planted header with our exact value.
//   Fallback: a server that decoded the CR/LF but NOT the %3a colon emits a
//     colon-less physical line that parseHeaders drops (it skips lines without
//     ':'). Scan ONLY the header block (before the body separator) for a
//     physical line that STARTS with our marker header name and CONTAINS the
//     marker -- a body echo can't satisfy "starts with the name at a line
//     boundary", and the marker is random per probe, so this can't false-fire.
bool splitConfirmed(const QByteArray &rawResponse,
                    const QList<QPair<QString, QString>> &parsedHeaders,
                    const QString &markerName, const QString &marker) {
    for (const auto &h : parsedHeaders)
        if (h.first.compare(markerName, Qt::CaseInsensitive) == 0
            && h.second.trimmed() == marker)
            return true;

    const QString text = QString::fromLatin1(rawResponse);
    int sep = text.indexOf(QLatin1String("\r\n\r\n"));
    if (sep < 0) sep = text.indexOf(QLatin1String("\n\n"));
    // No delimited header block (e.g. body-only bytes from some future caller):
    // we cannot attribute a split header, so report unconfirmed rather than risk
    // scanning body content. (HttpClient always provides a separator.)
    if (sep < 0) return false;
    const QString headerBlock = text.left(sep);
    const QStringList lines = headerBlock.split('\n');
    for (int i = 1; i < lines.size(); ++i) {   // skip the status line (index 0)
        const QString ln = lines[i].trimmed(); // trims a trailing '\r' too
        if (ln.startsWith(markerName, Qt::CaseInsensitive) && ln.contains(marker))
            return true;
    }
    return false;
}

} // namespace Nullock::Core::CrlfInjection

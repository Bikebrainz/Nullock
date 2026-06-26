// Pure HTTP method-audit logic, split out of method_audit.cpp so a unit test
// can link it (via Networking) against Qt6::Core alone -- audit() and its
// HttpClient (the Qt6::Network chain via Proxy::HttpResponse) stay in
// method_audit.cpp. Mirrors the established sibling pattern
// (waf_detect_logic.cpp, crlf_logic.cpp, ...). Everything here is I/O-free: the
// request builder, the Allow-header classifier, and the TRACE-echo predicate
// operate on primitives (the plain Request struct, the Allow string, a body
// string).

#include "method_audit.hpp"

namespace Nullock::Core::MethodAudit {

const QStringList &writeMethods() {
    static const QStringList m = { "PUT", "DELETE", "PATCH" };
    return m;
}
const QStringList &webdavMethods() {
    // Core WebDAV (RFC 4918) plus the DeltaV (RFC 3253), ACL (RFC 3744),
    // search (RFC 5323), binding (RFC 5842), ordering (RFC 3648) and CalDAV
    // (RFC 4791) extension verbs -- all indicate a writable/extended DAV stack.
    static const QStringList m = {
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
        "SEARCH", "ACL", "REPORT", "BIND", "UNBIND", "REBIND", "ORDERPATCH",
        "VERSION-CONTROL", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE",
        "MKACTIVITY", "MERGE", "LABEL", "MKCALENDAR" };
    return m;
}

QByteArray buildReq(const Request &req, const QString &method) {
    // Self-protect the request line + Host against CR/LF regardless of caller: a
    // deep-audit path (HAR import / fromHistory) could carry a crafted
    // host/basePath/query. (method comes from a fixed internal list, but is
    // stripped too for symmetry.)
    QString m = method;          m.remove('\r'); m.remove('\n');
    QString host = req.host;     host.remove('\r'); host.remove('\n');
    QString basePath = req.basePath; basePath.remove('\r'); basePath.remove('\n');
    QString query = req.query;   query.remove('\r'); query.remove('\n');
    const QString target = query.isEmpty() ? basePath : basePath + "?" + query;
    QByteArray out = m.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/method-audit\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// Parse an Allow header value into a deduplicated, upper-cased method list.
QStringList parseAllow(const QString &allowHeader) {
    QStringList out;
    for (const QString &m : allowHeader.split(',', Qt::SkipEmptyParts)) {
        const QString name = m.trimmed().toUpper();
        if (!name.isEmpty() && !out.contains(name)) out << name;
    }
    return out;
}

QStringList dangerousWriteMethods(const QStringList &allowed) {
    QStringList out;
    for (const QString &m : allowed)
        if (writeMethods().contains(m)) out << m;
    return out;
}

QStringList dangerousWebdavMethods(const QStringList &allowed) {
    QStringList out;
    for (const QString &m : allowed)
        if (webdavMethods().contains(m)) out << m;
    return out;
}

// Did a TRACE response echo our request back (Cross-Site Tracing)? A true TRACE
// loopback (RFC 7231) returns the received request verbatim as the body, so it
// must START with our request line "TRACE " AND carry back our distinctive
// User-Agent. Requiring the request line at offset 0 (not merely "contains
// TRACE") rejects a logging/error page that quotes the request mid-body or a
// page that just mentions the word "trace".
bool traceEchoed(const QString &body) {
    // UA match is case-insensitive: an h2->h1.1 gateway may lower-case the
    // echoed header names, which must not hide a real XST loopback.
    return body.trimmed().startsWith(QLatin1String("TRACE "), Qt::CaseInsensitive)
        && body.contains(QLatin1String("User-Agent: Nullock/method-audit"), Qt::CaseInsensitive);
}

} // namespace Nullock::Core::MethodAudit

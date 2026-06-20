// Pure, I/O-free helpers for the host-header injection probe: the URL-context
// detectors and the CR/LF-guarded request builder. Kept in their OWN
// translation unit (separate from host_header.cpp's test(), which pulls
// HttpClient and the networking/GUI chain) so the unit test can link this logic
// against Qt6::Core alone.

#include "host_header.hpp"

namespace Nullock::Core::HostHeader {

// A Location header value IS itself a URL, so a bare "//sentinel" there counts.
bool locationIsUrl(const QString &location, const QString &s) {
    return location.contains("://" + s) || location.contains("//" + s);
}

// In the BODY we require the sentinel to sit as the host of an actual URL so a
// bare "//sentinel" inside a comment, JSON string, or prose can't be mistaken
// for one: a scheme ("://"+s), a QUOTED protocol-relative URL ("//s / '//s), or
// an UNQUOTED protocol-relative value in attribute position ("=//"+s, e.g.
// href=//sentinel) -- the "=" prefix is present in attributes but not in prose,
// so it doesn't reintroduce the comment/JSON false positive.
bool bodyHasUrl(const QString &body, const QString &s) {
    return body.contains("://" + s)
        || body.contains("\"//" + s) || body.contains("'//" + s)
        || body.contains("=//" + s);
}

// Build a GET/POST where the Host line is `hostLine` and one extra header is
// appended (unless empty). CR/LF-guards the method/path/query and hostLine (a
// tainted one aborts the request -> {}) and drops any CR/LF-bearing carried
// header -- matching the jwt_probe hardening pattern; the request line was
// previously unguarded (a live injection via the JSON "method" field).
QByteArray buildRequest(const Request &req, const QString &hostLine,
                        const QString &extraHeader, const QString &extraValue) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (req.query.contains('\r')    || req.query.contains('\n'))    return {};
    if (hostLine.contains('\r')     || hostLine.contains('\n'))     return {};
    const QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    const QString target = req.query.isEmpty() ? path : path + "?" + req.query;
    QByteArray out = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + hostLine.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/host-header\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (!extraHeader.isEmpty() && h.first.compare(extraHeader, Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!extraHeader.isEmpty())
        out += extraHeader.toUtf8() + ": " + extraValue.toUtf8() + "\r\n";
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::HostHeader

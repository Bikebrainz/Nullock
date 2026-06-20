// Pure, I/O-free helpers for the path-traversal probe: the file-content
// signature matcher and the CR/LF-guarded request builder. Kept in their OWN
// translation unit (separate from path_traversal.cpp's test(), which pulls
// HttpClient and the networking/GUI chain) so the unit test can link this logic
// against Qt6::Core alone.

#include "path_traversal.hpp"

#include <QRegularExpression>

namespace Nullock::Core::PathTraversal {

// Cap the bytes matched -- a greedy signature over a multi-MB body can backtrack
// badly, and the fingerprint is near the top of a served file anyway.
constexpr int kMaxBody = 512 * 1024;

// First match of a file-content signature in the body (bounded), or "".
QString matchSig(const QRegularExpression &sig, const QByteArray &body) {
    const auto m = sig.match(QString::fromUtf8(body.left(kMaxBody)));
    return m.hasMatch() ? m.captured(0) : QString();
}

// Build the raw request, CR/LF-guarding method/host/path (returns {} if any is
// tainted, e.g. an attacker-crafted method from a HAR import reaching the deep
// audit) and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/path-traversal\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::PathTraversal

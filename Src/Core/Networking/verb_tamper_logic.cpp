// Pure (no-network) logic for the verb-tampering probe: the request builder's
// CR/LF guards, denied/allowed status classification, case-variant generation,
// and the override-redundancy / HEAD-corroboration decisions. Split out of
// verb_tamper.cpp so Tests/verb_tamper links Qt6::Core alone.

#include "verb_tamper.hpp"

namespace Nullock::Core::VerbTamper {

// Denied / access-controlled states worth trying to bypass. Includes 404
// because hiding a protected resource behind a 404 is a common pattern.
bool isDenied(int status) {
    return status == 401 || status == 403 || status == 404 || status == 405;
}
bool isAllowed(int status) { return status >= 200 && status < 300; }

QByteArray buildRequest(const Request &req, const QString &method,
                        const QList<QPair<QString, QString>> &extraHeaders) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // method/host/path flow raw from the deep-audit / fromHistory path; a CR/LF
    // in any would smuggle a second request line or header -- refuse to build.
    if (crlf(method) || crlf(req.host) || crlf(req.basePath)) return QByteArray();

    const bool hasBody = !req.body.isEmpty();
    // POST/PUT/PATCH conventionally carry a body; some servers reject one
    // sent with no Content-Length at all, so always frame it (even as 0).
    const bool bodyMethod = method.compare("POST",  Qt::CaseInsensitive) == 0
                         || method.compare("PUT",   Qt::CaseInsensitive) == 0
                         || method.compare("PATCH", Qt::CaseInsensitive) == 0;
    QByteArray out;
    out  = method.toUtf8() + " " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/verb-tamper\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    for (const auto &h : extraHeaders) {
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (hasBody || bodyMethod)
        out += "Content-Length: " + QByteArray::number(req.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    if (hasBody) out += req.body;
    return out;
}

QStringList caseVariants(const QString &method) {
    QStringList out;
    const QString lower = method.toLower();
    if (lower != method) out << lower;          // GET -> get (front-end denylist bypass)
    if (!method.isEmpty()) {
        QString cap = method.toLower();
        cap[0] = cap[0].toUpper();              // GET -> Get
        if (cap != method && !out.contains(cap)) out << cap;
    }
    return out;
}

bool overrideAddedNothing(int overrideStatus, const QByteArray &overrideBody,
                          int carrierStatus, const QByteArray &carrierBody) {
    return overrideStatus == carrierStatus && overrideBody == carrierBody;
}

bool headIsBypass(int status, int headContentLength, int denialContentLength) {
    return isAllowed(status) && headContentLength > 0
        && headContentLength != denialContentLength;
}

} // namespace Nullock::Core::VerbTamper

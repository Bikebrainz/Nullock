// Pure (no-network) logic for the mass-assignment probe: JSON-vs-form body
// sniffing, the accepted-status (2xx) gate, and the request builder's CR/LF
// guards. Split out of mass_assign.cpp so Tests/mass_assign links Qt6::Core
// alone (no HttpClient / Network / GUI chain).

#include "mass_assign.hpp"

namespace Nullock::Core::MassAssign {

bool looksJson(const QByteArray &body, const QString &contentType) {
    if (contentType.contains("json", Qt::CaseInsensitive)) return true;
    if (contentType.contains("x-www-form-urlencoded", Qt::CaseInsensitive)) return false;
    const QByteArray t = body.trimmed();
    return t.startsWith('{') || t.startsWith('[');
}

bool acceptedStatus(int status) {
    return status >= 200 && status < 300;
}

// The reflection control (a junk field no model binds) is only USABLE when it
// actually completed AND the junk was NOT echoed. A control that failed at
// transport is inconclusive -> not usable (fail-closed), so a raw-echo endpoint
// whose control request happened to drop can't fabricate mass-assignment finds.
bool reflectionControlUsable(bool controlOk, bool junkEchoed) {
    return controlOk && !junkEchoed;
}

QByteArray buildRequest(const Request &req, bool json, const QByteArray &body) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // method/host/path flow raw from the deep-audit / fromHistory path; a CR/LF
    // in any would smuggle a second request line or header -- refuse to build.
    if (crlf(req.method) || crlf(req.host) || crlf(req.basePath)) return QByteArray();

    QByteArray out;
    out  = req.method.toUtf8() + " " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/mass-assign\r\n";
    out += "Accept: */*\r\n";
    // Force an identity (uncompressed) response: we scan the body for our
    // marker, and the HTTP client doesn't inflate gzip/deflate -- without
    // this, every compressed endpoint would hide the marker (false clean).
    out += "Accept-Encoding: identity\r\n";
    bool haveCt = false;
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Transfer-Encoding too: we emit our OWN Content-Length
        // (below), so a surviving Transfer-Encoding would make this probe's own
        // outbound request CL.TE-ambiguous -- request smuggling in our own send.
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding: we force "identity" above (line 43) so a
        // gzip response can't hide the echoed marker; a surviving "gzip, deflate, br"
        // combines (RFC 7230 3.2.2) to let the server compress and the client does
        // NOT inflate -> the marker scan sees compressed bytes and reports false clean.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) haveCt = true;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!haveCt)
        out += QByteArray("Content-Type: ")
             + (json ? "application/json" : "application/x-www-form-urlencoded") + "\r\n";
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace Nullock::Core::MassAssign

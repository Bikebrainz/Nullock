#include "ssrf_logic.hpp"

namespace Nullock::Core::SsrfScan {

QByteArray buildRequest(const Request &req, const QString &query) {
    // Request-line / Host injection guard. method, basePath, AND host are written
    // RAW into the request line and the Host header below, so a CR or LF in any
    // of them would inject a header or split the request. (basePath's CR/LF was
    // already guarded; req.host -- written as "Host: <host>" -- previously was
    // not, an inconsistency this closes.)
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};

    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ssrf\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QStringList knownSsrfParams() {
    // URL-typed sink names only -- generic search/short names (q, query, r, ...)
    // are deliberately excluded: auto-detect picks the first match and stops,
    // so a non-sink name would steal the probe budget from the real sink.
    // NOTE: entries MUST stay lowercase -- the caller matches via
    // known.contains(paramName.toLower()).
    return { "url", "uri", "target", "targeturl", "dest", "dest_url",
             "destination", "redirect", "redirect_uri", "redirect_url",
             "return", "returnurl", "return_url", "callback", "callback_url",
             "webhook", "feed", "rss", "atom", "image", "image_url", "imageurl",
             "avatar", "avatar_url", "logo", "thumb", "thumbnail", "preview",
             "path", "file", "link", "src", "source", "sourceurl", "host",
             "hostname", "address", "addr", "domain", "site", "page", "fetch",
             "load", "proxy", "next", "continue", "data", "reference", "ref",
             "out", "to", "view", "show", "goto", "forward", "forward_url",
             "origin", "remote", "resource", "document", "wsdl", "xsl",
             "upload", "endpoint", "server", "u", "uri_ref" };
}

bool controlProvesFetch(bool controlOk, bool controlReproducedSig) {
    // FAIL CLOSED: report only when the shaped control RAN and did NOT carry the
    // signature. A control that reproduced the signature means shape-tracking
    // (not a fetch); a control that failed to run leaves the FP defeater unrun,
    // so the hit is unproven -- either way, do not report.
    return controlOk && !controlReproducedSig;
}

} // namespace Nullock::Core::SsrfScan

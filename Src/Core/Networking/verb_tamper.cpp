#include "verb_tamper.hpp"
#include "networking.hpp"

namespace Nullock::Core::VerbTamper {

namespace {

QByteArray buildRequest(const Request &req, const QString &method,
                        const QList<QPair<QString, QString>> &extraHeaders) {
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
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    for (const auto &h : extraHeaders)
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    if (hasBody || bodyMethod)
        out += "Content-Length: " + QByteArray::number(req.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    if (hasBody) out += req.body;
    return out;
}

// Denied / access-controlled states worth trying to bypass. Includes 404
// because hiding a protected resource behind a 404 is a common pattern.
bool isDenied(int status) {
    return status == 401 || status == 403 || status == 404 || status == 405;
}
bool isAllowed(int status) { return status >= 200 && status < 300; }

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &method,
                    const QList<QPair<QString, QString>> &extra = {}) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, method, extra));
    };

    // Baseline as-is.
    const auto base = send(req.method);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    result.baselineDenied = isDenied(result.baselineStatus);
    if (!result.baselineDenied) return result;   // nothing to bypass
    const QByteArray denialBody = base.parsed.body;

    // Control probe: a bogus method no router defines. If the server still
    // answers 2xx, it doesn't discriminate by method at all (a catch-all /
    // SPA backend that 200s everything) -- so any "bypass" we'd report is
    // noise. Suppress the whole method/override signal in that case.
    const auto control = send("XYZZY");
    const bool methodControlOpen = control.ok && isAllowed(control.parsed.statusCode);
    if (methodControlOpen) return result;

    // A variant is a real bypass only if it returns 2xx AND (for verbs that
    // carry a body) the body differs from the denial page -- a 200 that
    // re-serves the same "forbidden" page, or an empty CORS/OPTIONS 200,
    // isn't access to the protected resource.
    auto consider = [&](const QString &technique, const QString &detail,
                        const HttpClient::SendResult &r, bool bodyless) {
        if (!r.ok || !isAllowed(r.parsed.statusCode)) return;
        if (!bodyless && r.parsed.body == denialBody) return;   // same denial page
        result.bypasses.append({ technique, detail, r.parsed.statusCode });
    };

    // 1) Alternate content-serving methods (OPTIONS/TRACE excluded: their
    //    2xx is preflight/echo, not resource access).
    static const QStringList methods = {
        "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE",
    };
    for (const QString &m : methods) {
        if (m.compare(req.method, Qt::CaseInsensitive) == 0) continue;
        consider("method:" + m,
                 "served under " + m + " while " + req.method + " is denied",
                 send(m), m == "HEAD");
    }

    // 2) Method-override headers. Carry the request under a method a front
    //    end is unlikely to block (POST, or GET if the baseline is POST)
    //    and ask the back end to route it as the denied method.
    const QString carrier = (req.method.compare("POST", Qt::CaseInsensitive) == 0)
                            ? QStringLiteral("GET") : QStringLiteral("POST");
    static const QStringList overrideHeaders = {
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    };
    for (const QString &h : overrideHeaders) {
        consider("override:" + h,
                 h + ": " + req.method + " (carried as " + carrier
                     + ") flipped a denied request to allowed",
                 send(carrier, {{ h, req.method }}), false);
    }

    return result;
}

} // namespace Nullock::Core::VerbTamper

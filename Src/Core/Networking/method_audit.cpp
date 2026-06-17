#include "method_audit.hpp"
#include "networking.hpp"

namespace Nullock::Core::MethodAudit {

namespace {

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

QByteArray buildReq(const Request &req, const QString &method) {
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    QByteArray out = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
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

const QStringList &writeMethods() {
    static const QStringList m = { "PUT", "DELETE", "PATCH" };
    return m;
}
const QStringList &webdavMethods() {
    static const QStringList m = { "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK" };
    return m;
}

} // namespace

Result audit(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto add = [&](const QString &k, const QString &sev, const QString &d) {
        result.findings.append({ k, sev, d });
    };

    const auto opt = client.send(req.host, port, req.tls, buildReq(req, "OPTIONS"));
    if (!opt.ok) { result.error = "OPTIONS failed: " + opt.errorMessage; return result; }
    result.optionsStatus = opt.parsed.statusCode;

    const QString allow = headerValue(opt.parsed, "Allow");
    for (const QString &m : allow.split(',', Qt::SkipEmptyParts))
        result.allowed << m.trimmed().toUpper();

    QStringList dangerousWrite, dangerousDav;
    for (const QString &m : result.allowed) {
        if (writeMethods().contains(m))  dangerousWrite << m;
        if (webdavMethods().contains(m)) dangerousDav << m;
    }
    if (!dangerousWrite.isEmpty())
        add("dangerous-http-methods", "medium",
            "server advertises write methods: " + dangerousWrite.join(", "));
    if (!dangerousDav.isEmpty())
        add("webdav-enabled", "medium",
            "WebDAV methods advertised: " + dangerousDav.join(", "));

    // TRACE echo probe (non-mutating): if the server reflects the request back,
    // it's vulnerable to Cross-Site Tracing -- a request smuggling-free way to
    // read otherwise-HttpOnly headers via a scripted client.
    const auto tr = client.send(req.host, port, req.tls, buildReq(req, "TRACE"));
    if (tr.ok && tr.parsed.statusCode >= 200 && tr.parsed.statusCode < 300) {
        const QString body = QString::fromUtf8(tr.parsed.body.left(2048));
        if (body.contains("TRACE ", Qt::CaseInsensitive)
            && body.contains("User-Agent: Nullock/method-audit")) {
            result.traceEnabled = true;
            add("http-trace-enabled", "medium",
                "TRACE is enabled and echoes the request (Cross-Site Tracing / XST)");
        }
    }

    return result;
}

} // namespace Nullock::Core::MethodAudit

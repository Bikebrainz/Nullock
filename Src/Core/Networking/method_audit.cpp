#include "method_audit.hpp"
#include "networking.hpp"

namespace Nullock::Core::MethodAudit {

// The pure builder/classifier (buildReq, parseAllow, dangerousWriteMethods,
// dangerousWebdavMethods, traceEchoed) lives in method_audit_logic.cpp so it can
// be unit-tested against Qt6::Core alone. This TU keeps audit(), which pulls in
// HttpClient (the Qt6::Network chain via Proxy::HttpResponse) and is I/O.

namespace {

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
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

    result.allowed = parseAllow(headerValue(opt.parsed, "Allow"));
    const QStringList dangerousWrite = dangerousWriteMethods(result.allowed);
    const QStringList dangerousDav   = dangerousWebdavMethods(result.allowed);
    // These are ADVERTISED in the OPTIONS Allow header, not confirmed callable or
    // unauthenticated -- the probe never issues the mutating method (by design).
    // Every access-controlled REST/CRUD API advertises PUT/DELETE, so this is
    // reconnaissance (info), not a confirmed vuln; the operator confirms
    // intrusively if authorized.
    if (!dangerousWrite.isEmpty())
        add("dangerous-http-methods", "info",
            "server advertises write methods in OPTIONS Allow (not confirmed "
            "callable/unauthenticated): " + dangerousWrite.join(", "));
    if (!dangerousDav.isEmpty())
        add("webdav-enabled", "info",
            "WebDAV methods advertised in OPTIONS Allow (not confirmed functional/"
            "unauthenticated): " + dangerousDav.join(", "));

    // TRACE echo probe (non-mutating): if the server reflects the request back,
    // it's vulnerable to Cross-Site Tracing -- a request smuggling-free way to
    // read otherwise-HttpOnly headers via a scripted client.
    const auto tr = client.send(req.host, port, req.tls, buildReq(req, "TRACE"));
    if (tr.ok && tr.parsed.statusCode >= 200 && tr.parsed.statusCode < 300) {
        if (traceEchoed(QString::fromUtf8(tr.parsed.body.left(2048)))) {
            result.traceEnabled = true;
            add("http-trace-enabled", "medium",
                "TRACE is enabled and echoes the request (Cross-Site Tracing / XST)");
        }
    }

    return result;
}

} // namespace Nullock::Core::MethodAudit

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
    // Track whether ANY probe got a response. The OPTIONS-failure fallthrough
    // means a blocked OPTIONS must not, on its own, mark the whole audit failed;
    // we only set result.error when nothing answered (host unreachable).
    bool anyResponse = false;
    QString firstError;
    auto noteFail = [&](const QString &where, const QString &msg) {
        if (firstError.isEmpty()) firstError = where + " failed: " + msg;
    };

    // OPTIONS: the primary Allow source -- but do NOT bail if it fails or comes
    // back empty. A proxy may block OPTIONS while the methods themselves work.
    const auto opt = client.send(req.host, port, req.tls, buildReq(req, "OPTIONS"));
    if (opt.ok) {
        anyResponse = true;
        result.optionsStatus = opt.parsed.statusCode;
        result.allowed = parseAllow(headerValue(opt.parsed, "Allow"));
    } else {
        noteFail("OPTIONS", opt.errorMessage);
    }

    // 405-harvest: many servers omit Allow on OPTIONS but DO return it on a 405
    // Method Not Allowed. Send a deliberately-bogus method and fold any Allow it
    // hands back into the advertised set. Runs even when OPTIONS gave nothing.
    const auto bogus = client.send(req.host, port, req.tls, buildReq(req, "XYZZY"));
    if (bogus.ok) {
        anyResponse = true;
        result.allowed = mergeAllow(result.allowed, headerValue(bogus.parsed, "Allow"));
    } else {
        noteFail("405-harvest", bogus.errorMessage);
    }

    // Cross-Site Tracing family (all non-mutating): if the server reflects the
    // request back, a scripted client can read otherwise-HttpOnly headers.
    //   TRACE              -- the classic XST loopback.
    //   TRACK              -- IIS's alias for TRACE; bypasses TRACE-only blocks.
    //   TRACE Max-Forwards:0 -- forces the FIRST hop to answer, surfacing a
    //                         proxy that echoes even when the origin does not.
    // Each keeps the offset-0 + case-insensitive-UA discipline (traceEchoed).
    auto echoProbe = [&](const QString &method, const QString &expectVerb,
                         const QList<QPair<QString, QString>> &extra) -> bool {
        Request er = req;
        for (const auto &h : extra) er.headers.append(h);
        const auto r = client.send(req.host, port, req.tls, buildReq(er, method));
        if (!r.ok) { noteFail(method, r.errorMessage); return false; }
        anyResponse = true;
        if (r.parsed.statusCode < 200 || r.parsed.statusCode >= 300) return false;
        return traceEchoed(QString::fromUtf8(r.parsed.body.left(2048)), expectVerb);
    };

    const bool traceEcho  = echoProbe("TRACE", "TRACE", {});
    const bool maxFwdEcho  = echoProbe("TRACE", "TRACE", { { "Max-Forwards", "0" } });
    const bool trackEcho  = echoProbe("TRACK", "TRACK", {});
    result.traceEnabled = traceEcho || maxFwdEcho || trackEcho;

    // The which-input-yields-which-finding decision is the pure, unit-tested
    // classifyMethods(); audit() only harvested the Allow list + ran the echo
    // probes above. Emitting in its order: dangerous-write, webdav, trace, track.
    for (const Finding &f : classifyMethods(result.allowed, traceEcho, maxFwdEcho, trackEcho))
        add(f.kind, f.severity, f.detail);

    // Only a total blackout -- nothing answered any probe -- is a hard error.
    if (!anyResponse) result.error = firstError.isEmpty()
        ? QStringLiteral("all method-audit probes failed") : firstError;

    return result;
}

} // namespace Nullock::Core::MethodAudit

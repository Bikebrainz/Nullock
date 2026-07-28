#include "http3_detect.hpp"
#include "http3_logic.hpp"
#include "networking.hpp"

namespace Nullock::Core::Http3Detect {

namespace {

using Proxy::HttpResponse;

QStringList allHeaderValues(const HttpResponse &r, const QString &name) {
    QStringList out;
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second;
    return out;
}

} // namespace

Result detect(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    // Validate before the quint16 cast: an out-of-range int would silently wrap
    // (65536 -> 0, -1 -> 65535) and probe the wrong port.
    if (req.port < 1 || req.port > 65535) { result.error = "invalid port"; return result; }

    // buildGet() returns {} to REJECT a CR/LF-tainted host/path/query. Passing that
    // straight to send() turned an input-validation rejection into a silent zero-byte
    // probe (and a meaningless result) instead of surfacing the refusal.
    const QByteArray raw = buildGet(req);
    if (raw.isEmpty()) { result.error = "invalid request (CR/LF in host, path or query)"; return result; }

    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, raw);
    if (!r.ok) { result.error = "request failed: " + r.errorMessage; return result; }
    result.baselineStatus = r.parsed.statusCode;

    const QStringList altSvc = allHeaderValues(r.parsed, "Alt-Svc");
    result.altSvcRaw = altSvc.join(", ");
    for (const QString &v : altSvc)
        result.protocols += parseAltSvc(v);

    for (const AltProtocol &p : result.protocols) {
        if (p.isHttp3) {
            result.advertisesHttp3 = true;
            if (!result.http3Versions.contains(p.id))
                result.http3Versions << p.id;
        }
    }
    return result;
}

} // namespace Nullock::Core::Http3Detect

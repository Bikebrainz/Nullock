#include "host_header.hpp"
#include "networking.hpp"

#include <QRandomGenerator>

namespace Nullock::Core::HostHeader {

namespace {

using Proxy::HttpResponse;

// The host-class headers worth probing. `replacesHost` overrides the real Host
// line (the literal password-reset-poisoning vector); the rest are forwarding
// headers a reverse proxy / framework commonly trusts ahead of Host.
struct Probe {
    const char *header;
    bool        replacesHost;
    bool        forwardedSyntax;   // value is "host=<sentinel>" (RFC 7239)
};
const QList<Probe> &probes() {
    static const QList<Probe> p = {
        { "Host",               true,  false },
        { "X-Forwarded-Host",   false, false },
        { "X-Host",             false, false },
        { "X-Forwarded-Server", false, false },
        { "X-Original-Host",    false, false },
        { "Forwarded",          false, true  },
    };
    return p;
}

QString sentinel() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nullock-hhi-");
    for (int i = 0; i < 8; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s + QStringLiteral(".test");
}

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

} // namespace

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    bool gotAnyResponse = false;
    for (const Probe &p : probes()) {
        const QString header = QString::fromUtf8(p.header);
        const QString s = sentinel();
        const QString injectValue = p.forwardedSyntax ? ("host=" + s) : s;

        QByteArray raw;
        if (p.replacesHost)
            raw = buildRequest(req, s, QString(), QString());      // Host: <sentinel>
        else
            raw = buildRequest(req, req.host, header, injectValue); // real Host + forwarding header

        ++result.requestsSent;
        const auto r = client.send(req.host, port, req.tls, raw);
        if (!r.ok) continue;
        gotAnyResponse = true;
        if (result.baselineStatus == 0) result.baselineStatus = r.parsed.statusCode;

        const QString location = headerValue(r.parsed, "Location");
        const QString body = QString::fromUtf8(r.parsed.body);

        // The whole reflection classification (url-context, header-reflection,
        // the skip gate, the where cascade, injection-vs-reflection) is the pure,
        // unit-tested classifyHostReflection().
        const HostVerdict v = classifyHostReflection(s, header, p.replacesHost,
                                                     location, body, r.parsed.headers);
        if (!v.report)
            continue;   // sentinel didn't come back -> nothing to report
        if (v.anyInjection)      result.anyInjection = true;
        else if (v.anyReflected) result.anyReflected = true;
        result.hits.append(v.hit);
    }

    if (!gotAnyResponse && result.hits.isEmpty())
        result.error = "all probes failed (no response)";
    return result;
}

} // namespace Nullock::Core::HostHeader

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

        const bool locUrl  = locationIsUrl(location, s);
        const bool bodyUrl = bodyHasUrl(body, s);

        // Reflection anywhere, including response headers (e.g. an injected host
        // echoed into a Set-Cookie Domain=), which a Location-only check misses.
        QString hdrHit;
        for (const auto &hh : r.parsed.headers)
            if (hh.second.contains(s)) { hdrHit = hh.first; break; }

        Hit hit;
        hit.header = header;
        hit.sentinel = s;
        hit.fromHostLine = p.replacesHost;   // the literal Host line (victim's
                                             // browser sends it) vs a forwarding
                                             // header (not victim-deliverable)
        hit.inLocation   = location.contains(s);
        hit.inUrlContext = locUrl || bodyUrl;
        hit.reflected    = body.contains(s) || !hdrHit.isEmpty() || hit.inLocation;

        if (!hit.inUrlContext && !hit.reflected)
            continue;   // sentinel didn't come back -> nothing to report

        if (locUrl)                 hit.where = QStringLiteral("Location");
        else if (bodyUrl)           hit.where = QStringLiteral("body-url");
        else if (!hdrHit.isEmpty()) hit.where = QStringLiteral("header:") + hdrHit;
        else                        hit.where = QStringLiteral("body");

        if (hit.inUrlContext)   result.anyInjection = true;
        else if (hit.reflected) result.anyReflected = true;
        result.hits.append(hit);
    }

    if (!gotAnyResponse && result.hits.isEmpty())
        result.error = "all probes failed (no response)";
    return result;
}

} // namespace Nullock::Core::HostHeader

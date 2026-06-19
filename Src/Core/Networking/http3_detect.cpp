#include "http3_detect.hpp"
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

QByteArray buildGet(const Request &req) {
    const QString path = req.path.isEmpty() ? QStringLiteral("/") : req.path;
    const QString target = req.query.isEmpty() ? path : path + "?" + req.query;
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/http3-detect\r\n";
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

// An h3 protocol-id is "h3" or "h3-<anything>" (drafts h3-29, h3-Q050, ...).
// Match the token start so "h3-29" counts but unrelated ids like "h2" don't.
bool looksHttp3(const QString &id) {
    return id == QLatin1String("h3") || id.startsWith(QLatin1String("h3-"));
}

// Parse one RFC-7838 Alt-Svc field value into protocol entries. The value is a
// comma-separated list of `protocol-id=authority` with optional `; ma=N` /
// `; persist=1` parameters. "clear" means the server is withdrawing all
// advertisements -- we return nothing for it.
QList<AltProtocol> parseAltSvc(const QString &value) {
    QList<AltProtocol> out;
    if (value.trimmed().compare(QLatin1String("clear"), Qt::CaseInsensitive) == 0)
        return out;
    for (const QString &entryRaw : value.split(',', Qt::SkipEmptyParts)) {
        const QStringList parts = entryRaw.split(';');
        if (parts.isEmpty()) continue;
        const QString head = parts.first().trimmed();
        const int eq = head.indexOf('=');
        if (eq <= 0) continue;
        AltProtocol p;
        p.id = head.left(eq).trimmed();
        p.authority = head.mid(eq + 1).trimmed();
        if (p.authority.startsWith('"') && p.authority.endsWith('"') && p.authority.size() >= 2)
            p.authority = p.authority.mid(1, p.authority.size() - 2);
        for (int i = 1; i < parts.size(); ++i) {
            const QString param = parts.at(i).trimmed();
            if (param.startsWith(QLatin1String("ma="), Qt::CaseInsensitive)) {
                bool ok = false;
                const int ma = param.mid(3).trimmed().toInt(&ok);
                if (ok) p.maxAge = ma;
            }
        }
        if (p.id.isEmpty()) continue;
        p.isHttp3 = looksHttp3(p.id);
        out.append(p);
    }
    return out;
}

} // namespace

Result detect(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
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

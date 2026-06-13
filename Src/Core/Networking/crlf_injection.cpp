#include "crlf_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrlQuery>

namespace Nullock::Core::CrlfInjection {

namespace {

// The marker header an injected payload tries to plant. If it comes back in
// the parsed response, the server split our CR/LF into a new header line.
const QString kMarkerName = QStringLiteral("X-Nullock-Crlf");

struct Technique { const char *name; const char *sep; };

// Each separator is the CR/LF encoding a vulnerable decoder might accept.
const QList<Technique> &techniques() {
    static const QList<Technique> t = {
        { "crlf",            "%0d%0a" },
        { "lf-only",         "%0a" },
        { "cr-only",         "%0d" },
        { "double-encoded",  "%250d%250a" },
        { "unicode-overlong","%e5%98%8a%e5%98%8d" },
    };
    return t;
}

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/crlf\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// Build the query string with `param` set to `rawValue`, preserving any other
// existing params. rawValue is spliced in RAW (already percent-encoded) so the
// CRLF escapes survive to the server -- QUrlQuery would re-encode the '%'.
QString queryWith(const QString &existing, const QString &param, const QString &rawValue) {
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        // Compare decoded names so an exotically-encoded existing key matching
        // the target isn't left in place alongside our injected copy.
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + rawValue;
    return parts.join('&');
}

} // namespace

QStringList defaultParams() {
    return { "redirect", "url", "next", "return", "returnurl", "dest", "lang",
             "page", "q", "ref", "callback", "goto" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Which params to probe.
    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
    }
    while (params.size() > 8) params.removeLast();   // cap work
    result.testedParams = params;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, query));
    };

    const auto base = send(req.query);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    // If the marker header somehow already exists, we can't attribute it.
    if (!headerValue(base.parsed, kMarkerName).isEmpty()) {
        result.error = "inconclusive: the marker header is present at baseline";
        return result;
    }

    for (const QString &param : params) {
        for (const Technique &t : techniques()) {
            // A fresh random marker per probe so a hit is unambiguous.
            const QString marker = QStringLiteral("nlk")
                + QString::number(QRandomGenerator::global()->bounded(100000, 999999));
            const QString payload = QStringLiteral("nlk") + QString::fromUtf8(t.sep)
                + kMarkerName + "%3a" + marker;   // %3a == ':'
            const auto r = send(queryWith(req.query, param, payload));
            if (!r.ok) continue;
            // Confirmed iff the server emitted our marker header with our value.
            if (headerValue(r.parsed, kMarkerName).trimmed() == marker) {
                result.hits.append({ param, QString::fromUtf8(t.name),
                                     payload, kMarkerName + ": " + marker });
                result.vulnerable = true;
                break;   // this param is proven; move to the next
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::CrlfInjection

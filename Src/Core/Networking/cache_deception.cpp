#include "cache_deception.hpp"
#include "networking.hpp"

#include <QRandomGenerator>

namespace Nullock::Core::CacheDeception {

namespace {

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// Would a shared cache plausibly store this response? Hit signal, or a public/
// max-age>0 Cache-Control without no-store/private. (Static-extension URLs are
// often cached even against Cache-Control by mis-tuned CDNs, but we report the
// header signal as the higher-confidence case.)
bool looksCacheable(const Proxy::HttpResponse &r) {
    if (!headerValue(r, "Age").isEmpty()) return true;
    const QString xc = headerValue(r, "X-Cache") + " " + headerValue(r, "CF-Cache-Status");
    if (xc.contains("hit", Qt::CaseInsensitive)) return true;
    const QString cc = headerValue(r, "Cache-Control").toLower();
    if (cc.contains("no-store") || cc.contains("private")) return false;
    return cc.contains("public") || cc.contains("max-age");
}

QByteArray buildGet(const Request &req, const QString &path) {
    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cache-deception\r\n";
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

bool lenSimilar(int a, int b) {
    const int mx = qMax(a, b), d = qAbs(a - b);
    return d <= 40 || (mx > 0 && double(d) / mx < 0.10);
}

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 6; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    const quint16 port = static_cast<quint16>(req.port);
    HttpClient client;
    auto send = [&](const QString &path) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildGet(req, path));
    };

    QString base = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    if (!req.query.isEmpty()) base += "?" + req.query;

    const auto baseResp = send(base);
    if (!baseResp.ok) { result.error = "baseline failed: " + baseResp.errorMessage; return result; }
    result.baselineStatus = baseResp.parsed.statusCode;
    const QByteArray baseBody = baseResp.parsed.body;
    result.baselineLen = baseBody.size();
    // A non-2xx baseline (login redirect / 404) has no sensitive page to leak.
    if (baseResp.parsed.statusCode < 200 || baseResp.parsed.statusCode >= 300) {
        result.error = "baseline not a 2xx page (nothing to deceive)";
        return result;
    }

    const QString pathOnly = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    static const QStringList exts = { ".css", ".js", ".jpg", ".png", ".ico" };
    for (const QString &ext : exts) {
        // /<path>/<random>.css -- a suffix a cache treats as static.
        const QString sep = pathOnly.endsWith('/') ? QString() : QStringLiteral("/");
        const QString probe = pathOnly + sep + randTok() + ext;
        const auto r = send(probe);
        if (!r.ok) continue;
        if (r.parsed.statusCode < 200 || r.parsed.statusCode >= 300) continue;
        // Path confusion: the dynamic page is echoed at the static URL (the app
        // ignored the suffix) rather than returning a 404 or a real asset.
        if (!lenSimilar(r.parsed.body.size(), baseBody.size())) continue;
        const bool cacheable = looksCacheable(r.parsed);
        result.hits.append({ ext, probe, cacheable,
            QString("dynamic page served at static URL %1%2")
                .arg(probe, cacheable ? " AND response is cacheable" : "") });
    }
    return result;
}

} // namespace Nullock::Core::CacheDeception

#include "secret_scanner.hpp"
#include "networking.hpp"

#include <QSet>
#include <QUrl>

namespace Nullock::Core::SecretScanner {

// (The pattern table, scanText(), filters, mask(), sameOriginScripts() and
// buildGet() live in secret_logic.cpp so the regression test can exercise the
// detection without the network stack.)

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    QSet<QString> seen;   // de-dupe by type|masked

    auto scanBody = [&](const QString &body, const QString &loc) {
        ++result.resourcesScanned;
        for (const Hit &h : scanText(body, loc)) {
            const QString dedupe = h.type + "|" + h.masked;
            if (seen.contains(dedupe)) continue;
            seen.insert(dedupe);
            result.hits.append(h);
        }
    };

    QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    ++result.requestsSent;
    const auto main = client.send(req.host, port, req.tls, buildGet(req, path, req.query));
    if (!main.ok) { result.error = "request failed: " + main.errorMessage; return result; }
    const QString mainBody = QString::fromUtf8(main.parsed.body.left(maxScanBytes()));
    scanBody(mainBody, req.tls ? "https://" + req.host + path : "http://" + req.host + path);

    if (req.followScripts) {
        QUrl base;
        base.setScheme(req.tls ? "https" : "http");
        base.setHost(req.host); base.setPort(req.port); base.setPath(path);
        for (const QString &sp : sameOriginScripts(mainBody, base, req.maxScripts)) {
            const int q = sp.indexOf('?');
            const QString spath = q < 0 ? sp : sp.left(q);
            const QString squery = q < 0 ? QString() : sp.mid(q + 1);
            ++result.requestsSent;
            const auto sr = client.send(req.host, port, req.tls, buildGet(req, spath, squery));
            if (!sr.ok) continue;
            scanBody(QString::fromUtf8(sr.parsed.body.left(maxScanBytes())),
                     (req.tls ? "https://" : "http://") + req.host + spath);
        }
    }

    return result;
}

} // namespace Nullock::Core::SecretScanner

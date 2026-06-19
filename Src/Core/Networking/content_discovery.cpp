#include "content_discovery.hpp"
#include "networking.hpp"

#include <QRandomGenerator>

#include <algorithm>
#include <cstdlib>

namespace Nullock::Core::ContentDiscovery {

namespace {

constexpr int kMaxBody = 256 * 1024;

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

QString randToken() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nl404");
    for (int i = 0; i < 10; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

// Normalise the base dir to "" or "/sub" (no trailing slash), so base + "/" +
// word always yields a single-slash join.
QString normBase(const QString &p) {
    QString b = p;
    if (b == "/" ) return QString();
    while (b.endsWith('/')) b.chop(1);
    if (!b.isEmpty() && !b.startsWith('/')) b.prepend('/');
    return b;
}

QByteArray buildGet(const Request &req, const QString &fullPath) {
    QByteArray out = "GET " + fullPath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/content-discovery\r\n";
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

} // namespace

QStringList defaultWordlist() {
    return {
        // dirs / panels
        "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
        "console", "manager", "manage", "portal", "cpanel", "phpmyadmin", "pma",
        "adminer.php", "user", "users", "account", "auth", "signin", "register",
        // api / app
        "api", "api/v1", "api/v2", "graphql", "graphiql", "swagger", "swagger-ui",
        "swagger.json", "openapi.json", "api-docs", "v1", "v2", "rest", "rpc",
        "actuator", "actuator/health", "metrics", "health", "status", "debug",
        // vcs / config / sensitive
        ".git", ".git/config", ".git/HEAD", ".svn", ".hg", ".env", ".env.local",
        ".env.production", "config", "config.php", "config.json", "configuration.php",
        "settings.py", "web.config", "appsettings.json", "wp-config.php.bak",
        "server-status", "server-info", "phpinfo.php", "info.php", ".htaccess",
        "robots.txt", "sitemap.xml", "crossdomain.xml", ".DS_Store", "Dockerfile",
        "docker-compose.yml", ".dockerignore", "package.json", "composer.json",
        "composer.lock", "yarn.lock", ".npmrc", ".aws/credentials",
        // backups / archives
        "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
        "dump.sql", "database.sql", "site.zip", "www.zip", "app.zip", "old", "bak",
        "test", "tests", "temp", "tmp", "dev", "staging", "beta", "demo",
        // uploads / data
        "uploads", "upload", "files", "file", "media", "static", "assets", "data",
        "private", "secret", "internal", "logs", "log", "error.log", "access.log",
        // misc
        "cgi-bin", "includes", "vendor", "node_modules", ".well-known/security.txt",
        "readme.md", "README.md", "CHANGELOG.md", "license.txt", "install",
        "setup", "installer", "update", "shell", "cmd", "tools",
    };
}

Result discover(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    const QString base = normBase(req.basePath);
    QStringList words = req.wordlist.isEmpty() ? defaultWordlist() : req.wordlist;
    if (req.maxRequests > 0 && words.size() > req.maxRequests)
        words = words.mid(0, req.maxRequests);

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto get = [&](const QString &fullPath) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildGet(req, fullPath));
    };
    auto bodyLen = [](const Proxy::HttpResponse &r) -> int {
        return std::min(static_cast<int>(r.body.size()), kMaxBody);
    };

    // 1) Calibrate the not-found baseline from two random, certainly-absent
    //    paths. If both agree we trust it; if they disagree (size-varying error
    //    page) we fall back to "anything that is not the random status".
    const auto c1 = get(base + "/" + randToken());
    if (!c1.ok) { result.error = "calibration failed: " + c1.errorMessage; return result; }
    const auto c2 = get(base + "/" + randToken() + "/" + randToken());
    const int s1 = c1.parsed.statusCode, s2 = c2.ok ? c2.parsed.statusCode : s1;
    const int l1 = bodyLen(c1.parsed), l2 = c2.ok ? bodyLen(c2.parsed) : l1;
    const bool stableSoft = (s1 == s2);
    result.softNotFoundStatus = stableSoft ? s1 : 0;
    result.softNotFoundSize = (l1 + l2) / 2;
    result.softNotFoundIs200 = stableSoft && s1 == 200;

    // Body-size deviation threshold for the 200-soft-404 case: a real page must
    // differ by more than the random-probe jitter (and a floor of 64 bytes).
    const int jitter = std::max(64, std::abs(l1 - l2) * 2);
    const int softLen = result.softNotFoundSize;

    auto interesting = [&](const Proxy::HttpResponse &resp) -> QString {
        const int st = resp.statusCode;
        // 3xx with a Location -> a real resource (often dir -> dir/).
        if (st == 301 || st == 302 || st == 307 || st == 308) {
            if (stableSoft && st == s1) return QString();   // server 3xx-soft-404s
            return QStringLiteral("redirect");
        }
        // Auth-gated -> the resource exists behind a control.
        if (st == 401 || st == 403) {
            if (stableSoft && st == s1) return QString();
            return QStringLiteral("auth-gated");
        }
        if (st == 200) {
            if (!result.softNotFoundIs200) return QStringLiteral("ok");  // baseline 404s
            // Soft-404 server: only a materially different body counts.
            if (std::abs(bodyLen(resp) - softLen) > jitter) return QStringLiteral("ok-distinct");
            return QString();
        }
        // Other 2xx (206/204 etc.) are worth noting if not the soft status.
        if (st >= 200 && st < 300 && !(stableSoft && st == s1))
            return QStringLiteral("ok");
        return QString();
    };

    for (const QString &w : words) {
        if (result.requestsSent >= req.maxRequests + 2) break;  // +2 calibration
        QString rel = w; while (rel.startsWith('/')) rel.remove(0, 1);
        if (rel.isEmpty()) continue;
        const auto r = get(base + "/" + rel);
        if (!r.ok) continue;
        const QString note = interesting(r.parsed);
        if (note.isEmpty()) continue;
        Hit hit;
        hit.path = base + "/" + rel;
        hit.status = r.parsed.statusCode;
        hit.size = bodyLen(r.parsed);
        hit.location = headerValue(r.parsed, "Location");
        hit.note = note;
        result.hits.append(hit);
    }
    return result;
}

} // namespace Nullock::Core::ContentDiscovery

#include "content_discovery.hpp"
#include "networking.hpp"

#include <QRandomGenerator>

#include <algorithm>
#include <climits>
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

// normBase(), classify() and forbiddenSaturated() are pure and live in
// content_logic.cpp so they can be unit-tested against Qt6::Core alone.

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
    result.wordsTotal = words.size();
    // maxRequests <= 0 means "no cap" -- normalise so the cap AND the loop budget
    // agree on it (previously 0 skipped the cap but made the loop break fire
    // immediately after calibration -> zero discovery).
    const int maxReq = req.maxRequests > 0 ? req.maxRequests : (INT_MAX - 2);
    if (words.size() > maxReq) { words = words.mid(0, maxReq); result.wordlistTruncated = true; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto get = [&](const QString &fullPath) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildGet(req, fullPath));
    };
    auto bodyLen = [](const Proxy::HttpResponse &r) -> int {
        return std::min(static_cast<int>(r.body.size()), kMaxBody);
    };

    // 1) Calibrate the not-found baseline from two random, certainly-absent paths
    //    AT THE SAME DEPTH as the real probes (a single segment under base).
    //    Probing different depths made a depth-routing server (hard-404 at one
    //    depth, catch-all 200 at another) look "unstable" and disabled every
    //    soft-404 suppression. A failed second probe leaves the baseline
    //    UNcorroborated, so it must not be trusted as reliable.
    const auto c1 = get(base + "/" + randToken());
    if (!c1.ok) { result.error = "calibration failed: " + c1.errorMessage; return result; }
    const auto c2 = get(base + "/" + randToken());

    CalibProfile cal;
    const int s1 = c1.parsed.statusCode;
    const int l1 = bodyLen(c1.parsed);
    cal.softStatuses.insert(s1);
    cal.softLocation = headerValue(c1.parsed, "Location");
    int l2 = l1;
    if (c2.ok) {
        const int s2 = c2.parsed.statusCode;
        cal.softStatuses.insert(s2);                 // both observed statuses are "soft"
        l2 = bodyLen(c2.parsed);
        cal.reliable = (s1 == s2);                   // corroborated only if they agree
        if (cal.softLocation.isEmpty()) cal.softLocation = headerValue(c2.parsed, "Location");
    }
    cal.softLen = (l1 + l2) / 2;
    cal.jitter  = std::max(64, std::abs(l1 - l2) * 2);

    result.calibrationReliable = cal.reliable;
    result.softNotFoundStatus  = cal.reliable ? s1 : 0;
    result.softNotFoundSize    = cal.softLen;
    result.softNotFoundIs200   = cal.reliable && cal.softStatuses.contains(200);

    for (const QString &w : words) {
        if (result.requestsSent >= maxReq + 2) break;  // +2 calibration
        QString rel = w; while (rel.startsWith('/')) rel.remove(0, 1);
        if (rel.isEmpty()) continue;
        ++result.wordsTried;
        const auto r = get(base + "/" + rel);
        if (!r.ok) continue;
        const QString note = classify(r.parsed.statusCode, bodyLen(r.parsed),
                                      headerValue(r.parsed, "Location"), cal);
        if (note.isEmpty()) continue;
        Hit hit;
        hit.path = base + "/" + rel;
        hit.status = r.parsed.statusCode;
        hit.size = bodyLen(r.parsed);
        hit.location = headerValue(r.parsed, "Location");
        hit.note = note;
        result.hits.append(hit);
    }

    // 2) WAF-saturation: a pattern-blocking WAF that passes the benign "nl404"
    //    calibration tokens yet 401/403s every attack-shaped wordlist path would
    //    otherwise emit one bogus "auth-gated" hit per path. If the forbidden
    //    fraction is high, collapse them into a single signal.
    auto isForbidden = [](const Hit &h) {
        return h.note == QLatin1String("auth-gated") && (h.status == 401 || h.status == 403);
    };
    int forbidden = 0;
    for (const Hit &h : result.hits) if (isForbidden(h)) ++forbidden;
    if (forbiddenSaturated(forbidden, result.wordsTried)) {
        result.forbiddenSaturated = true;
        QList<Hit> kept;
        for (const Hit &h : result.hits) if (!isForbidden(h)) kept.append(h);
        Hit agg;
        agg.path = base + "/*";
        agg.status = 403;
        agg.note = QStringLiteral("waf-saturated: %1 forbidden paths suppressed "
                                  "(likely WAF pattern-blocking, not real resources)").arg(forbidden);
        kept.append(agg);
        result.hits = kept;
    }
    return result;
}

} // namespace Nullock::Core::ContentDiscovery

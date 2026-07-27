// Pure (no-network) logic for the HTTP tech-fingerprint probe: the whole
// detection table (headers / cookies / body+meta markers) and the GET builder's
// CR/LF guards. Split out of http_fingerprint.cpp so Tests/http_fingerprint
// links Qt6::Core alone.
//
// DISCIPLINE: a CVE-bearing version (version + cveKind both set) is attached
// ONLY from a distinctive structural marker -- a generator meta tag, a product-
// specific path/header -- never from a bare product word + a whole-body version
// scan, which would CVE-correlate any page that merely mentions the product.

#include "http_fingerprint.hpp"

#include <QRegularExpression>
#include <QSet>

namespace Nullock::Core::HttpFingerprint {

namespace {
QString headerValue(const Headers &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}
QStringList allHeaderValues(const Headers &headers, const QString &name) {
    QStringList out;
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second;
    return out;
}
} // namespace

QList<Tech> detect(const Headers &headers, const QByteArray &bodyBytes) {
    constexpr int kMaxBody = 512 * 1024;
    const QString body = QString::fromUtf8(bodyBytes.left(kMaxBody));
    QList<Tech> tech;

    // Dedup by name, UPGRADE version/cveKind from a later, richer detection.
    auto add = [&](const QString &name, const QString &ver, const QString &src, const QString &kind) {
        for (auto &t : tech) {
            if (t.name.compare(name, Qt::CaseInsensitive) == 0) {
                if (t.version.isEmpty() && !ver.isEmpty()) { t.version = ver; t.source = src; }
                if (t.cveKind.isEmpty() && !kind.isEmpty()) t.cveKind = kind;
                return;
            }
        }
        tech.append({ name, ver, src, kind });
    };
    auto rx = [](const QString &p) {
        return QRegularExpression(p, QRegularExpression::CaseInsensitiveOption);
    };
    auto cap1 = [](const QRegularExpression &re, const QString &s) {
        const auto m = re.match(s); return m.hasMatch() ? m.captured(1) : QString();
    };

    // ---- headers ----
    const QString server = headerValue(headers, "Server");
    if (!server.isEmpty()) {
        QString v;
        if (!(v = cap1(rx("Apache/([0-9][0-9.]*)"), server)).isEmpty()) add("Apache", v, "header", "server-apache");
        else if (!(v = cap1(rx("nginx/([0-9][0-9.]*)"), server)).isEmpty()) add("nginx", v, "header", "server-nginx");
        else if (!(v = cap1(rx("Microsoft-IIS/([0-9][0-9.]*)"), server)).isEmpty()) add("IIS", v, "header", "server-iis");
        else if (server.contains("cloudflare", Qt::CaseInsensitive)) add("Cloudflare", "", "header", "");
        else add(server.section('/', 0, 0), cap1(rx("/([0-9][0-9.]*)"), server), "header", "");
    }
    const QString xpb = headerValue(headers, "X-Powered-By");
    if (!xpb.isEmpty()) {
        QString v;
        if (!(v = cap1(rx("PHP/([0-9][0-9.]*)"), xpb)).isEmpty()) add("PHP", v, "header", "lang-php");
        if (xpb.contains("ASP.NET", Qt::CaseInsensitive)) add("ASP.NET", cap1(rx("ASP\\.NET\\s*([0-9][0-9.]*)"), xpb), "header", "fw-aspnet");
        if (xpb.contains("Express", Qt::CaseInsensitive)) add("Express", "", "header", "");
        if (xpb.contains("Next.js", Qt::CaseInsensitive)) add("Next.js", "", "header", "fw-nextjs");
    }
    if (!headerValue(headers, "X-Drupal-Cache").isEmpty() || !headerValue(headers, "X-Generator").isEmpty()) {
        const QString gen = headerValue(headers, "X-Generator");
        if (gen.contains("Drupal", Qt::CaseInsensitive) || !headerValue(headers, "X-Drupal-Cache").isEmpty())
            add("Drupal", cap1(rx("Drupal\\s*([0-9][0-9.]*)"), gen), "header", "cms-drupal");
    }
    const QString aspVer = headerValue(headers, "X-AspNet-Version");
    if (!aspVer.isEmpty()) add("ASP.NET", aspVer, "header", "fw-aspnet");
    const QString jenkins = headerValue(headers, "X-Jenkins");
    if (!jenkins.isEmpty()) add("Jenkins", cap1(rx("([0-9][0-9.]*)"), jenkins), "header", "app-jenkins");

    // ---- cookies (collect names first so combo rules work) ----
    QSet<QString> cookieNames;
    for (const QString &sc : allHeaderValues(headers, "Set-Cookie"))
        cookieNames.insert(sc.section('=', 0, 0).trimmed().toLower());
    for (const QString &name : cookieNames) {
        if (name == "phpsessid")            add("PHP", "", "cookie", "lang-php");
        else if (name == "jsessionid")      add("Java", "", "cookie", "");
        else if (name.startsWith("laravel_") || name == "xsrf-token") add("Laravel", "", "cookie", "fw-laravel");
        else if (name.startsWith(".aspnet") || name.startsWith(".aspxauth")) add("ASP.NET", "", "cookie", "fw-aspnet");
        else if (name.startsWith("wordpress_") || name.startsWith("wp-")) add("WordPress", "", "cookie", "cms-wordpress");
        else if (name.startsWith("_session_id") || name.contains("rails")) add("Ruby on Rails", "", "cookie", "fw-rails");
    }
    // Django: "sessionid" alone is generic (used by many non-Django stacks), so
    // require BOTH of Django's default cookies together (mirrors passive_scanner).
    if (cookieNames.contains("csrftoken") && cookieNames.contains("sessionid"))
        add("Django", "", "cookie", "fw-django");

    // ---- body / meta ----
    QString v;
    if (!(v = cap1(rx("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\\s*([0-9][0-9.]*)"), body)).isEmpty())
        add("WordPress", v, "meta", "cms-wordpress");
    else if (body.contains("/wp-content/", Qt::CaseInsensitive) || body.contains("/wp-includes/", Qt::CaseInsensitive))
        add("WordPress", "", "body", "cms-wordpress");

    // Drupal: a CVE-bearing version comes ONLY from the generator meta (or the
    // X-Generator header above) -- NOT free body text, which would CVE-correlate
    // a page that merely quotes "Drupal 7.58". A /sites/ path is versionless
    // inventory.
    if (!(v = cap1(rx("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Drupal\\s*([0-9][0-9.]*)"), body)).isEmpty())
        add("Drupal", v, "meta", "cms-drupal");
    else if (body.contains("/sites/all/", Qt::CaseInsensitive) || body.contains("/sites/default/files", Qt::CaseInsensitive))
        add("Drupal", "", "body", "cms-drupal");

    // Joomla: same discipline -- version+CVE only from the generator meta; a
    // Joomla-specific path is versionless inventory; a bare "Joomla" word is NOT
    // a detection (it would CVE-correlate advisories/comparisons/changelogs).
    if (!(v = cap1(rx("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla!?\\s*([0-9][0-9.]*)"), body)).isEmpty())
        add("Joomla", v, "meta", "cms-joomla");
    else if (body.contains("/media/jui/", Qt::CaseInsensitive)
             || body.contains("/media/system/js/", Qt::CaseInsensitive)
             || rx("option=com_[a-z]").match(body).hasMatch())
        add("Joomla", "", "body", "cms-joomla");

    // ---- Atlassian Confluence / Jira ----
    QString ajs = cap1(rx("name=[\"']ajs-version-number[\"'][^>]*content=[\"']([0-9][0-9.]*)"), body);
    if (ajs.isEmpty())
        ajs = cap1(rx("content=[\"']([0-9][0-9.]*)[\"'][^>]*name=[\"']ajs-version-number[\"']"), body);
    if (!ajs.isEmpty()) {
        const bool confMarker = body.contains("confluence-base-url", Qt::CaseInsensitive)
                             || body.contains("confluence-context-path", Qt::CaseInsensitive)
                             || body.contains("com.atlassian.confluence", Qt::CaseInsensitive);
        const bool jiraMarker = body.contains("ajs-server-jira-version", Qt::CaseInsensitive)
                             || body.contains("com.atlassian.jira", Qt::CaseInsensitive)
                             || rx("application-name[\"']\\s+content=[\"']JIRA").match(body).hasMatch();
        if (confMarker)      add("Confluence", ajs, "meta", "cms-confluence");
        else if (jiraMarker) add("Jira", ajs, "meta", "cms-jira");
        else                 add("Atlassian", ajs, "meta", "");
    }

    if (!(v = cap1(rx("jquery[.\\-]?([0-9]+\\.[0-9][0-9.]*)(?:\\.min)?\\.js"), body)).isEmpty())
        add("jQuery", v, "body", "lib-jquery");
    if (!(v = cap1(rx("jquery-ui[.\\-]([0-9]+\\.[0-9][0-9.]*)(?:\\.custom)?(?:\\.min)?\\.(?:js|css)"), body)).isEmpty())
        add("jQuery UI", v, "body", "lib-jquery-ui");
    if (!(v = cap1(rx("bootstrap[.\\-]?([0-9]+\\.[0-9][0-9.]*)(?:\\.min)?\\.(?:js|css)"), body)).isEmpty())
        add("Bootstrap", v, "body", "lib-bootstrap");
    if (body.contains("__NEXT_DATA__")) add("Next.js", "", "body", "fw-nextjs");
    if (body.contains("ng-version", Qt::CaseInsensitive)) add("Angular", cap1(rx("ng-version=[\"']([0-9][0-9.]*)"), body), "body", "");
    if (body.contains("data-reactroot") || body.contains("react.production.min.js")) add("React", "", "body", "");
    if (body.contains("grafanaBootData"))
        add("Grafana", cap1(rx("buildInfo\"[\\s\\S]*?\"version\"\\s*:\\s*\"([0-9]+\\.[0-9][0-9.]*)\""), body),
            "body", "app-grafana");
    if (body.contains("You Know, for Search"))
        add("Elasticsearch", cap1(rx("\"number\"\\s*:\\s*\"([0-9]+\\.[0-9][0-9.]*)\""), body), "body", "app-elasticsearch");
    if (!headerValue(headers, "kbn-name").isEmpty())
        add("Kibana", cap1(rx("version\"[\\s\\S]*?\"number\"\\s*:\\s*\"([0-9]+\\.[0-9][0-9.]*)\""), body), "header", "app-kibana");
    if (body.contains("Apache Tomcat/")) {
        const QString tv = cap1(rx("Apache Tomcat/([0-9]+\\.[0-9][0-9.]*)"), body);
        if (!tv.isEmpty()) add("Apache Tomcat", tv, "body", "app-tomcat");
    }
    if (body.contains("adminer.org")) {
        const QString av = cap1(rx("Adminer\\s+([0-9]+\\.[0-9][0-9.]*)"), body);
        if (!av.isEmpty()) add("Adminer", av, "body", "app-adminer");
    }
    if (body.contains("data-v-app") || body.contains("/vue.runtime")) add("Vue.js", "", "body", "");

    return tech;
}

QByteArray buildGet(const Request &req) {
    if (req.host.contains('\r') || req.host.contains('\n')) return {};
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    if (target.contains('\r') || target.contains('\n')) return {};
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/fingerprint\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers on this body-less GET:
        //  - Accept-Encoding: line 178 forces "identity" so detect() scans a PLAINTEXT
        //    body; a surviving "gzip,.." lets the server compress (client never
        //    inflates) -> the whole tech-fingerprint / CVE-correlation table reports
        //    CLEAN (a WordPress/Apache/Grafana site and any CVE-bearing version missed).
        //  - Content-Length / Transfer-Encoding: a copied framing header on a bodyless
        //    GET strands the request (server waits for a body that never arrives) or
        //    desyncs the socket, so the fingerprint response never parses.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::HttpFingerprint

#include "http_fingerprint.hpp"
#include "networking.hpp"

#include <QRegularExpression>

namespace Nullock::Core::HttpFingerprint {

namespace {

constexpr int kMaxBody = 512 * 1024;

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}
QStringList allHeaderValues(const Proxy::HttpResponse &r, const QString &name) {
    QStringList out;
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second;
    return out;
}

QByteArray buildGet(const Request &req) {
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/fingerprint\r\n";
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

Result fingerprint(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = "request failed: " + r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    const QString body = QString::fromUtf8(r.parsed.body.left(kMaxBody));

    // Dedup by name, but UPGRADE: if a later detection carries a version the
    // first one lacked (e.g. cookie finds "WordPress", meta finds "WordPress
    // 5.8.1"), adopt the version so CVE correlation can fire.
    auto add = [&](const QString &name, const QString &ver, const QString &src, const QString &kind) {
        for (auto &t : result.tech) {
            if (t.name.compare(name, Qt::CaseInsensitive) == 0) {
                if (t.version.isEmpty() && !ver.isEmpty()) { t.version = ver; t.source = src; }
                if (t.cveKind.isEmpty() && !kind.isEmpty()) t.cveKind = kind;
                return;
            }
        }
        result.tech.append({ name, ver, src, kind });
    };
    auto rx = [](const QString &p) {
        return QRegularExpression(p, QRegularExpression::CaseInsensitiveOption);
    };
    auto cap1 = [](const QRegularExpression &re, const QString &s) {
        const auto m = re.match(s); return m.hasMatch() ? m.captured(1) : QString();
    };

    // ---- headers ----
    const QString server = headerValue(r.parsed, "Server");
    if (!server.isEmpty()) {
        QString v;
        if (!(v = cap1(rx("Apache/([0-9][0-9.]*)"), server)).isEmpty()) add("Apache", v, "header", "server-apache");
        else if (!(v = cap1(rx("nginx/([0-9][0-9.]*)"), server)).isEmpty()) add("nginx", v, "header", "server-nginx");
        else if (!(v = cap1(rx("Microsoft-IIS/([0-9][0-9.]*)"), server)).isEmpty()) add("IIS", v, "header", "server-iis");
        else if (server.contains("cloudflare", Qt::CaseInsensitive)) add("Cloudflare", "", "header", "");
        else add(server.section('/', 0, 0), cap1(rx("/([0-9][0-9.]*)"), server), "header", "");
    }
    const QString xpb = headerValue(r.parsed, "X-Powered-By");
    if (!xpb.isEmpty()) {
        QString v;
        if (!(v = cap1(rx("PHP/([0-9][0-9.]*)"), xpb)).isEmpty()) add("PHP", v, "header", "lang-php");
        if (xpb.contains("ASP.NET", Qt::CaseInsensitive)) add("ASP.NET", cap1(rx("ASP\\.NET\\s*([0-9][0-9.]*)"), xpb), "header", "fw-aspnet");
        if (xpb.contains("Express", Qt::CaseInsensitive)) add("Express", "", "header", "");
        if (xpb.contains("Next.js", Qt::CaseInsensitive)) add("Next.js", "", "header", "fw-nextjs");
    }
    if (!headerValue(r.parsed, "X-Drupal-Cache").isEmpty() || !headerValue(r.parsed, "X-Generator").isEmpty()) {
        const QString gen = headerValue(r.parsed, "X-Generator");
        if (gen.contains("Drupal", Qt::CaseInsensitive) || !headerValue(r.parsed, "X-Drupal-Cache").isEmpty())
            add("Drupal", cap1(rx("Drupal\\s*([0-9][0-9.]*)"), gen), "header", "cms-drupal");
    }
    const QString aspVer = headerValue(r.parsed, "X-AspNet-Version");
    if (!aspVer.isEmpty()) add("ASP.NET", aspVer, "header", "fw-aspnet");
    // Jenkins puts its exact build in the X-Jenkins response header on every
    // page -- a clean, reliable version signal for CVE correlation.
    const QString jenkins = headerValue(r.parsed, "X-Jenkins");
    if (!jenkins.isEmpty()) add("Jenkins", cap1(rx("([0-9][0-9.]*)"), jenkins), "header", "app-jenkins");

    // ---- cookies ----
    for (const QString &sc : allHeaderValues(r.parsed, "Set-Cookie")) {
        const QString name = sc.section('=', 0, 0).trimmed().toLower();
        if (name == "phpsessid")            add("PHP", "", "cookie", "lang-php");
        else if (name == "jsessionid")      add("Java", "", "cookie", "");
        else if (name.startsWith("laravel_") || name == "xsrf-token") add("Laravel", "", "cookie", "fw-laravel");
        else if (name.startsWith(".aspnet") || name.startsWith(".aspxauth")) add("ASP.NET", "", "cookie", "fw-aspnet");
        else if (name.startsWith("wordpress_") || name.startsWith("wp-")) add("WordPress", "", "cookie", "cms-wordpress");
        else if (name == "csrftoken" || name == "sessionid") add("Django", "", "cookie", "fw-django");
        else if (name.startsWith("_session_id") || name.contains("rails")) add("Ruby on Rails", "", "cookie", "fw-rails");
    }

    // ---- body / meta ----
    QString v;
    if (!(v = cap1(rx("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\\s*([0-9][0-9.]*)"), body)).isEmpty())
        add("WordPress", v, "meta", "cms-wordpress");
    else if (body.contains("/wp-content/", Qt::CaseInsensitive) || body.contains("/wp-includes/", Qt::CaseInsensitive))
        add("WordPress", "", "body", "cms-wordpress");
    if (!(v = cap1(rx("Drupal\\s*([0-9][0-9.]*)"), body)).isEmpty()) add("Drupal", v, "body", "cms-drupal");
    else if (body.contains("/sites/all/", Qt::CaseInsensitive) || body.contains("/sites/default/files", Qt::CaseInsensitive))
        add("Drupal", "", "body", "cms-drupal");
    if (body.contains("Joomla", Qt::CaseInsensitive)) add("Joomla", cap1(rx("Joomla!?\\s*([0-9][0-9.]*)"), body), "body", "cms-joomla");
    // ---- Atlassian Confluence / Jira -------------------------------------
    // Atlassian products expose their exact build through the
    // <meta name="ajs-version-number" content="X.Y.Z"> tag. The product is
    // told apart by product-specific markers so the version can be
    // CVE-correlated (this is what makes the cms-confluence / cms-jira CVE
    // entries reachable).
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
        // Attach a product-specific cveKind ONLY on a reliable structural
        // marker. A bare "confluence"/"jira" word elsewhere on the page (e.g.
        // a footer link to confluence.atlassian.com on a Jira UI) would
        // cross-label the product and misattribute its CVEs, so when the
        // product is ambiguous we record the version under "Atlassian" with
        // no kind (it shows in inventory but correlates no CVEs).
        if (confMarker)      add("Confluence", ajs, "meta", "cms-confluence");
        else if (jiraMarker) add("Jira", ajs, "meta", "cms-jira");
        else                 add("Atlassian", ajs, "meta", "");
    }
    if (!(v = cap1(rx("jquery[.\\-]?([0-9]+\\.[0-9][0-9.]*)(?:\\.min)?\\.js"), body)).isEmpty())
        add("jQuery", v, "body", "lib-jquery");
    if (!(v = cap1(rx("bootstrap[.\\-]?([0-9]+\\.[0-9][0-9.]*)(?:\\.min)?\\.(?:js|css)"), body)).isEmpty())
        add("Bootstrap", v, "body", "");
    if (body.contains("__NEXT_DATA__")) add("Next.js", "", "body", "fw-nextjs");
    if (body.contains("ng-version", Qt::CaseInsensitive)) add("Angular", cap1(rx("ng-version=[\"']([0-9][0-9.]*)"), body), "body", "");
    if (body.contains("data-reactroot") || body.contains("react.production.min.js")) add("React", "", "body", "");
    if (body.contains("data-v-app") || body.contains("/vue.runtime")) add("Vue.js", "", "body", "");

    return result;
}

} // namespace Nullock::Core::HttpFingerprint

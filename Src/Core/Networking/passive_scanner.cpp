#include "passive_scanner.hpp"

#include <QDateTime>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QStringList>
#include <QUrl>

namespace Nullock::Core {

namespace {

// Tokens/keys that show up in URL query strings are almost always a
// mistake -- they end up in proxy logs, referer headers, and browser
// history. Substring match against lowercased parameter names.
const QStringList kSensitiveQueryKeys = {
    "token", "access_token", "id_token", "auth", "authorization",
    "api_key", "apikey", "key", "secret", "password", "passwd",
    "session", "sid", "sessionid", "jwt", "code",
};

constexpr int kCap = 1000;

bool isHtmlResponse(const QString &contentType) {
    return contentType.contains("text/html",          Qt::CaseInsensitive)
        || contentType.contains("application/xhtml",  Qt::CaseInsensitive);
}

} // namespace

PassiveScanner::PassiveScanner(QObject *parent) : QObject(parent) {}

int PassiveScanner::count() const {
    QMutexLocker lock(&m_mutex);
    return m_findings.size();
}

QList<Finding> PassiveScanner::findings(int limit) const {
    QMutexLocker lock(&m_mutex);
    if (limit >= m_findings.size()) return m_findings;
    // Return the newest-first slice so the UI list is interesting at the
    // top without sorting client-side.
    QList<Finding> out;
    out.reserve(limit);
    for (int i = m_findings.size() - 1; i >= 0 && out.size() < limit; --i)
        out.append(m_findings[i]);
    return out;
}

void PassiveScanner::setNextRowId(int n) {
    QMutexLocker lock(&m_mutex);
    m_nextRowId = n;
}

void PassiveScanner::clear() {
    {
        QMutexLocker lock(&m_mutex);
        m_findings.clear();
        m_nextId = 1;
    }
    emit findingsChanged();
}

void PassiveScanner::reportFinding(int rowId,
                                   const QString &severity,
                                   const QString &kind,
                                   const QString &summary,
                                   const QString &evidence,
                                   const QString &host,
                                   const QString &url) {
    Finding f;
    {
        QMutexLocker lock(&m_mutex);
        f.id    = m_nextId++;
        f.rowId = rowId;
    }
    f.ts       = QDateTime::currentDateTime();
    f.severity = severity;
    f.kind     = kind;
    f.summary  = summary;
    f.evidence = evidence;
    f.host     = host;
    f.url      = url;
    {
        QMutexLocker lock(&m_mutex);
        m_findings.append(f);
        if (m_findings.size() > 1000) m_findings.removeFirst();
    }
    emit findingsChanged();
}

QString PassiveScanner::headerOf(const QList<QPair<QString, QString>> &headers,
                                 const QString &name) const {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QList<QString> PassiveScanner::allHeaderValues(
        const QList<QPair<QString, QString>> &headers,
        const QString &name) const {
    QList<QString> out;
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out.append(h.second);
    return out;
}

void PassiveScanner::onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                                        const Nullock::Proxy::HttpResponse &resp) {
    // We only audit "normal" HTTP responses, not the synthetic WS frame
    // entries the proxy emits.
    if (req.method.startsWith("WS")) return;
    // Each call to responseReceived corresponds to one history row. We
    // claim the row id here -- shared across every finding emitted while
    // this response is being checked.
    int rowId = 0;
    {
        QMutexLocker lock(&m_mutex);
        rowId = m_nextRowId++;
    }
    checkResponse(rowId, req, resp);
}

void PassiveScanner::addFinding(int rowId,
                                const Nullock::Proxy::HttpRequest &req,
                                const Nullock::Proxy::HttpResponse &resp,
                                const QString &severity,
                                const QString &kind,
                                const QString &summary,
                                const QString &evidence) {
    Finding f;
    {
        QMutexLocker lock(&m_mutex);
        f.id       = m_nextId++;
        f.rowId    = rowId;
    }
    f.ts       = QDateTime::currentDateTime();
    f.severity = severity;
    f.kind     = kind;
    f.summary  = summary;
    f.evidence = evidence;
    f.host     = req.host;
    QString proto = resp.wasTls ? "https" : "http";
    QString port  = (req.port == 80 || req.port == 443)
                    ? QString() : ":" + QString::number(req.port);
    f.url      = proto + "://" + req.host + port + (req.path.startsWith('/')
                                                    ? req.path
                                                    : "/" + req.path);
    bool over = false;
    {
        QMutexLocker lock(&m_mutex);
        m_findings.append(f);
        over = (m_findings.size() > kCap);
        if (over) m_findings.removeFirst();
    }
    emit findingsChanged();
}

void PassiveScanner::checkResponse(int rowId,
                                   const Nullock::Proxy::HttpRequest &req,
                                   const Nullock::Proxy::HttpResponse &resp) {
    // Only audit HTML pages for the missing-header set -- application/json
    // / images / etc don't need a CSP. The cookie checks fire regardless.
    const QString contentType = headerOf(resp.headers, "Content-Type");
    const bool html = isHtmlResponse(contentType);

    // Protocol-level fingerprinting. Flag gRPC and GraphQL endpoints
    // so the user can immediately see them in the findings panel and
    // use the right decoder (grpc-frame / graphql-parse).
    if (contentType.contains("application/grpc", Qt::CaseInsensitive)) {
        addFinding(rowId, req, resp, "info", "protocol-grpc",
                   "gRPC endpoint detected",
                   "content-type=" + contentType
                   + "; use grpc-frame decoder + check for grpc-status in trailers");
    } else if (req.path == "/graphql" || req.path.endsWith("/graphql")
               || contentType.contains("application/graphql", Qt::CaseInsensitive)) {
        QString detail = "path looks GraphQL-shaped";
        // Cheap introspection sniff -- if the response body contains
        // "__schema" or "__typename" the endpoint allowed introspection.
        if (QString::fromUtf8(resp.body.left(8 * 1024))
                .contains("__schema", Qt::CaseInsensitive)) {
            detail = "introspection ENABLED -- production servers usually disable";
            addFinding(rowId, req, resp, "low", "graphql-introspection",
                       "GraphQL introspection exposed", detail);
        } else {
            addFinding(rowId, req, resp, "info", "protocol-graphql",
                       "GraphQL endpoint detected", detail);
        }
    }

    if (html && resp.statusCode >= 200 && resp.statusCode < 400) {
        struct Rule {
            const char *header;
            const char *kind;
            const char *summary;
            const char *severity;
        };
        const Rule rules[] = {
            { "Content-Security-Policy", "missing-csp",
              "No Content-Security-Policy header",                "medium" },
            { "Strict-Transport-Security", "missing-hsts",
              "No Strict-Transport-Security header on TLS resp",  "medium" },
            { "X-Frame-Options", "missing-xfo",
              "No X-Frame-Options header (clickjacking risk)",    "low" },
            { "X-Content-Type-Options", "missing-xcto",
              "No X-Content-Type-Options: nosniff",               "low" },
            { "Referrer-Policy", "missing-rp",
              "No Referrer-Policy header",                        "info" },
        };
        for (const auto &r : rules) {
            const QString v = headerOf(resp.headers, r.header);
            if (v.isEmpty()) {
                // HSTS only matters on TLS responses.
                if (QString::fromLatin1(r.kind) == "missing-hsts" && !resp.wasTls) continue;
                addFinding(rowId, req, resp, r.severity, r.kind, r.summary,
                           QString("absent on %1").arg(req.host));
            }
        }
    }

    // Set-Cookie hardening flags. Most servers set the cookie multiple
    // times in one response (auth + csrf + lang) so walk every one.
    for (const QString &cookie : allHeaderValues(resp.headers, "Set-Cookie")) {
        const QString lc = cookie.toLower();
        const QString name = cookie.section('=', 0, 0).trimmed();
        if (!lc.contains("httponly"))
            addFinding(rowId, req, resp, "low", "cookie-no-httponly",
                       "Cookie set without HttpOnly: " + name,
                       cookie.left(240));
        if (resp.wasTls && !lc.contains("secure"))
            addFinding(rowId, req, resp, "low", "cookie-no-secure",
                       "Cookie set on TLS without Secure: " + name,
                       cookie.left(240));
        if (!lc.contains("samesite"))
            addFinding(rowId, req, resp, "info", "cookie-no-samesite",
                       "Cookie set without SameSite: " + name,
                       cookie.left(240));
    }

    // Server header version leak. The bare product name is normally
    // fine; "Apache/2.4.41 (Ubuntu)" is information disclosure.
    const QString server = headerOf(resp.headers, "Server");
    if (server.contains(QChar('/')) && server.contains(QRegularExpression("\\d"))) {
        addFinding(rowId, req, resp, "low", "server-version-leak",
                   "Server header leaks software version",
                   "Server: " + server);
    }
    const QString xpb = headerOf(resp.headers, "X-Powered-By");
    if (!xpb.isEmpty()) {
        addFinding(rowId, req, resp, "info", "x-powered-by",
                   "X-Powered-By header discloses stack",
                   "X-Powered-By: " + xpb);
    }

    // CORS misconfig: ACAO: * with credentials is the dangerous shape,
    // but plain "*" is still surfaced as info since it's often wrong.
    const QString acao = headerOf(resp.headers, "Access-Control-Allow-Origin");
    const QString acac = headerOf(resp.headers, "Access-Control-Allow-Credentials");
    if (acao == "*" && acac.compare("true", Qt::CaseInsensitive) == 0) {
        addFinding(rowId, req, resp, "high", "cors-wildcard-creds",
                   "ACAO: * with Allow-Credentials: true (browsers reject "
                   "but the intent is dangerous)",
                   "ACAO: " + acao + " · ACAC: " + acac);
    } else if (acao == "*") {
        addFinding(rowId, req, resp, "info", "cors-wildcard",
                   "Access-Control-Allow-Origin: *",
                   "ACAO: *");
    }

    // Sensitive token in URL query string. Picks up GETs that leak
    // bearer-style auth.
    const int qmark = req.path.indexOf('?');
    if (qmark >= 0) {
        const QString query = req.path.mid(qmark + 1);
        const QStringList parts = query.split('&', Qt::SkipEmptyParts);
        for (const QString &p : parts) {
            const QString key = p.section('=', 0, 0).toLower();
            for (const QString &sk : kSensitiveQueryKeys) {
                if (key == sk || key.contains(sk)) {
                    addFinding(rowId, req, resp, "medium", "secret-in-url",
                               "Sensitive parameter in URL query: " + key,
                               p.left(240));
                    break;
                }
            }
        }
    }

    // Bearer / Authorization on a non-TLS connection.
    if (!resp.wasTls) {
        const QString authz = headerOf(req.headers, "Authorization");
        if (!authz.isEmpty()) {
            addFinding(rowId, req, resp, "high", "auth-over-http",
                       "Authorization header sent over plaintext HTTP",
                       "Authorization: " + authz.left(80) + (authz.size() > 80 ? "..." : ""));
        }
    }

    // ====================================================================
    // Extended detector library. Each block is independent; comment out
    // any individual block to disable that detector without affecting
    // others. Severity scoring follows OWASP risk matrix conventions.
    // ====================================================================

    // ---- CSP granular analysis -------------------------------------------
    // A present CSP can still be useless. Walk the value, flag the common
    // weaknesses individually so the user can patch them piecewise.
    const QString csp = headerOf(resp.headers, "Content-Security-Policy");
    if (!csp.isEmpty()) {
        const QString cspLow = csp.toLower();
        if (cspLow.contains("'unsafe-inline'")) {
            addFinding(rowId, req, resp, "medium", "csp-unsafe-inline",
                       "CSP allows 'unsafe-inline' (XSS via injected script tags)",
                       "directive contains 'unsafe-inline'");
        }
        if (cspLow.contains("'unsafe-eval'")) {
            addFinding(rowId, req, resp, "medium", "csp-unsafe-eval",
                       "CSP allows 'unsafe-eval' (eval / new Function permitted)",
                       "directive contains 'unsafe-eval'");
        }
        // Wildcard outside report-uri / hash sources is suspicious.
        if (cspLow.contains(" * ") || cspLow.contains(" *;") || cspLow.endsWith("*")) {
            addFinding(rowId, req, resp, "medium", "csp-wildcard-src",
                       "CSP includes a wildcard '*' source",
                       "see Content-Security-Policy header");
        }
        if (!cspLow.contains("frame-ancestors")) {
            addFinding(rowId, req, resp, "low", "csp-no-frame-ancestors",
                       "CSP missing frame-ancestors (clickjacking via iframe still possible)",
                       "frame-ancestors directive absent");
        }
        if (!cspLow.contains("form-action")) {
            addFinding(rowId, req, resp, "info", "csp-no-form-action",
                       "CSP missing form-action (form submission to attacker.example permitted)",
                       "form-action directive absent");
        }
        if (!cspLow.contains("base-uri")) {
            addFinding(rowId, req, resp, "info", "csp-no-base-uri",
                       "CSP missing base-uri (<base> injection can change all relative URLs)",
                       "base-uri directive absent");
        }
        // report-only without enforcement does nothing for users.
        const QString cspRO = headerOf(resp.headers, "Content-Security-Policy-Report-Only");
        if (!cspRO.isEmpty() && csp.isEmpty()) {
            addFinding(rowId, req, resp, "info", "csp-report-only",
                       "Only CSP-Report-Only is set; nothing is enforced",
                       "Content-Security-Policy header absent");
        }
    }

    // ---- HSTS strength ---------------------------------------------------
    // The presence-only check happens above. If it's present, look at
    // strength: max-age (>= 1 year), includeSubDomains, preload.
    const QString hsts = headerOf(resp.headers, "Strict-Transport-Security");
    if (resp.wasTls && !hsts.isEmpty()) {
        static const QRegularExpression rxAge(R"(max-age\s*=\s*(\d+))",
                                              QRegularExpression::CaseInsensitiveOption);
        const auto mAge = rxAge.match(hsts);
        if (mAge.hasMatch()) {
            const qint64 secs = mAge.captured(1).toLongLong();
            if (secs < 31536000) {  // 1 year
                addFinding(rowId, req, resp, "low", "hsts-short-max-age",
                           "HSTS max-age is < 1 year (" + QString::number(secs) + "s)",
                           "Strict-Transport-Security: " + hsts);
            }
        }
        if (!hsts.toLower().contains("includesubdomains")) {
            addFinding(rowId, req, resp, "low", "hsts-no-subdomains",
                       "HSTS missing includeSubDomains (subdomains can still be MITM'd)",
                       "Strict-Transport-Security: " + hsts);
        }
        if (!hsts.toLower().contains("preload")) {
            addFinding(rowId, req, resp, "info", "hsts-no-preload",
                       "HSTS missing preload (first-time visitors aren't protected)",
                       "Strict-Transport-Security: " + hsts);
        }
    }

    // ---- Missing modern isolation headers --------------------------------
    if (html && resp.statusCode >= 200 && resp.statusCode < 400) {
        if (headerOf(resp.headers, "Permissions-Policy").isEmpty()
            && headerOf(resp.headers, "Feature-Policy").isEmpty()) {
            addFinding(rowId, req, resp, "info", "missing-permissions-policy",
                       "No Permissions-Policy header (browser features unrestricted)",
                       "neither Permissions-Policy nor legacy Feature-Policy present");
        }
        if (headerOf(resp.headers, "Cross-Origin-Opener-Policy").isEmpty()) {
            addFinding(rowId, req, resp, "info", "missing-coop",
                       "No Cross-Origin-Opener-Policy (cross-origin window references possible)",
                       "COOP header absent");
        }
        if (headerOf(resp.headers, "Cross-Origin-Embedder-Policy").isEmpty()) {
            addFinding(rowId, req, resp, "info", "missing-coep",
                       "No Cross-Origin-Embedder-Policy (Spectre-class isolation absent)",
                       "COEP header absent");
        }
        if (headerOf(resp.headers, "Cross-Origin-Resource-Policy").isEmpty()) {
            addFinding(rowId, req, resp, "info", "missing-corp",
                       "No Cross-Origin-Resource-Policy (response readable cross-origin)",
                       "CORP header absent");
        }
    }

    // ---- Cache-Control on authenticated responses ------------------------
    // Auth-bearing or cookie-setting responses MUST NOT be cached by
    // shared proxies. Common screw-up: a CDN caches a personalized page.
    const bool hasAuth = !headerOf(req.headers, "Authorization").isEmpty()
                      || !headerOf(req.headers, "Cookie").isEmpty();
    const bool setsCookie = !headerOf(resp.headers, "Set-Cookie").isEmpty();
    if ((hasAuth || setsCookie) && resp.statusCode == 200) {
        const QString cc = headerOf(resp.headers, "Cache-Control").toLower();
        if (!cc.contains("private") && !cc.contains("no-store")
            && !cc.contains("no-cache")) {
            addFinding(rowId, req, resp, "medium", "auth-no-cache-control",
                       "Authenticated response cacheable by shared proxies",
                       "Cache-Control: " + (cc.isEmpty() ? "(absent)" : cc));
        }
    }

    // ---- Cookie hardening v2: prefixes + scope ---------------------------
    for (const QString &cookie : allHeaderValues(resp.headers, "Set-Cookie")) {
        const QString lc = cookie.toLower();
        const QString name = cookie.section('=', 0, 0).trimmed();
        // __Secure- prefix requires Secure.
        if (name.startsWith("__Secure-", Qt::CaseInsensitive) && !lc.contains("secure")) {
            addFinding(rowId, req, resp, "medium", "cookie-secure-prefix-violation",
                       "__Secure- prefixed cookie set without Secure flag",
                       cookie.left(240));
        }
        // __Host- prefix requires Secure, Path=/, no Domain.
        if (name.startsWith("__Host-", Qt::CaseInsensitive)) {
            const bool hasDomain = lc.contains("domain=");
            const bool hasSecure = lc.contains("secure");
            const bool pathRoot = lc.contains("path=/") && !lc.contains("path=/;path=/"
                                                                        );
            if (hasDomain || !hasSecure || !pathRoot) {
                addFinding(rowId, req, resp, "medium", "cookie-host-prefix-violation",
                           "__Host- prefixed cookie missing Secure / Path=/ or has Domain",
                           cookie.left(240));
            }
        }
        // Path=/ + no SameSite gives the cookie max blast radius.
        if (lc.contains("path=/") && !lc.contains("samesite")) {
            addFinding(rowId, req, resp, "info", "cookie-broad-path-no-samesite",
                       "Cookie with Path=/ and no SameSite: scoped to whole origin",
                       cookie.left(240));
        }
    }

    // ---- ETag predictability --------------------------------------------
    // Weak ETags (W/"...") are fine; strong incrementing integer ETags
    // are an information disclosure (database row id, file inode).
    const QString etag = headerOf(resp.headers, "ETag");
    if (!etag.isEmpty() && !etag.startsWith("W/")) {
        static const QRegularExpression rxIntEtag("^\"(\\d{1,10})\"$");
        if (rxIntEtag.match(etag.trimmed()).hasMatch()) {
            addFinding(rowId, req, resp, "info", "etag-predictable",
                       "ETag is a small integer (likely DB row id / inode)",
                       "ETag: " + etag);
        }
    }

    // ---- Mixed content on HTTPS pages -----------------------------------
    if (html && resp.wasTls) {
        const QString bodyText = QString::fromUtf8(resp.body.left(256 * 1024));
        // src="http://..." or href="http://..." without the s
        static const QRegularExpression rxMixed(
            R"#((?:src|href|action)\s*=\s*['"]http://[^'"\s]+['"])#",
            QRegularExpression::CaseInsensitiveOption);
        auto it = rxMixed.globalMatch(bodyText);
        int hits = 0;
        QString firstHit;
        while (it.hasNext() && hits < 5) {
            const auto m = it.next();
            if (firstHit.isEmpty()) firstHit = m.captured().left(160);
            ++hits;
        }
        if (hits > 0) {
            addFinding(rowId, req, resp, "low", "mixed-content",
                       QString("HTTPS page references %1 plain-HTTP resource(s)").arg(hits),
                       "first occurrence: " + firstHit);
        }
    }

    // ---- Source map exposure --------------------------------------------
    // Production JS shipping with sourcemaps leaks original symbols, file
    // names, and often comments + local paths.
    if (contentType.contains("javascript", Qt::CaseInsensitive)
        || contentType.contains("application/json", Qt::CaseInsensitive)
        || req.path.endsWith(".js") || req.path.endsWith(".mjs")) {
        const QString bodyText = QString::fromUtf8(resp.body.right(2048));
        static const QRegularExpression rxSourceMap(
            R"#(//[#@]\s*sourceMappingURL\s*=\s*([^\s\r\n]+))#",
            QRegularExpression::CaseInsensitiveOption);
        const auto mSM = rxSourceMap.match(bodyText);
        if (mSM.hasMatch()) {
            addFinding(rowId, req, resp, "low", "source-map-exposed",
                       "Production JS references a source map",
                       "sourceMappingURL=" + mSM.captured(1).left(200));
        }
    }

    // ---- API key / secret patterns in any response body -----------------
    // These regex patterns catch the most common providers' tokens. Each
    // match is treated as high severity because leaked keys = direct compromise.
    if (resp.statusCode == 200 && resp.body.size() < 4 * 1024 * 1024) {
        const QString body = QString::fromUtf8(resp.body.left(4 * 1024 * 1024));
        struct SecretPattern {
            const char *kind;
            const char *label;
            QRegularExpression rx;
        };
        static const SecretPattern kSecretPatterns[] = {
            { "leaked-aws-key", "AWS Access Key ID",
              QRegularExpression(R"(\bAKIA[0-9A-Z]{16}\b)") },
            { "leaked-aws-secret", "AWS Secret Access Key",
              QRegularExpression(R"(\b[A-Za-z0-9/+=]{40}\b)",
                                 QRegularExpression::NoPatternOption) },
            { "leaked-gh-token", "GitHub Personal Access Token",
              QRegularExpression(R"(\bghp_[A-Za-z0-9]{36}\b)") },
            { "leaked-gh-app", "GitHub App Token",
              QRegularExpression(R"(\bghs_[A-Za-z0-9]{36}\b)") },
            { "leaked-slack", "Slack Bot Token",
              QRegularExpression(R"(\bxox[abprs]-[A-Za-z0-9-]{10,}\b)") },
            { "leaked-stripe", "Stripe Secret/Live Key",
              QRegularExpression(R"(\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b)") },
            { "leaked-sendgrid", "SendGrid API Key",
              QRegularExpression(R"(\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b)") },
            { "leaked-mapbox", "Mapbox token",
              QRegularExpression(R"(\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b)") },
            { "leaked-google-api", "Google API Key",
              QRegularExpression(R"(\bAIza[0-9A-Za-z_-]{35}\b)") },
            { "leaked-private-key", "PEM private key block",
              QRegularExpression(R"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)") },
        };
        for (const auto &p : kSecretPatterns) {
            const auto m = p.rx.match(body);
            if (!m.hasMatch()) continue;
            // AWS Secret pattern (40 b64 chars) has too many false positives
            // standing alone -- require an "aws" / "secret" / "key" context
            // word within 80 chars.
            if (QString::fromLatin1(p.kind) == "leaked-aws-secret") {
                const int start = qMax(0, m.capturedStart() - 80);
                const QString ctx = body.mid(start, 160).toLower();
                if (!ctx.contains("aws") && !ctx.contains("secret")
                    && !ctx.contains("access")) continue;
            }
            addFinding(rowId, req, resp, "high", p.kind,
                       QString("%1 found in response body").arg(p.label),
                       "match: " + m.captured().left(60) + "...");
        }
    }

    // ---- Stack-trace fragments -----------------------------------------
    // A 500-class response leaking internal stack lines tells the attacker
    // which framework + line numbers to target.
    if (resp.statusCode >= 500 && resp.body.size() < 1 * 1024 * 1024) {
        const QString body = QString::fromUtf8(resp.body.left(64 * 1024));
        struct Trace {
            const char *kind;
            const char *needle;
        };
        static const Trace kTraces[] = {
            { "stack-python",  "Traceback (most recent call last)" },
            { "stack-java",    "java.lang." },
            { "stack-dotnet",  "at System." },
            { "stack-php",     "Stack trace:" },
            { "stack-ruby",    "from /usr/lib/ruby" },
            { "stack-node",    "at Object." },
            { "stack-rails",   "ActionController::" },
            { "stack-django",  "Django tried these URL patterns" },
            { "stack-spring",  "org.springframework" },
        };
        for (const auto &t : kTraces) {
            if (body.contains(QString::fromLatin1(t.needle), Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp, "medium", t.kind,
                           QString("Server error response leaks %1 stack trace")
                               .arg(QString::fromLatin1(t.kind).mid(6)),
                           QString::fromLatin1(t.needle));
                break;  // one stack-trace finding per row is enough
            }
        }
    }

    // ---- Exposed dev / VCS files ---------------------------------------
    // .git/HEAD, .env, /admin/, etc. -- the perennial easy bug-bounty pull.
    if (resp.statusCode == 200) {
        static const QStringList kExposedPaths = {
            "/.git/", "/.svn/", "/.hg/", "/.env",
            "/.DS_Store", "/.htaccess", "/.htpasswd",
            "/web.config", "/composer.json", "/composer.lock",
            "/package.json", "/yarn.lock", "/Gemfile",
            "/wp-config.php", "/config.yml", "/config.yaml",
            "/database.yml", "/credentials.yml",
            "/backup.zip", "/backup.tar", "/backup.sql",
            "/dump.sql", "/.bak", "/phpinfo.php",
        };
        for (const QString &p : kExposedPaths) {
            if (req.path.contains(p, Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp, "high", "exposed-dev-file",
                           "Sensitive dev / VCS file accessible (" + p + ")",
                           "path: " + req.path);
                break;
            }
        }
    }

    // ---- TRACE / debug methods accepted --------------------------------
    if ((req.method.compare("TRACE", Qt::CaseInsensitive) == 0
         || req.method.compare("CONNECT", Qt::CaseInsensitive) == 0
         || req.method.compare("PROPFIND", Qt::CaseInsensitive) == 0)
        && resp.statusCode >= 200 && resp.statusCode < 300) {
        addFinding(rowId, req, resp, "medium", "debug-method-allowed",
                   "Server accepts " + req.method.toUpper() + " method",
                   "response " + QString::number(resp.statusCode));
    }

    // ---- Internal hostname / private IP exposure ------------------------
    if (html && resp.body.size() < 2 * 1024 * 1024) {
        const QString body = QString::fromUtf8(resp.body.left(2 * 1024 * 1024));
        static const QRegularExpression rxPrivIP(
            R"(\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
        const auto mIP = rxPrivIP.match(body);
        if (mIP.hasMatch()) {
            addFinding(rowId, req, resp, "info", "internal-ip-leak",
                       "RFC 1918 private IP referenced in response",
                       "first match: " + mIP.captured());
        }
        static const QRegularExpression rxInternalTld(
            R"(\b[a-zA-Z0-9-]+\.(?:local|internal|corp|intranet|lan)\b)");
        const auto mTld = rxInternalTld.match(body);
        if (mTld.hasMatch()) {
            addFinding(rowId, req, resp, "info", "internal-hostname-leak",
                       "Internal-TLD hostname referenced",
                       "first match: " + mTld.captured());
        }
    }

    // ---- HTML comment leaks (TODO / FIXME / credentials) ----------------
    if (html && resp.body.size() < 512 * 1024) {
        const QString body = QString::fromUtf8(resp.body);
        static const QRegularExpression rxComments(
            R"#(<!--([\s\S]*?)-->)#", QRegularExpression::CaseInsensitiveOption);
        auto it = rxComments.globalMatch(body);
        int interesting = 0;
        QString firstHit;
        while (it.hasNext() && interesting < 1) {
            const auto m = it.next();
            const QString c = m.captured(1).toLower();
            if (c.contains("todo") || c.contains("fixme") || c.contains("hack")
                || c.contains("password") || c.contains("secret")
                || c.contains("debug") || c.contains("test only")) {
                ++interesting;
                firstHit = m.captured().left(160);
            }
        }
        if (interesting > 0) {
            addFinding(rowId, req, resp, "info", "html-comment-leak",
                       "Interesting HTML comment in response",
                       firstHit);
        }
    }

    // ---- Open redirect via response Location header ---------------------
    // If the Location goes to a completely different host than req.host
    // AND a request parameter contained the same hostname, flag it.
    if (resp.statusCode >= 300 && resp.statusCode < 400) {
        const QString loc = headerOf(resp.headers, "Location");
        if (!loc.isEmpty()) {
            QString locHost;
            const QUrl locUrl = QUrl::fromUserInput(loc);
            if (locUrl.isValid()) locHost = locUrl.host();
            if (!locHost.isEmpty() && locHost.compare(req.host, Qt::CaseInsensitive) != 0) {
                const int qmark2 = req.path.indexOf('?');
                if (qmark2 >= 0) {
                    const QString query = req.path.mid(qmark2 + 1);
                    if (query.contains(locHost, Qt::CaseInsensitive)
                        || query.contains(QUrl::toPercentEncoding(locHost),
                                          Qt::CaseInsensitive)) {
                        addFinding(rowId, req, resp, "medium",
                                   "open-redirect-suspect",
                                   "Redirect target appears to come from a query param",
                                   "Location: " + loc + " (host: " + locHost + ")");
                    }
                }
            }
        }
    }

    // ---- CORS subtle misconfigurations ---------------------------------
    if (!acao.isEmpty() && acao != "*") {
        const QString origin = headerOf(req.headers, "Origin");
        // Reflects arbitrary Origin -- worse than * when paired with creds.
        if (!origin.isEmpty() && origin.compare(acao, Qt::CaseInsensitive) == 0
            && acac.compare("true", Qt::CaseInsensitive) == 0) {
            addFinding(rowId, req, resp, "high", "cors-origin-reflection",
                       "ACAO reflects request Origin with credentials",
                       "Origin: " + origin + " · ACAO: " + acao);
        }
        // "null" origin is allowed -- file://, sandboxed iframe, etc.
        if (acao.compare("null", Qt::CaseInsensitive) == 0) {
            addFinding(rowId, req, resp, "medium", "cors-null-origin",
                       "ACAO: null (sandboxed iframes / file:// pages get access)",
                       "Access-Control-Allow-Origin: null");
        }
    }
}

} // namespace Nullock::Core

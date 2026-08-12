#include "passive_scanner.hpp"
#include "finding_enricher.hpp"
#include "cve_database.hpp"
#include "jwt_tool.hpp"

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

// A hostile response can pack thousands of tiny Set-Cookie headers into the 64KB
// header budget; the cookie-hardening loops fire up to ~3 findings each, which
// without a bound would flush the kCap=1000 findings ring many times over and
// EVICT real findings (leaked keys, RCE, CVEs). Cap how many Set-Cookie headers
// each loop inspects -- a legitimate response sets a handful.
constexpr int kMaxCookiesScanned = 40;

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
    // limit <= 0 means "all" -- callers like the report builder and the
    // grouped view pass 0 to get the full set. (A literal 0 limit would
    // otherwise fall through to the slice loop and return an empty list.)
    if (limit <= 0 || limit >= m_findings.size()) return m_findings;
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
    FindingEnricher::enrich(f);
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
    FindingEnricher::enrich(f);
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
    // Scan the DECODED body (gzip/deflate inflated by the proxy) so compressed
    // responses -- most of the real web -- are actually inspected instead of
    // being seen as opaque bytes. Falls back to the raw body when it wasn't
    // compressed. Size gates below therefore bound the decoded size.
    const QByteArray &scanBody = resp.bodyForInspection();
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
        // Cheap introspection sniff: "__schema" in the body means the endpoint
        // answered an introspection query.
        //
        // Deliberately NOT "__typename". Clients request __typename in ordinary
        // operations all the time (Apollo and Relay add it automatically), so it
        // appears in perfectly normal responses from a server with introspection
        // disabled. Matching on it would report every GraphQL app as vulnerable.
        if (QString::fromUtf8(scanBody.left(8 * 1024))
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
    // times in one response (auth + csrf + lang) so walk every one (capped).
    {
        int cookieN = 0;
        for (const QString &cookie : allHeaderValues(resp.headers, "Set-Cookie")) {
            if (cookieN++ >= kMaxCookiesScanned) break;   // bound finding-spam
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
    }
    // Report-Only without an enforcing CSP: separate block so it fires
    // even when there's no enforcing CSP at all (which is precisely the
    // case we care about).
    {
        const QString cspRO = headerOf(resp.headers,
                                       "Content-Security-Policy-Report-Only");
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
    int cookieN2 = 0;
    for (const QString &cookie : allHeaderValues(resp.headers, "Set-Cookie")) {
        if (cookieN2++ >= kMaxCookiesScanned) break;   // bound finding-spam
        const QString lc = cookie.toLower();
        const QString name = cookie.section('=', 0, 0).trimmed();
        // __Secure- prefix requires Secure.
        if (name.startsWith("__Secure-", Qt::CaseInsensitive) && !lc.contains("secure")) {
            addFinding(rowId, req, resp, "medium", "cookie-secure-prefix-violation",
                       "__Secure- prefixed cookie set without Secure flag",
                       cookie.left(240));
        }
        // Path must be EXACTLY "/" (RFC 6265bis). A substring contains("path=/")
        // wrongly accepts a non-root Path=/app, because "path=/app" contains
        // "path=/". Computed ONCE here and shared by both checks below: they
        // used to disagree, with __Host- tokenizing correctly while the
        // broad-path check a few lines down used the substring test this very
        // comment warns against.
        bool pathRoot = false;
        for (const QString &attr : lc.split(';'))
            if (attr.trimmed() == "path=/") { pathRoot = true; break; }

        // __Host- prefix requires Secure, Path=/, no Domain.
        if (name.startsWith("__Host-", Qt::CaseInsensitive)) {
            const bool hasDomain = lc.contains("domain=");
            const bool hasSecure = lc.contains("secure");
            if (hasDomain || !hasSecure || !pathRoot) {
                addFinding(rowId, req, resp, "medium", "cookie-host-prefix-violation",
                           "__Host- prefixed cookie missing Secure / Path=/ or has Domain",
                           cookie.left(240));
            }
        }
        // Path=/ + no SameSite gives the cookie max blast radius. Uses the
        // tokenized pathRoot above -- the finding text asserts the cookie is
        // "scoped to whole origin", which is only true for an exact Path=/.
        if (pathRoot && !lc.contains("samesite")) {
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
        const QString bodyText = QString::fromUtf8(scanBody.left(256 * 1024));
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

    // ---- Missing Subresource Integrity on cross-origin scripts ----------
    // A third-party <script src> with no integrity= lets a compromised CDN or
    // dependency execute arbitrary code in this origin (supply-chain risk).
    // Only cross-origin (different host) scripts are flagged -- SRI is not
    // expected for first-party scripts, so requiring it there would be noise.
    if (html) {
        const QString bodyText = QString::fromUtf8(scanBody.left(256 * 1024));
        static const QRegularExpression rxScript(
            R"#(<script\b[^>]*\bsrc\s*=\s*['"](https?://[^'"]+)['"][^>]*>)#",
            QRegularExpression::CaseInsensitiveOption);
        auto it = rxScript.globalMatch(bodyText);
        int hits = 0;
        QString firstHit;
        while (it.hasNext() && hits < 5) {
            const auto m = it.next();
            if (m.captured(0).contains("integrity", Qt::CaseInsensitive)) continue;  // has SRI
            const QString srcHost = QUrl(m.captured(1)).host();
            if (srcHost.isEmpty() || srcHost.compare(req.host, Qt::CaseInsensitive) == 0)
                continue;   // same-origin script -> SRI not expected
            if (firstHit.isEmpty()) firstHit = m.captured(1).left(160);
            ++hits;
        }
        if (hits > 0) {
            addFinding(rowId, req, resp, "low", "sri-missing",
                       QString("%1 cross-origin <script> without Subresource Integrity").arg(hits),
                       "first: " + firstHit + " -- add an integrity= (with crossorigin) "
                       "attribute so a compromised third party cannot inject code");
        }
    }

    // ---- Source map exposure --------------------------------------------
    // Production JS shipping with sourcemaps leaks original symbols, file
    // names, and often comments + local paths.
    if (contentType.contains("javascript", Qt::CaseInsensitive)
        || contentType.contains("application/json", Qt::CaseInsensitive)
        || req.path.endsWith(".js") || req.path.endsWith(".mjs")) {
        const QString bodyText = QString::fromUtf8(scanBody.right(2048));
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
    if (resp.statusCode == 200 && scanBody.size() < 4 * 1024 * 1024) {
        const QString body = QString::fromUtf8(scanBody.left(4 * 1024 * 1024));
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
            // standing alone -- require an "aws" / "secret" / "access" context
            // word within 80 chars.
            //
            // "access" and not the looser "key" on purpose: the real credential
            // sits next to aws_secret_access_key, which "access" already
            // catches, whereas a bare "key" is one of the most common words in
            // any JSON document. Accepting it would flag every 40-character
            // base64 blob that happens to follow a "key" field.
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
    // which framework + line numbers to target. Django is the exception: its
    // DEBUG error page renders the URLconf resolver on a 404 (not only on 5xx),
    // so its needle also runs on a 404. Every other needle stays 5xx-only -- a
    // generic 404 page mentioning "java.lang." / "at Object." must not fire.
    if ((resp.statusCode >= 500 || resp.statusCode == 404)
        && scanBody.size() < 1 * 1024 * 1024) {
        const bool is404 = resp.statusCode == 404;
        const QString body = QString::fromUtf8(scanBody.left(64 * 1024));
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
            // On a 404 only the Django URLconf needle is specific enough to fire
            // without false positives on ordinary not-found pages.
            if (is404 && QLatin1String(t.kind) != QLatin1String("stack-django"))
                continue;
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
    if (html && scanBody.size() < 2 * 1024 * 1024) {
        const QString body = QString::fromUtf8(scanBody.left(2 * 1024 * 1024));
        // Per-prefix octet counts: the 10/127 branches carry ONE leading octet
        // (+3 = 4 total), while 192.168 and 172.1x already carry TWO (+2 = 4).
        // The old shared "+3 octets" tail made 192.168.x.x / 172.16-31.x.x need a
        // spurious 5th octet, so those two common private ranges never matched.
        static const QRegularExpression rxPrivIP(
            R"(\b(?:10|127)\.\d{1,3}(?:\.\d{1,3}){2}\b|\b192\.168(?:\.\d{1,3}){2}\b|\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b)");
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
    if (html && scanBody.size() < 512 * 1024) {
        const QString body = QString::fromUtf8(scanBody);
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

    // ---- CORS preflight overpermissive --------------------------------
    if (headerOf(resp.headers, "Access-Control-Allow-Methods").contains("*")) {
        addFinding(rowId, req, resp, "low", "cors-methods-wildcard",
                   "Access-Control-Allow-Methods: * is overly permissive",
                   "ACAM: *");
    }
    if (headerOf(resp.headers, "Access-Control-Allow-Headers").contains("*")) {
        addFinding(rowId, req, resp, "low", "cors-headers-wildcard",
                   "Access-Control-Allow-Headers: * permits any header",
                   "ACAH: *");
    }

    // ---- Vary header on cookie-dependent responses --------------------
    // If Set-Cookie is present AND Cache-Control allows caching AND
    // Vary doesn't include Cookie, a shared cache will serve user A's
    // cookies to user B. Classic Cloudflare bug pattern.
    const QString vary = headerOf(resp.headers, "Vary").toLower();
    if (setsCookie && resp.statusCode == 200) {
        const QString cc = headerOf(resp.headers, "Cache-Control").toLower();
        const bool cacheable = !cc.contains("no-store") && !cc.contains("private");
        if (cacheable && !vary.contains("cookie")) {
            addFinding(rowId, req, resp, "medium", "cache-vary-missing-cookie",
                       "Response sets cookies and may be cached without Vary: Cookie",
                       "Cache-Control: " + cc + " · Vary: " + vary);
        }
    }

    // ---- WAF / CDN fingerprinting (informational) ---------------------
    // Useful to know the user is sitting behind Cloudflare / Akamai /
    // Imperva so they can plan evasion vs. block-list testing.
    struct WafIndicator { const char *header; const char *kind; const char *label; };
    static const WafIndicator kWafs[] = {
        { "CF-RAY",                "waf-cloudflare", "Cloudflare" },
        { "Server",                "waf-cloudflare", "Cloudflare" },  // cf-... server
        { "X-Akamai-Transformed",  "waf-akamai",     "Akamai" },
        { "X-Iinfo",               "waf-imperva",    "Imperva" },
        { "X-CDN",                 "waf-fastly",     "Fastly/CDN" },
        { "X-Cache",               "waf-varnish",    "Varnish/CDN" },
        { "X-Sucuri-ID",           "waf-sucuri",     "Sucuri" },
        { "Server-Timing",         "waf-server-timing", "Server-Timing" },
    };
    for (const auto &w : kWafs) {
        const QString v = headerOf(resp.headers, w.header);
        if (v.isEmpty()) continue;
        if (QString::fromLatin1(w.kind) == "waf-cloudflare" && QString::fromLatin1(w.header) == "Server") {
            if (!v.toLower().startsWith("cf")) continue;  // not cloudflare
        }
        addFinding(rowId, req, resp, "info", w.kind,
                   QString("%1 detected via %2 header").arg(QString::fromLatin1(w.label),
                                                             QString::fromLatin1(w.header)),
                   QString::fromLatin1(w.header) + ": " + v.left(120));
        if (QString::fromLatin1(w.kind) != "waf-cloudflare") break;
    }

    // ---- Server-Timing leak --------------------------------------------
    // Reveals internal timing (DB lookup, cache miss, etc.) which can
    // power timing attacks. Same header sometimes acts as WAF marker;
    // we surface as separate finding only when content looks like timing.
    const QString stiming = headerOf(resp.headers, "Server-Timing");
    if (!stiming.isEmpty() && stiming.contains(QRegularExpression("dur=\\d"))) {
        addFinding(rowId, req, resp, "info", "server-timing-leak",
                   "Server-Timing header exposes internal timing measurements",
                   "Server-Timing: " + stiming.left(200));
    }

    // ---- Cloud bucket / storage endpoints exposed ---------------------
    // S3 / GCS / Azure Blob URLs in response body suggest public storage
    // or hard-coded references the user can probe directly.
    if (html && scanBody.size() < 1 * 1024 * 1024) {
        const QString body = QString::fromUtf8(scanBody.left(1 * 1024 * 1024));
        struct CloudPat { const char *kind; const char *label; QRegularExpression rx; };
        // The host/bucket character runs are LENGTH-BOUNDED ({0,253}, the max DNS
        // name) instead of +/*. The S3 pattern has two runs over the same class
        // separated by a `.s3.` anchor that can REPEAT in a crafted body; an
        // unbounded run then re-scans to EOF at every anchor -> O(n^2) backtracking
        // (measured: 320KB ~= 14s) on the MAIN/GUI thread. Bounding each run caps
        // the per-anchor rescan to 253, making the whole match linear.
        static const CloudPat kCloud[] = {
            { "cloud-s3-bucket", "AWS S3 bucket",
              QRegularExpression(R"(https?://[a-zA-Z0-9.\-]{1,253}\.s3[.\-][a-zA-Z0-9.\-]{0,253}amazonaws\.com)") },
            { "cloud-gcs-bucket", "GCS bucket",
              QRegularExpression(R"(https?://storage\.googleapis\.com/[a-zA-Z0-9._\-]{1,253})") },
            { "cloud-azure-blob", "Azure Blob",
              QRegularExpression(R"(https?://[a-zA-Z0-9.\-]{1,253}\.blob\.core\.windows\.net)") },
            { "cloud-firebase", "Firebase Realtime DB",
              QRegularExpression(R"(https?://[a-zA-Z0-9.\-]{1,253}\.firebaseio\.com)") },
            { "cloud-firebase-storage", "Firebase Storage",
              QRegularExpression(R"(https?://firebasestorage\.googleapis\.com)") },
        };
        for (const auto &c : kCloud) {
            const auto m = c.rx.match(body);
            if (m.hasMatch()) {
                addFinding(rowId, req, resp, "info", c.kind,
                           QString("%1 URL referenced -- check for public ACL")
                               .arg(QString::fromLatin1(c.label)),
                           "first: " + m.captured().left(160));
            }
        }
    }

    // ---- Dev / admin tooling exposed -----------------------------------
    // The single largest source of "easy" bug bounty wins. If any of
    // these paths return a 200, surface it loud.
    if (resp.statusCode == 200) {
        struct DevTool { const char *needle; const char *kind; const char *label; const char *severity; };
        static const DevTool kDevTools[] = {
            // ORDER MATTERS: the loop below takes the FIRST substring match and
            // breaks, so a generic needle placed above a specific one makes the
            // specific row unreachable. "/actuator/env" contains "/actuator/",
            // so these two must stay ABOVE the generic row -- otherwise
            // spring-actuator-env and spring-actuator-heap never fire at all,
            // and a heapdump (critical) silently reports as plain actuator
            // (high). Do not alphabetise this table.
            { "/actuator/env",     "spring-actuator-env", "Spring Boot /env",        "high" },
            { "/actuator/heapdump","spring-actuator-heap","Spring Boot /heapdump",   "critical" },
            { "/actuator/",        "spring-actuator",  "Spring Boot Actuator",       "high" },
            { "/swagger-ui",       "swagger-ui",       "Swagger UI",                  "medium" },
            { "/swagger.json",     "swagger-spec",     "Swagger spec",                "medium" },
            { "/openapi.json",     "openapi-spec",     "OpenAPI spec",                "medium" },
            { "/graphiql",         "graphiql",         "GraphiQL interface",          "medium" },
            { "/voyager",          "graphql-voyager",  "GraphQL Voyager",             "medium" },
            { "/playground",       "graphql-playground","GraphQL Playground",         "medium" },
            { "/_debugbar",        "debug-bar",        "Symfony / Laravel debug bar", "high" },
            { "/_profiler",        "symfony-profiler", "Symfony profiler",            "high" },
            { "/admin/",           "admin-path",       "Admin path",                  "low" },
            { "/.well-known/security.txt", "security-txt", "security.txt present",    "info" },
            { "/manager/html",     "tomcat-manager",   "Tomcat manager",              "high" },
            { "/host-manager",     "tomcat-host-mgr",  "Tomcat host manager",         "high" },
            { "/phpmyadmin",       "phpmyadmin",       "phpMyAdmin",                  "high" },
            { "/wp-admin",         "wp-admin",         "WordPress admin",             "info" },
            { "/server-status",    "apache-status",    "Apache server-status",        "high" },
            { "/server-info",      "apache-info",      "Apache server-info",          "high" },
            { "/.git/HEAD",        "git-head-exposed", "Git HEAD exposed",            "critical" },
            { "/jolokia",          "jolokia-exposed",  "Jolokia JMX HTTP",            "high" },
            { "/druid",            "druid-monitor",    "Apache Druid monitoring",     "medium" },
        };
        for (const auto &d : kDevTools) {
            if (req.path.contains(QString::fromLatin1(d.needle), Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp,
                           QString::fromLatin1(d.severity), d.kind,
                           QString("%1 reachable").arg(QString::fromLatin1(d.label)),
                           "path: " + req.path);
                break;  // one per row
            }
        }
    }

    // ---- phpinfo() output detection ------------------------------------
    if (resp.statusCode == 200 && html) {
        const QString body = QString::fromUtf8(scanBody.left(64 * 1024));
        if (body.contains("phpinfo()", Qt::CaseInsensitive)
            && body.contains("PHP Version", Qt::CaseInsensitive)
            && body.contains("System ", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "critical", "phpinfo-output",
                       "phpinfo() output reachable (full env + paths + extensions)",
                       "page contains 'phpinfo()' + 'PHP Version' + 'System '");
        }
    }

    // ---- Robots.txt / sitemap.xml sensitive paths ----------------------
    // Crawlers like to publish private endpoints in their disallow rules.
    if (resp.statusCode == 200 && req.path.endsWith("/robots.txt", Qt::CaseInsensitive)) {
        const QString body = QString::fromUtf8(scanBody.left(128 * 1024));
        static const QStringList kRobotsSnitch = {
            "admin", "private", "secret", "internal", "staging",
            "backup", "test", "debug", "/api/", "/v1/", "/dev/",
        };
        QStringList hits;
        for (const QString &word : kRobotsSnitch) {
            if (body.contains(word, Qt::CaseInsensitive)) hits << word;
        }
        if (!hits.isEmpty()) {
            addFinding(rowId, req, resp, "low", "robots-discloses-paths",
                       "robots.txt mentions sensitive-shape paths",
                       "keywords: " + hits.join(", "));
        }
    }

    // ---- Sec-Fetch-* missing on credentialed endpoints -----------------
    // Modern browsers send Sec-Fetch-Site / Sec-Fetch-Mode; backends
    // should verify them on sensitive requests. We can't prove enforcement
    // -- only flag the user that they could be a defense layer.
    if (hasAuth && resp.statusCode == 200
        && headerOf(req.headers, "Sec-Fetch-Site").isEmpty()) {
        // Don't flag: this is informational and would fire on every
        // CLI / non-browser request. The user's CLI hitting their own
        // API isn't a finding. Leaving this comment as a deliberate
        // anti-finding so future-me doesn't add it back.
    }

    // ---- JWT in URL / form / response body ----------------------------
    // Tokens in URLs get logged everywhere (proxy logs, referrers,
    // bookmark sync). Same applies if a JWT shows up echoed in a body.
    static const QRegularExpression rxJwt(
        R"(\bey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})");
    if (rxJwt.match(req.path).hasMatch()) {
        addFinding(rowId, req, resp, "medium", "jwt-in-url",
                   "JWT-shape token visible in URL",
                   "path: " + req.path.left(200));
    }
    if (scanBody.size() > 0 && scanBody.size() < 256 * 1024) {
        const QString body = QString::fromUtf8(scanBody);
        const auto mJ = rxJwt.match(body);
        if (mJ.hasMatch()) {
            // Don't double-flag obvious places like an /auth/login response.
            if (!req.path.contains("login", Qt::CaseInsensitive)
                && !req.path.contains("auth", Qt::CaseInsensitive)
                && !req.path.contains("token", Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp, "info", "jwt-echoed-in-body",
                           "JWT-shape token appears in response body of "
                           "a non-auth endpoint",
                           "first JWT: " + mJ.captured().left(40) + "...");
            }
        }
    }

    // ---- JWT weakness analysis ----------------------------------------
    // Decode any JWT carried on this request (Authorization: Bearer, a
    // cookie, or the URL) and emit findings for real weaknesses --
    // alg:none, missing/expired exp, kid-injection surface, etc. Each
    // distinct token is analysed once (keyed by its signature segment) so
    // an authenticated session doesn't spray duplicate findings.
    {
        QString jwt;
        const QString authz = headerOf(req.headers, "Authorization");
        if (authz.startsWith("Bearer ", Qt::CaseInsensitive)) {
            const QString cand = authz.mid(7).trimmed();
            if (rxJwt.match(cand).hasMatch()) jwt = cand;
        }
        if (jwt.isEmpty()) {
            // Fall back to a JWT-shaped token anywhere in the URL.
            const auto mu = rxJwt.match(req.path);
            if (mu.hasMatch()) jwt = mu.captured();
        }
        if (!jwt.isEmpty()) {
            const QString sig = jwt.section('.', 2, 2);
            bool fresh = false;
            {
                QMutexLocker lk(&m_mutex);
                if (!m_jwtSeen.contains(sig)) { m_jwtSeen.insert(sig); fresh = true; }
                // Cap the set so a long fuzzing session doesn't grow it forever.
                if (m_jwtSeen.size() > 20000) m_jwtSeen.clear();
            }
            if (fresh) {
                const auto d = JwtTool::decode(jwt);
                if (d.ok) {
                    for (const auto &w : JwtTool::analyze(d)) {
                        // Skip the pure-informational HMAC note to avoid
                        // flagging every normal HS256 token; keep the rest.
                        if (w.id == "jwt-hmac-alg") continue;
                        addFinding(rowId, req, resp, w.severity, w.id,
                                   "JWT: " + w.detail.left(120), w.detail);
                    }
                }
            }
        }
    }

    // ---- OPTIONS Allow header enumeration -----------------------------
    if (req.method.compare("OPTIONS", Qt::CaseInsensitive) == 0) {
        const QString allow = headerOf(resp.headers, "Allow");
        if (allow.contains("DELETE", Qt::CaseInsensitive)
            || allow.contains("PUT", Qt::CaseInsensitive)
            || allow.contains("PATCH", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "options-mutation-methods",
                       "OPTIONS response advertises mutation methods",
                       "Allow: " + allow);
        }
    }

    // ---- WebSocket Upgrade Origin not validated -----------------------
    // If we see a 101 Switching Protocols and the request Origin doesn't
    // match req.host's apex, that's a candidate cross-origin WS bug.
    if (resp.statusCode == 101) {
        const QString origin = headerOf(req.headers, "Origin");
        if (!origin.isEmpty()) {
            QString originHost;
            const QUrl ou = QUrl::fromUserInput(origin);
            if (ou.isValid()) originHost = ou.host();
            // Dot-anchor the comparison: cross-origin unless the Origin host
            // equals req.host or is a TRUE subdomain. A bare endsWith let an
            // attacker sibling (evil-example.com vs example.com) slip past.
            if (!originHost.isEmpty()
                && originHost.compare(req.host, Qt::CaseInsensitive) != 0
                && !originHost.endsWith("." + req.host, Qt::CaseInsensitive)
                && !req.host.endsWith("." + originHost, Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp, "medium", "ws-cross-origin-accepted",
                           "WebSocket upgrade accepted with cross-origin Origin",
                           "Origin: " + origin + " · host: " + req.host);
            }
        }
    }

    // ---- DOM-XSS sink patterns in inline scripts ----------------------
    if (html && scanBody.size() < 1 * 1024 * 1024) {
        const QString body = QString::fromUtf8(scanBody.left(1 * 1024 * 1024));
        struct DomPat { const char *kind; const char *label; QRegularExpression rx; };
        static const DomPat kDom[] = {
            { "dom-xss-innerhtml-location",
              "innerHTML <- location",
              QRegularExpression(
                  R"(\.innerHTML\s*=\s*[^;]*(?:location|document\.referrer|window\.name))") },
            { "dom-xss-eval-location",
              "eval / setTimeout with location-derived string",
              QRegularExpression(
                  R"((?:eval|setTimeout|setInterval|Function)\s*\(\s*(?:location|document\.referrer|window\.name))") },
            { "dom-postmessage-wildcard",
              "postMessage with '*' target origin",
              QRegularExpression(R"(postMessage\s*\([^,)]+,\s*['"]\*['"]\s*\))") },
            { "dom-eval-of-fetch",
              "eval of fetch / XHR response text",
              QRegularExpression(R"(eval\s*\(\s*\w+\.responseText)") },
        };
        for (const auto &d : kDom) {
            if (d.rx.match(body).hasMatch()) {
                addFinding(rowId, req, resp, "medium", d.kind,
                           QString("Suspicious inline JS pattern: %1")
                               .arg(QString::fromLatin1(d.label)),
                           "regex matched in body -- review the script tag");
                break;  // one DOM finding per page is plenty
            }
        }
    }

    // ---- Local / session storage of secrets in inline JS --------------
    if (html && scanBody.size() < 1 * 1024 * 1024) {
        const QString body = QString::fromUtf8(scanBody.left(1 * 1024 * 1024));
        static const QRegularExpression rxStoreSecret(
            R"((?:localStorage|sessionStorage)\.setItem\s*\(\s*['"](?:token|auth|jwt|password|secret|apiKey|api_key|access)['"])",
            QRegularExpression::CaseInsensitiveOption);
        if (rxStoreSecret.match(body).hasMatch()) {
            addFinding(rowId, req, resp, "low", "storage-of-secrets",
                       "Inline JS stores credential-shape value in localStorage/sessionStorage",
                       "matches setItem('token'|'jwt'|...)");
        }
    }

    // ---- Verbose 4xx errors leaking SQL / framework info --------------
    if (resp.statusCode >= 400 && resp.statusCode < 500
        && scanBody.size() < 256 * 1024) {
        const QString body = QString::fromUtf8(scanBody);
        struct ErrPat { const char *kind; const char *needle; };
        static const ErrPat kErrPats[] = {
            { "verbose-sql-err",      "ORA-" },
            { "verbose-sql-err",      "MySQL server version" },
            { "verbose-sql-err",      "syntax error at or near" },
            { "verbose-sql-err",      "Microsoft OLE DB Provider" },
            { "verbose-sql-err",      "ODBC SQL Server Driver" },
            { "verbose-sql-err",      "sqlite3.OperationalError" },
            { "verbose-php-err",      "Warning: " },
            { "verbose-php-err",      "Notice: " },
            { "verbose-debug-page",   "Werkzeug Debugger" },
            { "verbose-debug-page",   "Whoops! There was an error" },
            { "verbose-debug-page",   "<title>Symfony Exception" },
        };
        for (const auto &e : kErrPats) {
            if (body.contains(QString::fromLatin1(e.needle))) {
                addFinding(rowId, req, resp, "medium", e.kind,
                           "Verbose error leak (" + QString::fromLatin1(e.needle)
                               + ") in 4xx response",
                           "needle: " + QString::fromLatin1(e.needle));
                break;
            }
        }
    }

    // ---- Host header reflection / unvalidated -------------------------
    // If the Host header value shows up in a Set-Cookie domain attribute,
    // a Location header, or a body href, the server isn't validating
    // Host -> ripe for password-reset poisoning.
    const QString hostHdr = headerOf(req.headers, "Host");
    if (!hostHdr.isEmpty() && resp.statusCode >= 200 && resp.statusCode < 400) {
        const QString loc2 = headerOf(resp.headers, "Location");
        if (!loc2.isEmpty() && loc2.contains(hostHdr, Qt::CaseInsensitive)
            && !loc2.startsWith("/") && !loc2.startsWith("http")) {
            // Already-absolute Location with mathing host -- normal. Skip.
        } else if (!loc2.isEmpty() && loc2.contains(hostHdr, Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "host-header-reflected-location",
                       "Host header value appears in Location -- check for poisoning",
                       "Host: " + hostHdr + " · Location: " + loc2);
        }
    }

    // ---- Deserialization signatures (passive detection) ---------------
    // Look for serialized blobs in request bodies / cookies / params.
    // High false-positive risk in general, so we only flag when the
    // canonical magic bytes / prefixes are present.
    const QString reqAllHeaders = [&]{
        QString out;
        for (const auto &h : req.headers) out += h.first + ": " + h.second + "\n";
        return out;
    }();
    struct DesPat { const char *kind; const char *label; const char *prefix; };
    static const DesPat kDesPats[] = {
        // Java serialized: rO0 base64 prefix decodes to ac ed 00 05 magic
        { "deser-java",   "Java serialized object (rO0...)",   "rO0AB" },
        // Python pickle: "gASV" decodes to 0x80 0x04 0x95 -- PROTO 4 followed by
        // FRAME, which is what pickle.dumps emits by default on modern CPython.
        // The label must name the prefix actually matched: it used to advertise
        // "gAS... / gAR...", but gAR is not a needle, so a finding claimed a
        // match the code cannot make. (The old comment also had the arithmetic
        // wrong -- "gAB" decodes to 0x80 0x00, protocol 0, not 0x80 0x04.)
        // Broadening to the 3-char "gAS" would catch other protocol-4 framings
        // but raises false positives on arbitrary base64; left deliberately narrow.
        { "deser-pickle", "Python pickle (gASV...)",           "gASV" },
        // PHP serialized OBJECT only: the needle is "O:", refined below by
        // O:\d+:" so a stray "O:" in prose does not match.
        //
        // a:N: (array) and s:N: (string) are deliberately NOT needles, despite
        // also being serialized forms. A gadget chain needs an OBJECT to reach
        // __wakeup/__destruct, and an array carrying one still contains an O:
        // and is caught here anyway -- while a bare a:2: or s:5: matches
        // ordinary serialized data and would be almost pure false positive.
        { "deser-php",    "PHP serialized object (O:N:...)",   "O:" },
        // Ruby Marshal: BAh prefix
        { "deser-ruby",   "Ruby Marshal (BAh...)",             "BAh" },
        // .NET BinaryFormatter: AAEAAAD base64 prefix
        { "deser-dotnet", ".NET BinaryFormatter (AAEAAAD...)", "AAEAAAD" },
    };
    auto bodyText = QString::fromUtf8(req.body.left(64 * 1024));
    for (const auto &d : kDesPats) {
        const QString needle = QString::fromLatin1(d.prefix);
        bool hit = false;
        QString where;
        if (bodyText.contains(needle)) { hit = true; where = "request body"; }
        else if (reqAllHeaders.contains(needle)) { hit = true; where = "request headers"; }
        if (hit) {
            // PHP O: pattern is short. Require a colon-digit-colon to
            // cut false positives.
            if (QString::fromLatin1(d.kind) == "deser-php") {
                static const QRegularExpression rxPhp(R"(O:\d+:")");
                if (!rxPhp.match(bodyText).hasMatch()
                    && !rxPhp.match(reqAllHeaders).hasMatch()) continue;
            }
            addFinding(rowId, req, resp, "high", d.kind,
                       QString("Serialized %1 in %2 -- gadget-chain RCE candidate")
                           .arg(QString::fromLatin1(d.label), where),
                       "match begins: " + needle);
            break;
        }
    }

    // ---- CSV / formula injection markers (passive) --------------------
    // Look at responses likely intended for CSV download. If user-
    // controllable cells start with =, +, -, @, they execute as
    // formulas in Excel/LibreOffice on open.
    if (contentType.contains("text/csv", Qt::CaseInsensitive)
        || contentType.contains("application/csv", Qt::CaseInsensitive)
        || req.path.endsWith(".csv", Qt::CaseInsensitive)) {
        const QString body = QString::fromUtf8(scanBody.left(256 * 1024));
        static const QRegularExpression rxFormula(R"((^|\n)[=+\-@][A-Za-z])");
        if (rxFormula.match(body).hasMatch()) {
            addFinding(rowId, req, resp, "medium", "csv-formula-injection",
                       "CSV cell starts with formula trigger (=, +, -, @) -- "
                       "Excel will execute on open",
                       "first formula cell visible in CSV body");
        }
    }

    // ---- Subdomain takeover indicators (passive) ----------------------
    // 404 / 503 response bodies with vendor-specific error pages
    // suggest a CNAME pointing at an unclaimed cloud resource.
    if (resp.statusCode == 404 || resp.statusCode == 503) {
        const QString body = QString::fromUtf8(scanBody.left(32 * 1024));
        struct STPat { const char *kind; const char *label; const char *needle; };
        static const STPat kSTs[] = {
            { "takeover-s3",        "AWS S3 NoSuchBucket",
              "NoSuchBucket" },
            { "takeover-heroku",    "Heroku 'No such app'",
              "no such app" },
            { "takeover-github",    "GitHub Pages 404",
              "There isn't a GitHub Pages site here" },
            { "takeover-azure",     "Azure 404 Web App",
              "404 Web Site not found" },
            { "takeover-fastly",    "Fastly Fastly error: unknown domain",
              "Fastly error: unknown domain" },
            { "takeover-shopify",   "Shopify Sorry, this shop is",
              "Sorry, this shop is currently unavailable" },
            { "takeover-tumblr",    "Tumblr Whatever you were looking",
              "Whatever you were looking for" },
            // (removed) takeover-cargo: its needle was the literal "404 Not Found",
            // the stock body of nginx/Apache/IIS/Express/Flask -- so it fired a HIGH
            // takeover finding on essentially EVERY default 404. A ubiquitous string
            // must never map to a HIGH on its own; drop it rather than emit noise.
        };
        for (const auto &st : kSTs) {
            if (body.contains(QString::fromLatin1(st.needle), Qt::CaseInsensitive)) {
                addFinding(rowId, req, resp, "high", st.kind,
                           QString("Possible subdomain takeover on %1 (%2)")
                               .arg(req.host, QString::fromLatin1(st.label)),
                           "needle: " + QString::fromLatin1(st.needle));
                break;
            }
        }
    }

    // ---- SSRF outbound indicator: telltale OAST callback pattern ------
    // If the response body or a redirect lands at an attacker-controlled
    // OAST-shaped domain, the server already made an outbound request --
    // this catches CYA cases where the attacker won the race.
    // (Placeholder for now -- exercised only by self-test.)

    // ---- Defensive mode: outbound PII / secrets to public hosts -------
    // Flag your own app accidentally exfiltrating customer data to
    // unintended third-party hosts (analytics, error reporters that
    // weren't scoped, surveys). Burp doesn't have this -- they're
    // built for attacker-side use, we serve defender-side too.
    {
        const bool isPublicHost = !req.host.isEmpty()
            && !req.host.startsWith("127.")
            && !req.host.startsWith("10.")
            && !req.host.startsWith("192.168.")
            && !req.host.startsWith("172.")
            && !req.host.endsWith(".local", Qt::CaseInsensitive)
            && !req.host.endsWith(".internal", Qt::CaseInsensitive)
            && !req.host.endsWith(".corp", Qt::CaseInsensitive);

        const QString reqBody = QString::fromUtf8(req.body.left(256 * 1024));
        const QString fullUrl = req.path;
        const QString combined = fullUrl + "\n" + reqBody;

        if (isPublicHost && !combined.isEmpty()) {
            struct PiiPat { const char *kind; const char *label; QRegularExpression rx; };
            static const PiiPat kPiis[] = {
                { "pii-ssn-outbound", "US SSN",
                  QRegularExpression(R"(\b\d{3}-\d{2}-\d{4}\b)") },
                { "pii-cc-outbound", "Credit card number (Luhn shape)",
                  QRegularExpression(R"(\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b)") },
                { "pii-phone-us", "US phone number",
                  QRegularExpression(R"(\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b)") },
                { "pii-iban", "IBAN",
                  QRegularExpression(R"(\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b)") },
            };
            for (const auto &p : kPiis) {
                if (p.rx.match(combined).hasMatch()) {
                    addFinding(rowId, req, resp, "medium", p.kind,
                               QString("Outbound %1 in request to public host %2")
                                   .arg(QString::fromLatin1(p.label), req.host),
                               "review whether this destination is intended for this data class");
                }
            }

            // Mass-email leak: 3+ distinct email-shaped tokens. Counted via a
            // SINGLE linear regex + a bounded globalMatch loop, NOT the old
            // (?:email.*?){3,} mega-pattern -- that one nested a + inside a {3,}
            // repeat followed by a lazy .* (DotMatchesEverything), which
            // catastrophically backtracks on a near-miss body. checkResponse runs
            // on the MAIN/GUI thread (the queued responseReceived connection), so
            // that was a per-response main-thread ReDoS / UI freeze.
            {
                static const QRegularExpression rxEmail(
                    R"(\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b)");
                auto eit = rxEmail.globalMatch(combined);
                QSet<QString> emails;          // DISTINCT (the finding claims "3+ distinct")
                int scanned = 0;
                while (eit.hasNext() && emails.size() < 3 && scanned < 512) {
                    emails.insert(eit.next().captured().toLower());
                    ++scanned;
                }
                if (emails.size() >= 3) {
                    addFinding(rowId, req, resp, "medium", "pii-email-mass",
                               QString("Outbound %1 in request to public host %2")
                                   .arg(QStringLiteral("Email-shape (multiple)"), req.host),
                               "review whether this destination is intended for this data class");
                }
            }
        }
    }

    // ---- Reflected file download indicator ----------------------------
    // Content-Disposition: attachment with user-controlled filename in
    // path/query -- enables RFD attacks where the user is convinced to
    // execute the downloaded file.
    const QString cdsp = headerOf(resp.headers, "Content-Disposition");
    if (cdsp.contains("attachment", Qt::CaseInsensitive)) {
        const QString q = req.path.contains('?') ? req.path.section('?', 1) : QString();
        // The needle is the first param's VALUE, and it must be checked for
        // emptiness before use: QString::contains(QString()) returns TRUE
        // (indexOf of an empty needle is 0), and section('=',1,1) yields ""
        // for a valueless param. Without this guard "/export?csv" or
        // "/dl?a=&b=x" fire against a filename that mirrors nothing at all --
        // and a valueless flag param is exactly how download endpoints are
        // commonly written, so it was a live false-positive source rather
        // than a contrived one.
        const QString firstParamValue = q.section('&', 0, 0).section('=', 1, 1);
        if (!firstParamValue.isEmpty()
            && cdsp.contains(firstParamValue, Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "low", "reflected-file-download",
                       "Content-Disposition filename appears to mirror a request param",
                       cdsp.left(160));
        }
    }

    // ========================================================
    // CMS / framework fingerprinting (informational unless the
    // specific stack version is known-vulnerable). Detection is
    // path + header + body signature.
    // ========================================================
    if (resp.statusCode >= 200 && resp.statusCode < 400) {
        const QString bodyHead = QString::fromUtf8(scanBody.left(64 * 1024));
        const QString xPoweredBy = headerOf(resp.headers, "X-Powered-By");
        const QString genHdr = headerOf(resp.headers, "X-Generator");
        // Cached "have we already flagged a CMS for this row?" -- one
        // CMS finding per response is plenty.
        bool cmsHit = false;
        auto flagCms = [&](const char *sev, const char *kind, const QString &label,
                           const QString &evidence) {
            if (cmsHit) return;
            cmsHit = true;
            addFinding(rowId, req, resp, sev, kind,
                       "Detected: " + label, evidence.left(240));
        };

        // ---- WordPress -----------------------------------------------
        if (req.path.contains("/wp-content/") || req.path.contains("/wp-includes/")
            || req.path.contains("/wp-admin/")
            || bodyHead.contains("/wp-content/") || bodyHead.contains("wp-emoji")) {
            flagCms("info", "cms-wordpress", "WordPress",
                    "path or body contains wp-* markers");
        }
        // ---- Drupal --------------------------------------------------
        if (!cmsHit && (genHdr.contains("Drupal", Qt::CaseInsensitive)
                        || bodyHead.contains("Drupal.settings")
                        || bodyHead.contains("/sites/default/files")
                        || req.path.startsWith("/sites/default/"))) {
            flagCms("info", "cms-drupal", "Drupal",
                    "X-Generator/Drupal.settings/sites-default marker");
        }
        // ---- Joomla --------------------------------------------------
        if (!cmsHit && (bodyHead.contains("Joomla!")
                        || bodyHead.contains("/media/system/js/")
                        || req.path.startsWith("/administrator/"))) {
            flagCms("info", "cms-joomla", "Joomla",
                    "Joomla! string or /administrator/ marker");
        }
        // ---- Magento -------------------------------------------------
        const QString xMagento = headerOf(resp.headers, "X-Magento-Vary");
        if (!cmsHit && (!xMagento.isEmpty()
                        || bodyHead.contains("Mage.Cookies")
                        || bodyHead.contains("/skin/frontend/")
                        || req.path.startsWith("/index.php/admin"))) {
            flagCms("info", "cms-magento", "Magento",
                    "X-Magento-Vary / Mage.Cookies / skin/frontend marker");
        }
        // ---- Shopify -------------------------------------------------
        const QString xShopifyStage = headerOf(resp.headers, "X-Shopify-Stage");
        if (!cmsHit && (!xShopifyStage.isEmpty()
                        || bodyHead.contains("Shopify.theme")
                        || bodyHead.contains("cdn.shopify.com"))) {
            flagCms("info", "cms-shopify", "Shopify",
                    "X-Shopify-Stage / Shopify.theme / cdn.shopify.com");
        }
        // ---- Sitecore ------------------------------------------------
        if (!cmsHit && (!headerOf(resp.headers, "X-Sc-CompatibilityVersion").isEmpty()
                        || bodyHead.contains("scLayout")
                        || req.path.contains("/sitecore/"))) {
            flagCms("info", "cms-sitecore", "Sitecore",
                    "X-Sc-CompatibilityVersion / scLayout / /sitecore/ path");
        }
        // ---- Adobe Experience Manager --------------------------------
        if (!cmsHit && (bodyHead.contains("/etc/clientlibs/")
                        || bodyHead.contains("/content/dam/")
                        || bodyHead.contains("/aemforms/"))) {
            flagCms("info", "cms-aem", "Adobe Experience Manager",
                    "/etc/clientlibs/, /content/dam/, /aemforms/");
        }
        // ---- Umbraco -------------------------------------------------
        if (!cmsHit && (req.path.startsWith("/umbraco/")
                        || bodyHead.contains("umbraco.api"))) {
            flagCms("info", "cms-umbraco", "Umbraco",
                    "umbraco path or API string");
        }
        // ---- Salesforce / SF Commerce / Aura -------------------------
        if (!cmsHit && (bodyHead.contains("Aura.Component")
                        || bodyHead.contains("force.com")
                        || bodyHead.contains("salesforce.com"))) {
            flagCms("info", "cms-salesforce", "Salesforce / Aura",
                    "Aura.Component / force.com / salesforce.com marker");
        }
        // ---- Atlassian Confluence ------------------------------------
        const QString xConfReq = headerOf(resp.headers, "X-Confluence-Request-Time");
        if (!cmsHit && (!xConfReq.isEmpty()
                        || bodyHead.contains("ajs-version-number")
                        || bodyHead.contains("Confluence."))) {
            flagCms("info", "cms-confluence", "Atlassian Confluence",
                    "Confluence X-header / ajs-version / Confluence. marker");
        }
        // ---- Atlassian Jira ------------------------------------------
        if (!cmsHit && (req.path.startsWith("/secure/Dashboard.jspa")
                        || bodyHead.contains("jira-projectkey")
                        || bodyHead.contains("jira-issue"))) {
            flagCms("info", "cms-jira", "Atlassian Jira",
                    "Jira dashboard path / projectkey / issue marker");
        }
        // ---- WooCommerce on top of WordPress -------------------------
        if (cmsHit && req.path.contains("/wp-content/")
            && bodyHead.contains("woocommerce")) {
            // Separate finding for the platform layered on top.
            addFinding(rowId, req, resp, "info", "cms-woocommerce",
                       "Detected: WooCommerce",
                       "wp-content + 'woocommerce' string in body");
        }

        // ===== Framework / language ===================================
        // Independent of CMS finding -- multiple of these may apply.
        if (xPoweredBy.contains("Express", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "fw-express",
                       "Detected: Node.js / Express",
                       "X-Powered-By: " + xPoweredBy);
        }
        if (xPoweredBy.contains("ASP.NET", Qt::CaseInsensitive)
            || !headerOf(resp.headers, "X-AspNet-Version").isEmpty()
            || !headerOf(resp.headers, "X-AspNetMvc-Version").isEmpty()) {
            addFinding(rowId, req, resp, "info", "fw-aspnet",
                       "Detected: ASP.NET / MVC",
                       "X-AspNet headers present");
        }
        if (bodyHead.contains("__NEXT_DATA__")) {
            addFinding(rowId, req, resp, "info", "fw-nextjs",
                       "Detected: Next.js",
                       "__NEXT_DATA__ script tag in HTML");
        }
        if (bodyHead.contains("window.__NUXT__")) {
            addFinding(rowId, req, resp, "info", "fw-nuxt",
                       "Detected: Nuxt.js",
                       "window.__NUXT__ in HTML");
        }
        if (bodyHead.contains("ng-app=") || bodyHead.contains("ng-controller=")
            || bodyHead.contains("data-ng-app")) {
            addFinding(rowId, req, resp, "info", "fw-angularjs",
                       "Detected: AngularJS / Angular",
                       "ng-app / ng-controller attributes in HTML");
        }
        if (bodyHead.contains("data-reactroot") || bodyHead.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")) {
            addFinding(rowId, req, resp, "info", "fw-react",
                       "Detected: React",
                       "data-reactroot / __REACT_DEVTOOLS_GLOBAL_HOOK__ marker");
        }
        if (bodyHead.contains("v-app=") || bodyHead.contains("data-server-rendered")
            || bodyHead.contains("__VUE_HMR_RUNTIME__")) {
            addFinding(rowId, req, resp, "info", "fw-vue",
                       "Detected: Vue",
                       "Vue.js runtime marker");
        }
        if (!headerOf(resp.headers, "X-Runtime").isEmpty()
            || headerOf(resp.headers, "Set-Cookie").contains("_session_id=", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "fw-rails",
                       "Detected: Ruby on Rails",
                       "X-Runtime or _session_id cookie");
        }
        if (headerOf(resp.headers, "Set-Cookie").contains("laravel_session", Qt::CaseInsensitive)
            || xPoweredBy.contains("Laravel", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "fw-laravel",
                       "Detected: Laravel",
                       "laravel_session cookie / X-Powered-By");
        }
        if (headerOf(resp.headers, "Set-Cookie").contains("csrftoken=", Qt::CaseInsensitive)
            && headerOf(resp.headers, "Set-Cookie").contains("sessionid=", Qt::CaseInsensitive)) {
            addFinding(rowId, req, resp, "info", "fw-django",
                       "Detected: Django",
                       "csrftoken + sessionid cookies");
        }
        if (!headerOf(resp.headers, "X-Debug-Token").isEmpty()) {
            addFinding(rowId, req, resp, "info", "fw-symfony",
                       "Detected: Symfony",
                       "X-Debug-Token header");
        }
        if (bodyHead.contains("__INITIAL_STATE__") || bodyHead.contains("__APOLLO_STATE__")) {
            addFinding(rowId, req, resp, "info", "fw-spa-state-leak",
                       "Initial-state JSON inlined in HTML (review for PII)",
                       "__INITIAL_STATE__ / __APOLLO_STATE__ marker");
        }

        // =====================================================
        // CVE correlation. For each framework/CMS we already
        // fingerprinted, sniff a version string and look it up
        // in the static CVE table. Each match becomes its own
        // finding tagged with the CVE ID. Burp Pro doesn't do
        // this -- they sell it as a separate product.
        // =====================================================
        CveDatabase::HttpFingerprint fp;
        fp.server      = headerOf(resp.headers, "Server");
        fp.xPoweredBy  = xPoweredBy;
        fp.xGenerator  = genHdr;
        // Sniff version markers from the body. Patterns chosen
        // to match generator meta tags, Drupal.settings JSON,
        // wp-emoji src markers, NEXT_DATA build IDs, etc.
        static const QRegularExpression bodyVerRx(
            R"((?:WordPress|Drupal|Joomla|Magento|Sitecore|Next\.js|Express|Laravel|Django|Symfony)[\s\/-]?v?(\d+(?:\.\d+){1,3}))",
            QRegularExpression::CaseInsensitiveOption);
        const auto m = bodyVerRx.match(bodyHead);
        if (m.hasMatch()) fp.bodyVersion = m.captured(1);

        // Kinds we want CVE-correlated. Must match the kind we
        // emitted in detector findings above.
        static const QStringList cveKinds = {
            "cms-wordpress", "cms-drupal", "cms-magento", "cms-sitecore",
            "cms-confluence", "cms-jira",
            "fw-spring",   "fw-aspnet", "fw-express", "fw-nextjs",
            "fw-laravel",  "fw-django", "fw-symfony",
        };
        for (const QString &kind : cveKinds) {
            // Did we actually fire a finding of this kind on this
            // row? Cheap check: see if any pending finding in this
            // batch matches. We don't have a per-row index here,
            // so we just attempt the lookup whenever the
            // fingerprint sources mention the kind's vendor.
            const QString vendor = kind.section('-', 1, 1);
            const QString hay = (fp.bodyVersion + " " + fp.xGenerator + " "
                                 + fp.xPoweredBy + " " + fp.server).toLower();
            if (!hay.contains(vendor)) continue;
            const auto hits = CveDatabase::lookupByFingerprint(kind, fp);
            for (const auto &h : hits) {
                // Severity from CVSS base score -- but only for a version-CONFIRMED
                // match. An imprecise/manual-triage lead (version or range couldn't
                // be parsed) must never escalate to critical/high: a patched or
                // unknown host would otherwise read as a confirmed critical.
                const char *sev = !h.precise   ? "info"
                                : h.cvss >= 9.0 ? "critical"
                                : h.cvss >= 7.0 ? "high"
                                : h.cvss >= 4.0 ? "medium" : "low";
                addFinding(rowId, req, resp, sev, "cve-correlated",
                           QString("%1: %2").arg(h.cveId, h.summary),
                           QString("CVSS %1 %2 | affected: %3 | fix: %4 | ref: %5")
                               .arg(QString::number(h.cvss), h.cvssVector,
                                    h.affectedRange, h.fixVersion, h.reference));
            }
        }
    }
}

} // namespace Nullock::Core

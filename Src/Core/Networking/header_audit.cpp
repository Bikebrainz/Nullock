#include "header_audit.hpp"
#include "networking.hpp"

#include <QMap>
#include <QRegularExpression>
#include <QUrl>

namespace Nullock::Core::HeaderAudit {

namespace {

using Proxy::HttpResponse;

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}
QList<QString> allHeaderValues(const HttpResponse &r, const QString &name) {
    QList<QString> out;
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second;
    return out;
}

// Hosts that commonly serve JSONP endpoints or framework gadgets (AngularJS,
// etc.) usable to execute script under an allow-listing CSP. Allow-listing any
// of these in script-src effectively defeats the policy.
const QStringList &bypassableHosts() {
    static const QStringList h = {
        "ajax.googleapis.com", "www.google.com", "google.com",
        "accounts.google.com", "apis.google.com", "googleapis.com",
        "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
        "ajax.aspnetcdn.com", "cdn.ampproject.org", "*.amazonaws.com",
        "s3.amazonaws.com", "translate.google.com", "maps.googleapis.com",
    };
    return h;
}

// Split a CSP into a directive -> token-list map (lower-cased directive).
// Per the CSP spec the FIRST occurrence of a directive is enforced and later
// duplicates are ignored, so we keep the first (a naive last-wins would let
// "script-src 'unsafe-inline'; script-src 'self'" hide a real weakness).
QMap<QString, QStringList> parseCsp(const QString &csp) {
    QMap<QString, QStringList> out;
    for (const QString &part : csp.split(';', Qt::SkipEmptyParts)) {
        const QStringList toks = part.trimmed().split(QRegularExpression("\\s+"),
                                                       Qt::SkipEmptyParts);
        if (toks.isEmpty()) continue;
        const QString dir = toks.first().toLower();
        if (!out.contains(dir)) out.insert(dir, toks.mid(1));
    }
    return out;
}

QString hostOf(QString source) {
    // Strip scheme and path from a CSP source to get its host token.
    source = source.trimmed();
    const int s = source.indexOf("://");
    if (s >= 0) source = source.mid(s + 3);
    const int slash = source.indexOf('/');
    if (slash >= 0) source = source.left(slash);
    const int colon = source.indexOf(':');
    if (colon >= 0) source = source.left(colon);
    return source.toLower();
}

bool hostMatches(const QString &cspHost, const QString &gadget) {
    // A CSP-side wildcard (script-src *.googleapis.com) covers the gadget host.
    if (cspHost.startsWith("*.")) {
        const QString suffix = cspHost.mid(1); // ".googleapis.com"
        if (gadget == cspHost.mid(2) || gadget.endsWith(suffix)) return true;
    }
    if (gadget.startsWith("*.")) {
        const QString suffix = gadget.mid(1); // ".amazonaws.com"
        return cspHost == gadget.mid(2) || cspHost.endsWith(suffix);
    }
    return cspHost == gadget;
}

void auditCsp(const QString &csp, bool reportOnly, Result &result) {
    const auto dirs = parseCsp(csp);
    // The effective script source list: script-src, else default-src.
    const bool hasScriptSrc = dirs.contains("script-src");
    const QStringList script = hasScriptSrc ? dirs.value("script-src")
                                            : dirs.value("default-src");
    const QString ctx = reportOnly ? " (report-only -- not enforced)" : "";
    auto add = [&](const QString &k, const QString &sev, const QString &t, const QString &d) {
        result.findings.append({ k, sev, t, d + ctx });
    };

    // A nonce or hash makes supporting browsers ignore 'unsafe-inline', so an
    // attacker's injected inline script (which can't guess the nonce) is still
    // blocked -- 'strict-dynamic' is not required for that suppression.
    bool hasNonceOrHash = false;
    for (const QString &tok : script) {
        const QString t = tok.toLower();
        if (t.startsWith("'nonce-") || t.startsWith("'sha")) hasNonceOrHash = true;
    }
    for (const QString &tok : script) {
        const QString t = tok.toLower();
        if (t == "'unsafe-inline'" && !hasNonceOrHash)
            add("csp-unsafe-inline", "high",
                "CSP allows 'unsafe-inline' scripts",
                "inline script executes freely; add a per-response nonce/hash "
                "(ideally with 'strict-dynamic') so injected markup can't run");
        if (t == "'unsafe-eval'")
            add("csp-unsafe-eval", "medium", "CSP allows 'unsafe-eval'",
                "string-to-code APIs (eval, new Function) remain available to an attacker");
        if (t == "*" || t == "http:" || t == "https:" || t == "data:")
            add("csp-wildcard-source", "high",
                "CSP script source is wildcard/scheme-wide (" + tok + ")",
                "any host (or any data: URI) may supply script -- the allow-list is meaningless");
    }
    // Bypassable allow-listed hosts.
    for (const QString &tok : script) {
        const QString host = hostOf(tok);
        if (host.isEmpty()) continue;
        for (const QString &g : bypassableHosts())
            if (hostMatches(host, g)) {
                add("csp-bypassable-host", "medium",
                    "CSP allow-lists a script-gadget host (" + host + ")",
                    "this host serves JSONP/framework gadgets that run script under the policy");
                break;
            }
    }
    if (!script.isEmpty() && script.first().toLower() != "'none'") {
        const QString objectSrc = dirs.value("object-src").join(' ').toLower();
        if (!dirs.contains("object-src") || (!objectSrc.contains("'none'")))
            add("csp-no-object-src", "low", "CSP has no object-src 'none'",
                "plugins/<object> can be a script-execution / data-exfil vector");
        if (!dirs.contains("base-uri"))
            add("csp-no-base-uri", "medium", "CSP has no base-uri",
                "an injected <base> tag can re-root relative script URLs to an attacker host");
    }
    if (reportOnly) result.reportOnlyOnly = true;
}

QByteArray buildRequest(const Request &req) {
    const QString target = req.query.isEmpty() ? req.basePath
                                               : req.basePath + "?" + req.query;
    QByteArray out;
    out  = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/header-audit\r\n";
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

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    Request cur = req;
    HttpResponse resp;
    bool effTls = req.tls;
    bool got = false;
    // Follow up to two SAME-ORIGIN redirects so we audit the real landing
    // page's headers, not a header-bare 301 stub. Off-origin redirects stop
    // the chain (we only audit the host we were asked about).
    for (int hop = 0; hop <= 2; ++hop) {
        ++result.requestsSent;
        const auto r = client.send(cur.host, static_cast<quint16>(cur.port),
                                   effTls, buildRequest(cur));
        if (!r.ok) {
            if (got) break;
            result.error = "request failed: " + r.errorMessage;
            return result;
        }
        resp = r.parsed; got = true;
        if (resp.statusCode < 300 || resp.statusCode >= 400) break;
        const QString loc = headerValue(resp, "Location");
        if (loc.isEmpty()) break;
        QUrl base;
        base.setScheme(effTls ? "https" : "http");
        base.setHost(cur.host); base.setPort(cur.port);
        base.setPath(cur.basePath.isEmpty() ? "/" : cur.basePath);
        const QUrl next = base.resolved(QUrl(loc, QUrl::TolerantMode));
        if (next.host().compare(req.host, Qt::CaseInsensitive) != 0) break; // off-origin
        effTls = (next.scheme() == "https");
        cur.host = next.host();
        cur.port = next.port(effTls ? 443 : 80);
        cur.basePath = next.path().isEmpty() ? QStringLiteral("/") : next.path();
        cur.query = next.query(QUrl::FullyEncoded);
    }
    result.status = resp.statusCode;

    auto add = [&](const QString &k, const QString &sev, const QString &t, const QString &d) {
        result.findings.append({ k, sev, t, d });
    };

    // ---- Content-Security-Policy ----
    const QString csp = headerValue(resp, "Content-Security-Policy");
    const QString cspRO = headerValue(resp, "Content-Security-Policy-Report-Only");
    result.hasCsp = !csp.isEmpty();
    if (!csp.isEmpty()) {
        auditCsp(csp, false, result);
    } else if (!cspRO.isEmpty()) {
        result.reportOnlyOnly = true;
        add("csp-report-only", "low", "CSP is report-only (not enforced)",
            "the policy logs violations but does not block them");
        auditCsp(cspRO, true, result);
    } else {
        add("csp-missing", "medium", "No Content-Security-Policy",
            "a CSP is the primary defense-in-depth against injected script");
    }

    // ---- Transport / sniffing / framing ----
    if (effTls) {
        const QString hsts = headerValue(resp, "Strict-Transport-Security");
        if (hsts.isEmpty())
            add("hsts-missing", "medium", "No HSTS on an https response",
                "without HSTS a MITM can strip TLS on the first / subsequent visit");
        else {
            const QRegularExpression ma("max-age\\s*=\\s*(\\d+)",
                                        QRegularExpression::CaseInsensitiveOption);
            const auto m = ma.match(hsts);
            const long long age = m.hasMatch() ? m.captured(1).toLongLong() : 0;
            if (age < 15552000)
                add("hsts-weak", "low", "HSTS max-age is short (<180d)",
                    "a short max-age narrows the protection window");
            if (!hsts.contains("includeSubDomains", Qt::CaseInsensitive))
                add("hsts-no-subdomains", "low", "HSTS lacks includeSubDomains",
                    "subdomains remain strippable");
        }
    }
    const QString xcto = headerValue(resp, "X-Content-Type-Options");
    if (!xcto.contains("nosniff", Qt::CaseInsensitive))
        add("xcto-missing", "low", "No X-Content-Type-Options: nosniff",
            "MIME sniffing can turn an uploaded/served file into executable script");

    const QString xfo = headerValue(resp, "X-Frame-Options");
    const bool frameAncestors = csp.contains("frame-ancestors", Qt::CaseInsensitive)
                             || cspRO.contains("frame-ancestors", Qt::CaseInsensitive);
    if (xfo.isEmpty() && !frameAncestors)
        add("clickjacking-missing", "medium", "No clickjacking defense",
            "neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed");

    if (headerValue(resp, "Referrer-Policy").isEmpty())
        add("referrer-policy-missing", "low", "No Referrer-Policy",
            "full URLs (with tokens in query) may leak to third parties via Referer");

    // ---- Set-Cookie flags ----
    // Match attribute *keys* (the ';'-separated segments after name=value), not
    // a substring over the whole line -- else a value like sid=secure123 would
    // be read as having the Secure flag.
    int cookieFindings = 0;
    for (const QString &sc : allHeaderValues(resp, "Set-Cookie")) {
        const QStringList segs = sc.split(';');
        if (segs.isEmpty()) continue;
        const QString name = segs.first().section('=', 0, 0).trimmed();
        QStringList attrs;
        for (int i = 1; i < segs.size(); ++i)
            attrs << segs[i].section('=', 0, 0).trimmed().toLower();
        QStringList missing;
        if (effTls && !attrs.contains("secure")) missing << "Secure";
        if (!attrs.contains("httponly"))          missing << "HttpOnly";
        if (!attrs.contains("samesite"))          missing << "SameSite";
        if (!missing.isEmpty() && cookieFindings++ < 10)
            add("cookie-insecure", missing.contains("HttpOnly") ? "medium" : "low",
                "Cookie '" + name + "' missing " + missing.join(", "),
                "session cookies need Secure + HttpOnly + SameSite to resist theft/CSRF");
    }

    return result;
}

} // namespace Nullock::Core::HeaderAudit

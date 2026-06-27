// Pure security-header / CSP analysis, split out of header_audit.cpp so a unit
// test can link it (via Networking) against Qt6::Core alone -- test() and its
// HttpClient (the Qt6::Network chain via Proxy::HttpResponse) stay in
// header_audit.cpp. Mirrors the established sibling pattern (waf_detect_logic.cpp,
// method_audit_logic.cpp, ...). Everything here is I/O-free: it operates on an
// already-fetched header list (a QList<QPair<QString,QString>>), the effective
// TLS flag, and a plain Result struct.

#include "header_audit.hpp"

#include <QMap>
#include <QRegularExpression>

namespace Nullock::Core::HeaderAudit {

namespace {

using Headers = QList<QPair<QString, QString>>;

QString headerValue(const Headers &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}
QList<QString> allHeaderValues(const Headers &headers, const QString &name) {
    QList<QString> out;
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second;
    return out;
}

// Hosts that commonly serve JSONP endpoints or framework gadgets (AngularJS,
// etc.) usable to execute script under an allow-listing CSP. Allow-listing any
// of these in script-src effectively defeats the policy.
const QStringList &bypassableHostList() {
    static const QStringList h = {
        "ajax.googleapis.com", "www.google.com", "google.com",
        "accounts.google.com", "apis.google.com", "googleapis.com",
        "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
        "ajax.aspnetcdn.com", "cdn.ampproject.org", "*.amazonaws.com",
        "s3.amazonaws.com", "translate.google.com", "maps.googleapis.com",
    };
    return h;
}

} // namespace

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

    // No script-src AND no default-src => script execution is entirely
    // ungoverned (inline, eval, and any external script all run). That is no
    // better than a missing CSP, yet the per-token loops below would find
    // nothing -- so surface it explicitly as a high finding.
    if (!hasScriptSrc && !dirs.contains("default-src"))
        add("csp-no-script-restriction", "high",
            "CSP sets no script-src and no default-src",
            "script execution is entirely unrestricted -- inline scripts, eval, "
            "and any external script run; this policy provides no XSS mitigation");

    // A nonce or hash makes supporting browsers ignore 'unsafe-inline', so an
    // attacker's injected inline script (which can't guess the nonce) is still
    // blocked -- 'strict-dynamic' is not required for that suppression. Require a
    // well-formed hash algorithm so a malformed 'sha... token can't silently
    // suppress the unsafe-inline finding.
    bool hasNonceOrHash = false;
    for (const QString &tok : script) {
        const QString t = tok.toLower();
        if (t.startsWith("'nonce-") || t.startsWith("'sha256-")
            || t.startsWith("'sha384-") || t.startsWith("'sha512-")) hasNonceOrHash = true;
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
        // Flag bare schemes (https:/http:/data:) and any host-component-'*'
        // source -- "*", "https://*", "http://*" all allow script from every
        // host, so an exact "*" test alone would miss the scheme-prefixed forms.
        if (t == "*" || t == "http:" || t == "https:" || t == "data:" || hostOf(tok) == "*")
            add("csp-wildcard-source", "high",
                "CSP script source is wildcard/scheme-wide (" + tok + ")",
                "any host (or any data: URI) may supply script -- the allow-list is meaningless");
    }
    // Bypassable allow-listed hosts.
    for (const QString &tok : script) {
        const QString host = hostOf(tok);
        if (host.isEmpty()) continue;
        for (const QString &g : bypassableHostList())
            if (hostMatches(host, g)) {
                add("csp-bypassable-host", "medium",
                    "CSP allow-lists a script-gadget host (" + host + ")",
                    "this host serves JSONP/framework gadgets that run script under the policy");
                break;
            }
    }
    // Flag a missing object-src/base-uri unless script-src is exactly 'none'
    // (which already blocks all script). An EMPTY effective script list means no
    // governance -- still flag these (the no-script-restriction high is added
    // above, and these are real additional gaps).
    if (script.isEmpty() || script.first().toLower() != "'none'") {
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

// Does an ENFORCED CSP carry a frame-ancestors that actually restricts framing?
// A permissive list (*, a scheme, or a host-component '*') does NOT protect, and
// a report-only policy never blocks, so only the enforced CSP is consulted.
static bool frameAncestorsProtective(const QString &enforcedCsp) {
    if (enforcedCsp.isEmpty()) return false;
    const auto dirs = parseCsp(enforcedCsp);
    if (!dirs.contains("frame-ancestors")) return false;
    const QStringList fa = dirs.value("frame-ancestors");
    if (fa.isEmpty()) return false;                 // "frame-ancestors;" governs nothing
    for (const QString &s : fa) {
        const QString t = s.toLower();
        if (t == "*" || t == "http:" || t == "https:" || hostOf(s) == "*")
            return false;                           // permissive -> not protective
    }
    return true;                                    // 'none', 'self', or explicit origins
}

// Audit an already-fetched response's security headers. Pure: no network I/O.
// effTls is whether the (final, post-redirect) request was https.
void analyze(const Headers &headers, bool effTls, Result &result) {
    auto add = [&](const QString &k, const QString &sev, const QString &t, const QString &d) {
        result.findings.append({ k, sev, t, d });
    };

    // ---- Content-Security-Policy ----
    const QString csp = headerValue(headers, "Content-Security-Policy");
    const QString cspRO = headerValue(headers, "Content-Security-Policy-Report-Only");
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
        const QString hsts = headerValue(headers, "Strict-Transport-Security");
        if (hsts.isEmpty())
            add("hsts-missing", "medium", "No HSTS on an https response",
                "without HSTS a MITM can strip TLS on the first / subsequent visit");
        else {
            // RFC 6797 allows a quoted value: max-age="31536000". Tolerate the
            // optional opening quote so a strong quoted policy isn't mis-graded.
            const QRegularExpression ma("max-age\\s*=\\s*\"?(\\d+)",
                                        QRegularExpression::CaseInsensitiveOption);
            const auto m = ma.match(hsts);
            const bool hasMaxAge = m.hasMatch();
            const long long age = hasMaxAge ? m.captured(1).toLongLong() : 0;
            if (!hasMaxAge)
                add("hsts-invalid", "medium", "HSTS header has no valid max-age",
                    "an HSTS header without a max-age directive is ignored -- equivalent to no HSTS");
            else if (age == 0)
                add("hsts-disabled", "medium", "HSTS is disabled (max-age=0)",
                    "max-age=0 tells browsers to forget the HSTS policy -- equivalent to no HSTS");
            else if (age < 15552000)
                add("hsts-weak", "low", "HSTS max-age is short (<180d)",
                    "a short max-age narrows the protection window");
            // includeSubDomains only matters while HSTS is actually in force.
            if (hasMaxAge && age > 0
                && !hsts.contains("includeSubDomains", Qt::CaseInsensitive))
                add("hsts-no-subdomains", "low", "HSTS lacks includeSubDomains",
                    "subdomains remain strippable");
        }
    }
    const QString xcto = headerValue(headers, "X-Content-Type-Options");
    if (!xcto.contains("nosniff", Qt::CaseInsensitive))
        add("xcto-missing", "low", "No X-Content-Type-Options: nosniff",
            "MIME sniffing can turn an uploaded/served file into executable script");

    // Only DENY / SAMEORIGIN actually protect; ALLOWALL, the deprecated/ignored
    // ALLOW-FROM, an empty value, or any bogus token leaves the page framable.
    const QString xfoNorm = headerValue(headers, "X-Frame-Options").trimmed().toLower();
    const bool xfoProtects = (xfoNorm == "deny" || xfoNorm == "sameorigin");
    // Only the ENFORCED CSP's frame-ancestors blocks framing (report-only never
    // does), and only when its source list is restrictive.
    const bool faProtects = frameAncestorsProtective(csp);
    if (!xfoProtects && !faProtects)
        add("clickjacking-missing", "medium", "No effective clickjacking defense",
            "no protecting X-Frame-Options (DENY/SAMEORIGIN) and no restrictive "
            "CSP frame-ancestors; the page can be framed for clickjacking");

    if (headerValue(headers, "Referrer-Policy").isEmpty())
        add("referrer-policy-missing", "low", "No Referrer-Policy",
            "full URLs (with tokens in query) may leak to third parties via Referer");

    // ---- Modern defense-in-depth headers (low/info) ----
    // None of these enable a direct attack on their own, so they stay low: each
    // just closes a real gap (powerful-feature abuse, cross-window / Spectre-
    // class isolation, legacy Flash/PDF cross-domain trust). Kept quiet so they
    // inform without drowning the higher-signal CSP/HSTS/cookie findings. Kind
    // names mirror the passive scanner's so both paths share enricher mappings.
    if (headerValue(headers, "Permissions-Policy").isEmpty()
        && headerValue(headers, "Feature-Policy").isEmpty())
        add("missing-permissions-policy", "low", "No Permissions-Policy",
            "powerful features (camera/microphone/geolocation, etc.) are not "
            "restricted; neither Permissions-Policy nor the legacy Feature-Policy is set");

    // COOP only governs a *document's* opener relationship, so flag it only on an
    // HTML response -- firing it on a JSON/API/image reply would be noise.
    const bool isHtml =
        headerValue(headers, "Content-Type").contains("text/html", Qt::CaseInsensitive);
    if (isHtml && headerValue(headers, "Cross-Origin-Opener-Policy").isEmpty())
        add("missing-coop", "low", "No Cross-Origin-Opener-Policy",
            "a cross-origin opener keeps a window reference to this document, "
            "enabling cross-window attacks and defeating Spectre-class process "
            "isolation; set Cross-Origin-Opener-Policy: same-origin");

    if (headerValue(headers, "Cross-Origin-Embedder-Policy").isEmpty())
        add("missing-coep", "low", "No Cross-Origin-Embedder-Policy",
            "COEP (with COOP) is required for cross-origin isolation; without it "
            "the document can't use isolation-gated APIs and shares a process "
            "with cross-origin subresources");

    if (headerValue(headers, "Cross-Origin-Resource-Policy").isEmpty())
        add("missing-corp", "low", "No Cross-Origin-Resource-Policy",
            "the response carries no CORP, so other origins may embed/read it; "
            "set Cross-Origin-Resource-Policy: same-origin on sensitive resources");

    if (headerValue(headers, "X-Permitted-Cross-Domain-Policies").isEmpty())
        add("missing-permitted-cross-domain-policies", "low",
            "No X-Permitted-Cross-Domain-Policies",
            "legacy Flash/Acrobat cross-domain policy is unrestricted; set 'none' "
            "to deny cross-domain data loads (minor on modern stacks)");

    // ---- Set-Cookie flags ----
    // Match attribute *keys* (the ';'-separated segments after name=value), not
    // a substring over the whole line -- else a value like sid=secure123 would
    // be read as having the Secure flag.
    int cookieFindings = 0;
    for (const QString &sc : allHeaderValues(headers, "Set-Cookie")) {
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
}

QByteArray buildRequest(const Request &req) {
    // Self-protect the request line + Host against CR/LF regardless of caller (a
    // deep-audit path could carry a crafted host/basePath/query).
    QString host = req.host;          host.remove('\r'); host.remove('\n');
    QString basePath = req.basePath;  basePath.remove('\r'); basePath.remove('\n');
    QString query = req.query;        query.remove('\r'); query.remove('\n');
    const QString target = query.isEmpty() ? basePath : basePath + "?" + query;
    QByteArray out;
    out  = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
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

} // namespace Nullock::Core::HeaderAudit

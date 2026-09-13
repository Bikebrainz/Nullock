// Pure security-header / CSP analysis, split out of header_audit.cpp so a unit
// test can link it (via Networking) against Qt6::Core alone -- test() and its
// HttpClient (the Qt6::Network chain via Proxy::HttpResponse) stay in
// header_audit.cpp. Mirrors the established sibling pattern (waf_detect_logic.cpp,
// method_audit_logic.cpp, ...). Everything here is I/O-free: it operates on an
// already-fetched header list (a QList<QPair<QString,QString>>), the effective
// TLS flag, and a plain Result struct.

#include "header_audit.hpp"
#include "csp_intersection.hpp"

#include <QMap>
#include <QRegularExpression>

#include <limits>

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

QStringList cspPolicies(const Headers &headers, const QString &name) {
    QStringList policies;
    for (const auto &value : allHeaderValues(headers, name))
        for (const auto &policy : value.split(','))
            if (!policy.trimmed().isEmpty()) policies.append(policy.trimmed());
    return policies;
}

// Hosts that commonly serve JSONP endpoints or framework gadgets (AngularJS,
// etc.) potentially usable to execute script under an allow-listing CSP.
// A matching URL and the target's full policy still require verification.
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
        if (gadget.endsWith(suffix)) return true;
    }
    if (gadget.startsWith("*.")) {
        const QString suffix = gadget.mid(1); // ".amazonaws.com"
        return cspHost.endsWith(suffix);
    }
    return cspHost == gadget;
}

void auditCsp(const QString &csp, bool reportOnly, Result &result) {
    const auto dirs = parseCsp(csp);
    const QString scriptDirective = dirs.contains("script-src") ? "script-src" : "default-src";
    const QStringList script = dirs.value(scriptDirective);
    const QString elementDirective = dirs.contains("script-src-elem") ? "script-src-elem" : scriptDirective;
    const QString attributeDirective = dirs.contains("script-src-attr") ? "script-src-attr" : scriptDirective;
    const QStringList element = dirs.value(elementDirective);
    const QStringList attribute = dirs.value(attributeDirective);
    const QString ctx = reportOnly ? " (report-only -- not enforced)" : "";
    auto add = [&](const QString &k, const QString &sev, const QString &t, const QString &d) {
        result.findings.append({ k, sev, t, d + ctx });
    };
    auto alreadyReported = [&result](const QString &key) {
        for (const auto &f : result.findings) if (f.key == key) return true;
        return false;
    };
    auto hasKeyword = [](const QStringList &sources, const char *keyword) {
        for (const QString &source : sources)
            if (source.toLower() == QLatin1String(keyword)) return true;
        return false;
    };
    auto effectivelyNone = [&](const QStringList &sources) {
        return sources.size() == 1 && hasKeyword(sources, "'none'");
    };
    auto listIsPermissive = [](const QStringList &sources) {
        for (const QString &source : sources) {
            const QString token = source.toLower();
            if (token == "*" || token == "http:" || token == "https:" || token == "data:" || hostOf(source) == "*")
                return true;
        }
        return false;
    };
    auto hasValidNonceOrHash = [](const QStringList &sources) {
        // ASCII source grammar; neither arbitrary punctuation nor Unicode
        // case-fold equivalents count as Base64 characters.
        static const QRegularExpression sourcePattern(
            "\\A'([Nn][Oo][Nn][Cc][Ee]|[Ss][Hh][Aa]-?(?:256|384|512))-([A-Za-z0-9+/_-]+={0,2})'\\z");
        for (const QString &source : sources) {
            const auto match = sourcePattern.match(source);
            if (!match.hasMatch()) continue;
            // Nonces are opaque strings: no byte decoding or minimum length.
            if (match.captured(1).toLower() == "nonce") return true;
            QByteArray encoded = match.captured(2).toLatin1();
            encoded.replace('-', '+');
            encoded.replace('_', '/');
            while (encoded.size() % 4 != 0) encoded.append('=');
            // Browsers reject undecodable hashes, but a decodable short hash
            // still suppresses unsafe-inline even though it cannot match SHA.
            if (QByteArray::fromBase64Encoding(encoded, QByteArray::AbortOnBase64DecodingErrors))
                return true;
        }
        return false;
    };

    if (!dirs.contains("script-src") && !dirs.contains("default-src"))
        add("csp-no-script-restriction", "high",
            "CSP sets no script-src and no default-src",
            "eval has no CSP restriction; script contexts without their own "
            "script-src-elem/script-src-attr directive are also unrestricted");

    // Element and attribute overrides apply only in their own contexts. An
    // overridden permissive base list cannot authorize those inline operations.
    auto auditInline = [&](const QStringList &sources, const QString &directive) {
        if (hasKeyword(sources, "'unsafe-inline'")
            && !hasValidNonceOrHash(sources) && !hasKeyword(sources, "'strict-dynamic'")
            && !alreadyReported("csp-unsafe-inline"))
            add("csp-unsafe-inline", "high", "CSP allows 'unsafe-inline' scripts via " + directive,
                directive + " permits inline script in its effective context; "
                "use a valid per-response nonce/hash instead");
    };
    auditInline(element, elementDirective);
    auditInline(attribute, attributeDirective);

    // eval uses script-src/default-src, never the element or attribute overrides.
    if (hasKeyword(script, "'unsafe-eval'"))
        add("csp-unsafe-eval", "medium", "CSP allows 'unsafe-eval'",
            "string-to-code APIs (eval, new Function) remain available to an attacker");

    // Only the effective element list governs external <script> URLs. With
    // strict-dynamic, host/scheme sources do not authorize parser-inserted scripts.
    if (!hasKeyword(element, "'strict-dynamic'")) {
        for (const QString &token : element) {
            if (listIsPermissive(QStringList{token}) && !alreadyReported("csp-wildcard-source"))
                add("csp-wildcard-source", "high",
                    "CSP script source is wildcard/scheme-wide via " + elementDirective + " (" + token + ")",
                    "the effective element policy allows external scripts from broad sources");
            const QString host = hostOf(token);
            if (host.isEmpty() || alreadyReported("csp-bypassable-host")) continue;
            for (const QString &gadget : bypassableHostList()) {
                if (hostMatches(host, gadget)) {
                    add("csp-bypassable-host", "medium",
                        "CSP allow-lists a script-gadget host via " + elementDirective + " (" + host + ")",
                        "this host may serve JSONP/framework gadgets; verify whether an allowed URL supplies executable script");
                    break;
                }
            }
        }
    }

    // Retain the hardening checks unless both effective inline contexts are
    // explicitly 'none'. A permissive element override must not inherit an
    // exemption from script-src 'none'; mixed lists ignore the 'none' token.
    if (!effectivelyNone(element) || !effectivelyNone(attribute)) {
        // Same rule for object-src: a bare contains("'none'") credited
        // "object-src 'none' https://evil.tld" as blocking.
        if (!effectivelyNone(dirs.value("object-src")))
            add("csp-no-object-src", "low", "CSP has no object-src 'none'",
                "plugins/<object> can be a script-execution / data-exfil vector");
        // base-uri was PRESENCE-only, so a fully permissive "base-uri *" suppressed
        // the very finding it exists to raise -- an injected <base> can still re-root
        // relative script URLs. Require an actually-restrictive source list.
        const QStringList baseUri = dirs.value("base-uri");
        if (!dirs.contains("base-uri"))
            add("csp-no-base-uri", "medium", "CSP has no base-uri",
                "an injected <base> tag can re-root relative script URLs to an attacker host");
        else if (listIsPermissive(baseUri))
            add("csp-no-base-uri", "medium",
                "CSP base-uri is permissive (" + baseUri.join(' ') + ")",
                "a wildcard/scheme-wide base-uri does not constrain <base>, so an "
                "injected tag can still re-root relative script URLs to an attacker host");
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
    if (fa.isEmpty()) return true;                  // empty source list blocks all ancestors
    for (const QString &s : fa) {
        const QString t = s.toLower();
        if (t == "*" || t == "http:" || t == "https:" || hostOf(s) == "*")
            return false;                           // permissive -> not protective
    }
    return true;                                    // 'none', 'self', or explicit origins
}

// Audit an already-fetched response's security headers. Pure: no network I/O.
// effTls is whether the (final, post-redirect) request was https.
void analyze(const Headers &headers, bool effTls, Result &result, const QUrl &origin) {
    auto add = [&](const QString &k, const QString &sev, const QString &t, const QString &d) {
        result.findings.append({ k, sev, t, d });
    };

    // ---- Content-Security-Policy ----
    const QStringList csp = cspPolicies(headers, "Content-Security-Policy");
    const QStringList cspRO = cspPolicies(headers, "Content-Security-Policy-Report-Only");
    auto auditPolicies = [&](const QStringList &policies, bool reportOnly) {
        if (policies.size() == 1) auditCsp(policies.first(), reportOnly, result);
        else auditCspIntersection(policies, reportOnly, origin, effTls, result);
    };
    result.hasCsp = !csp.isEmpty();
    if (!csp.isEmpty()) {
        auditPolicies(csp, false);
    } else if (!cspRO.isEmpty()) {
        result.reportOnlyOnly = true;
        add("csp-report-only", "low", "CSP is report-only (not enforced)",
            "the policy logs violations but does not block them");
        auditPolicies(cspRO, true);
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
            // A max-age that overflows qint64 (a 20+ digit value) is a valid,
            // effectively-permanent policy -- a bare toLongLong() returns 0, so it
            // would be mis-graded as hsts-disabled AND skip the subdomain check.
            // Capture the ok flag and saturate an overflow to a large positive age.
            bool maxAgeOk = false;
            long long age = hasMaxAge ? m.captured(1).toLongLong(&maxAgeOk) : 0;
            if (hasMaxAge && !maxAgeOk) age = std::numeric_limits<long long>::max();
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
    // Every enforced policy applies. Any enforced frame-ancestors directive
    // overrides XFO, even when that directive allows arbitrary ancestors.
    bool hasFrameAncestors = false, faProtects = false;
    for (const auto &policy : csp) {
        hasFrameAncestors |= parseCsp(policy).contains("frame-ancestors");
        faProtects |= frameAncestorsProtective(policy);
    }
    bool frameUnresolved = false;
    if (hasFrameAncestors && !faProtects && csp.size() > 1) {
        const auto combined = cspFrameAncestorsProtective(csp, origin, effTls);
        if (combined) faProtects = *combined;
        else {
            frameUnresolved = true;
            bool reported = false;
            for (const auto &f : result.findings) reported |= f.key == "csp-analysis-incomplete";
            if (!reported) add("csp-analysis-incomplete", "info", "CSP ancestor intersection needs further review",
                "The bounded URL-source analysis could not resolve the complete ancestor list; review framing with the full response context.");
        }
    }
    if (!frameUnresolved && !(hasFrameAncestors ? faProtects : xfoProtects))
        add("clickjacking-missing", "medium", "No effective clickjacking defense",
            "no restrictive enforced CSP frame-ancestors, or protecting "
            "X-Frame-Options when frame-ancestors is absent");

    // Presence alone is not protection: "unsafe-url" deliberately sends the FULL URL
    // (query and all) to every destination, which is exactly the leak this finding
    // exists to raise -- so the weakest possible value used to SUPPRESS it.
    {
        const QString rp = headerValue(headers, "Referrer-Policy").trimmed().toLower();
        if (rp.isEmpty())
            add("referrer-policy-missing", "low", "No Referrer-Policy",
                "full URLs (with tokens in query) may leak to third parties via Referer");
        else if (rp.split(',').last().trimmed() == QLatin1String("unsafe-url"))
            add("referrer-policy-unsafe", "low", "Referrer-Policy: unsafe-url",
                "unsafe-url sends the full URL (including query tokens) to every "
                "destination -- weaker than having no policy on modern browsers");
    }

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
        QString sameSiteValue;
        for (int i = 1; i < segs.size(); ++i) {
            const QString aName = segs[i].section('=', 0, 0).trimmed().toLower();
            attrs << aName;
            if (aName == QLatin1String("samesite"))
                sameSiteValue = segs[i].section('=', 1).trimmed().toLower();
        }
        // SameSite=None is the ONE value that grants no cross-site protection at all
        // (it explicitly opts INTO cross-site sending). A presence-only check credited
        // it as protection, so the weakest possible setting silenced the finding.
        const bool sameSiteNone = sameSiteValue == QLatin1String("none");
        QStringList missing;
        if (effTls && !attrs.contains("secure")) missing << "Secure";
        if (!attrs.contains("httponly"))          missing << "HttpOnly";
        if (!attrs.contains("samesite"))          missing << "SameSite";
        else if (sameSiteNone)                    missing << "effective SameSite (set to None)";
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
    if (basePath.isEmpty()) basePath = QStringLiteral("/");   // else "GET  HTTP/1.1" (malformed)
    const QString target = query.isEmpty() ? basePath : basePath + "?" + query;
    QByteArray out;
    out  = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/header-audit\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers that fight the ones this body-less GET
        // forces (Accept-Encoding: identity above, Connection: close below):
        //  - Content-Length / Transfer-Encoding: advertise a body that is never sent,
        //    so the server waits for it (probe stalls) or the socket desyncs.
        //  - Accept-Encoding: a carried "gzip,..." combines (RFC 9112 7.4) and lets the
        //    server compress, defeating the forced identity the analysis depends on.
        //  - Connection: a carried "keep-alive" contradicts the forced close.
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

bool isSameOriginRedirect(bool curTls, const QString &curHost, int curPort,
                          const QUrl &next) {
    const QString sc = next.scheme().toLower();
    if (sc != QLatin1String("http") && sc != QLatin1String("https"))
        return false;                          // non-http(s) target is never same-origin
    const bool nextTls  = (sc == QLatin1String("https"));
    const int  nextPort = next.port(nextTls ? 443 : 80);
    return nextTls == curTls
        && next.host().compare(curHost, Qt::CaseInsensitive) == 0
        && nextPort == curPort;
}

} // namespace Nullock::Core::HeaderAudit

#include "csp_intersection.hpp"

#include <QRegularExpression>
#include <algorithm>
#include <optional>

namespace Nullock::Core::HeaderAudit {
namespace {
using Directives = QMap<QString, QStringList>;

bool keyword(const QStringList &list, const char *word) {
    return list.contains(QLatin1String(word), Qt::CaseInsensitive);
}

QString effective(const Directives &dirs, const QString &context) {
    if (dirs.contains(context)) return context;
    if (context.startsWith("script-src-") && dirs.contains("script-src")) return "script-src";
    return "default-src";
}

// Each range is a set of initial HTTP(S)/data URLs. Host '*' is universal;
// '*.example' excludes the bare domain. Port -1 is universal. Path decoding
// includes Chromium's encoded-slash behavior (covered by browser fixtures).
struct Range {
    QString scheme, host;
    int port = -1;
    QList<QByteArray> path;
    bool prefix = true;
};
struct Sources {
    QList<Range> ranges;
    bool unknown = false;
};

int defaultPort(const QString &scheme) { return scheme == "https" ? 443 : 80; }

Sources universe() {
    return {{{"http", "*"}, {"https", "*"}, {"data", "*"}}, false};
}

bool hostSubset(const QString &a, const QString &b) {
    if (b == "*" || a == b) return true;
    if (!b.startsWith("*.")) return false;
    return a.endsWith(b.mid(1));
}

bool pathSubset(const Range &a, const Range &b) {
    if (!b.prefix) return !a.prefix && a.path == b.path;
    if (a.path.size() < b.path.size()) return false;
    // /dir is not inside the /dir/ prefix: the directory slash matters.
    if (!a.prefix && a.path.size() == b.path.size() && !b.path.isEmpty()) return false;
    for (qsizetype i = 0; i < b.path.size(); ++i)
        if (a.path[i] != b.path[i]) return false;
    return true;
}

std::optional<Range> intersect(const Range &a, const Range &b) {
    if (a.scheme != b.scheme) return {};
    Range r = a;
    if (hostSubset(a.host, b.host)) r.host = a.host;
    else if (hostSubset(b.host, a.host)) r.host = b.host;
    else return {};
    if (a.port != -1 && b.port != -1 && a.port != b.port) return {};
    r.port = a.port == -1 ? b.port : a.port;
    if (pathSubset(a, b)) { r.path = a.path; r.prefix = a.prefix; }
    else if (pathSubset(b, a)) { r.path = b.path; r.prefix = b.prefix; }
    else return {};
    return r;
}

Sources intersect(const Sources &a, const Sources &b, int &budget) {
    if ((!a.unknown && a.ranges.isEmpty()) || (!b.unknown && b.ranges.isEmpty())) return {};
    Sources out;
    out.unknown = a.unknown || b.unknown;
    for (const auto &left : a.ranges) for (const auto &right : b.ranges) {
        if (--budget < 0 || out.ranges.size() >= 4096) return {{}, true};
        if (auto r = intersect(left, right)) out.ranges.append(*r);
    }
    return out;
}

Sources sources(const QStringList &list, const QUrl &origin, bool tls) {
    Sources out;
    static const QRegularExpression hostSource(
        R"(\A(?:([A-Za-z][A-Za-z0-9+.-]*)://)?(\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.?)(?::(\*|[0-9]+))?(/[^\s?#]*)?\z)");
    static const QRegularExpression schemeSource(R"(\A[A-Za-z][A-Za-z0-9+.-]*:\z)");
    for (const QString &token : list) {
        if (out.ranges.size() >= 4096) return {{}, true};
        const QString lower = token.toLower();
        if (lower == "*") {
            out.ranges.append(Range{"http", "*"}); out.ranges.append(Range{"https", "*"});
            continue;
        }
        if (lower == "'self'") {
            if (origin.host().isEmpty()) { out.unknown = true; continue; }
            const QString scheme = origin.scheme().toLower();
            if (scheme != "http" && scheme != "https") { out.unknown = true; continue; }
            const int port = origin.port(defaultPort(scheme));
            out.ranges.append(Range{scheme, origin.host().toLower(), port});
            if (scheme == "http") {
                out.ranges.append(Range{"https", origin.host().toLower(), port});
                if (port == 80) out.ranges.append(Range{"https", origin.host().toLower(), 443});
            }
            continue;
        }
        if (schemeSource.match(token).hasMatch()) {
            const QString scheme = lower.chopped(1);
            if (scheme == "http") out.ranges.append(Range{"https", "*"});
            if (scheme == "http" || scheme == "https" || scheme == "data")
                out.ranges.append(Range{scheme, "*"});
            // Other schemes do not supply an HTTP(S) gadget URL or data script.
            continue;
        }
        const auto match = hostSource.match(token);
        if (!match.hasMatch()) {
            // Browsers can recover nonstandard URL spellings differently. Do
            // not silently treat an unsupported URL expression as blocking.
            if (token.contains("://")) out.unknown = true;
            continue;
        }
        const QString scheme = match.captured(1).isEmpty()
            ? (tls ? "https" : "http") : match.captured(1).toLower();
        if (scheme != "http" && scheme != "https") continue;
        Range r; r.host = match.captured(2).toLower();
        const QString rawPath = match.captured(4);
        const QByteArray decodedPath = QByteArray::fromPercentEncoding(rawPath.toUtf8());
        r.prefix = decodedPath.isEmpty() || decodedPath.endsWith('/');
        if (!rawPath.isEmpty() && rawPath != "/") {
            r.path = decodedPath.mid(1).split('/');
            if (r.prefix) r.path.removeLast();
            // Encoded separators and dot segments can interact with URL
            // normalization; leave those unusual paths for manual review.
            if (r.path.contains(".") || r.path.contains("..")) { out.unknown = true; continue; }
        }
        QStringList schemes{scheme};
        if (scheme == "http") schemes.append("https");
        for (const QString &targetScheme : schemes) {
            r.scheme = targetScheme;
            const QString port = match.captured(3);
            if (port == "*") r.port = -1;
            else if (port.isEmpty()) r.port = defaultPort(targetScheme);
            else {
                bool ok = false; r.port = port.toInt(&ok);
                if (!ok || r.port > 65535) continue;
                if (r.port == 80 && targetScheme == "https") {
                    out.ranges.append(r);
                    r.port = 443;
                }
            }
            out.ranges.append(r);
        }
    }
    return out;
}

bool hasFinding(const Result &r, const char *key) {
    return std::any_of(r.findings.cbegin(), r.findings.cend(),
        [&](const Finding &f) { return f.key == QLatin1String(key); });
}

bool hasBroadSource(const Sources &sources) {
    return std::any_of(sources.ranges.cbegin(), sources.ranges.cend(),
        [](const Range &r) { return r.host == "*"; });
}

bool allowsInline(const Directives &dirs, const QString &context) {
    const QString directive = effective(dirs, context);
    if (!dirs.contains(directive)) return true;
    // Reuse the single-policy source grammar/nonce suppression instead of
    // maintaining a second interpretation of accepted nonce/hash expressions.
    Result r;
    auditCsp("script-src " + dirs.value(directive).join(' '), false, r);
    return hasFinding(r, "csp-unsafe-inline");
}
} // namespace

void auditCspIntersection(const QStringList &policies, bool reportOnly,
                          const QUrl &origin, bool tls, Result &result) {
    const QString suffix = reportOnly ? " (report-only -- not enforced)" : "";
    auto add = [&](const char *key, const char *severity, const QString &title, const QString &detail) {
        result.findings.append({QLatin1String(key), QLatin1String(severity), title, detail + suffix});
    };
    qsizetype totalSize = 0;
    for (const auto &policy : policies) totalSize += policy.size();
    if (policies.size() > 256 || totalSize > 262144) {
        add("csp-analysis-incomplete", "info", "CSP policy analysis limit reached",
            "The policy count or total size exceeds the bounded analysis limit; review the complete header set.");
        return;
    }
    bool elementInline = true, attributeInline = true, eval = true, noScriptBase = true;
    bool explicitInline = false, explicitEval = false, objectGap = true, baseGap = true;
    bool sandboxBlocks = false;
    Sources external = universe(), bases = universe();
    int budget = 65536, baseBudget = 65536;
    for (const QString &policy : policies) {
        const Directives dirs = parseCsp(policy);
        const QString script = dirs.contains("script-src") ? "script-src" : "default-src";
        const QString element = effective(dirs, "script-src-elem");
        const bool sandboxed = !reportOnly && dirs.contains("sandbox")
            && !keyword(dirs.value("sandbox"), "allow-scripts");
        sandboxBlocks |= sandboxed;
        elementInline &= allowsInline(dirs, "script-src-elem") && !sandboxed;
        attributeInline &= allowsInline(dirs, "script-src-attr") && !sandboxed;
        eval &= (!dirs.contains(script) || keyword(dirs.value(script), "'unsafe-eval'")) && !sandboxed;
        noScriptBase &= !dirs.contains(script);
        Result individual; auditCsp(policy, false, individual);
        explicitInline |= hasFinding(individual, "csp-unsafe-inline");
        explicitEval |= hasFinding(individual, "csp-unsafe-eval");
        objectGap &= hasFinding(individual, "csp-no-object-src");
        baseGap &= hasFinding(individual, "csp-no-base-uri");
        if (dirs.contains("base-uri")) {
            auto allowedBases = sources(dirs.value("base-uri"), origin, tls);
            // HTML ignores data: and javascript: base URLs.
            allowedBases.ranges.removeIf([](const Range &r) { return r.scheme == "data"; });
            bases = intersect(bases, allowedBases, baseBudget);
        }
        Sources allowed = !dirs.contains(element) ? universe() : sources(dirs.value(element), origin, tls);
        if (sandboxed || keyword(dirs.value(element), "'strict-dynamic'")) allowed = {};
        external = intersect(external, allowed, budget);
    }
    if (noScriptBase && !sandboxBlocks)
        add("csp-no-script-restriction", "high", "CSP policies set no script-src or default-src",
            "No enforced base script directive restricts eval; element and handler overrides may still apply.");
    if (explicitInline && (elementInline || attributeInline))
        add("csp-unsafe-inline", "high", "CSP source lists allow unsafe inline execution",
            QString("Every policy permits arbitrary inline ")
            + (elementInline && attributeInline ? "script elements and event handlers."
               : elementInline ? "script elements." : "event handlers."));
    if (explicitEval && eval)
        add("csp-unsafe-eval", "medium", "CSP source lists allow unsafe-eval",
            "Every policy's effective script/default source list permits eval; other browser controls may still apply.");
    bool broad = false, gadget = false;
    // These are the catalog domains used by the individual-policy auditor.
    // Ask that auditor about each surviving constrained host to keep one catalog.
    for (const auto &range : external.ranges) {
        if (range.host == "*") { broad = true; continue; }
        Result candidate;
        auditCsp("script-src " + range.host, false, candidate);
        gadget |= hasFinding(candidate, "csp-bypassable-host");
    }
    if (broad)
        add("csp-wildcard-source", "high", "CSP policies retain a wildcard/scheme-wide script source",
            "The initial URL source-list intersection still permits scripts from arbitrary hosts or data URLs.");
    if (gadget)
        add("csp-bypassable-host", "medium", "CSP policies retain a potential script-gadget host",
            "A catalog host remains in the initial URL source-list intersection. Verify the permitted scheme, port and path; no matching nonce or integrity metadata is assumed.");
    if (!sandboxBlocks && objectGap)
        add("csp-no-object-src", "low", "CSP policies lack an explicit object-src 'none' restriction",
            "No individual policy supplies the existing object-blocking hardening recommendation; restrictive URL intersections may still block objects.");
    if (!sandboxBlocks && baseGap && hasBroadSource(bases))
        add("csp-no-base-uri", "medium", "CSP policies lack a restrictive base-uri directive",
            "The combined base-uri source lists still permit an HTTP(S) base URL on arbitrary hosts. An injected base element may redirect relative URLs.");
    if (external.unknown || bases.unknown)
        add("csp-analysis-incomplete", "info", "CSP URL-source intersection needs further review",
            "A response origin, supported URL-source spelling, or remaining intersection budget is needed. Additional URL-source permissions could not be resolved.");
}

std::optional<bool> cspFrameAncestorsProtective(const QStringList &policies, const QUrl &origin, bool tls) {
    qsizetype totalSize = 0;
    for (const auto &policy : policies) totalSize += policy.size();
    if (policies.size() > 256 || totalSize > 262144) return {};
    Sources ancestors = universe();
    int budget = 65536;
    for (const auto &policy : policies) {
        const auto dirs = parseCsp(policy);
        if (!dirs.contains("frame-ancestors")) continue;
        auto allowed = sources(dirs.value("frame-ancestors"), origin, tls);
        // frame-ancestors checks the ancestor origin, whose URL path is '/'.
        // A source with a non-root path cannot authorize such an origin.
        allowed.ranges.removeIf([](const Range &r) { return !r.path.isEmpty() || r.scheme == "data"; });
        ancestors = intersect(ancestors, allowed, budget);
    }
    if (ancestors.unknown) return {};
    return !hasBroadSource(ancestors);
}
} // namespace Nullock::Core::HeaderAudit

// Pure JS-recon extraction, split out of js_recon.cpp so a unit test can link it
// against Qt6::Core alone -- scan()'s HttpClient I/O stays in js_recon.cpp. This
// is the soundness core: regexes + the consider() filter that turn a JS body into
// endpoint leads.

#include "js_recon.hpp"

#include <QRegularExpression>
#include <QUrl>

namespace Nullock::Core::JsRecon {

namespace {

// An api/version token must be a whole PATH SEGMENT (bounded by /._- or a string
// end), not a free substring -- "/therapist/" must NOT count as an "api" path,
// nor "restore.js" as a "rest" route.
const QRegularExpression &apiBounded() {
    static const QRegularExpression rx(
        R"((?:^|[/._-])(?:api|graphql|rest|internal|admin|auth)(?:$|[/._-])|(?:^|[/.])v\d+(?:$|[/.-]))",
        QRegularExpression::CaseInsensitiveOption);
    return rx;
}

const QRegularExpression &assetRx() {
    static const QRegularExpression rx(
        R"(\.(?:css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map|mp4|webm|webp|avif)(?:\?|$))",
        QRegularExpression::CaseInsensitiveOption);
    return rx;
}

// CDNs / namespaces / analytics that pollute the endpoint list (matched on HOST).
const QStringList &thirdParty() {
    static const QStringList l = {
        "w3.org", "schema.org", "googleapis.com", "gstatic.com",
        "jsdelivr.net", "unpkg.com", "cdnjs.", "google-analytics.com",
        "googletagmanager.com", "jquery.com", "bootstrapcdn.com",
        "fontawesome.com", "polyfill.io",
    };
    return l;
}

// Is the captured absolute URL hosted on a third-party CDN? Compares the parsed
// HOST as a domain suffix (or a host-label prefix for "cdnjs."-style entries),
// not a raw substring of the whole URL -- so a look-alike host
// (api.mygoogleapis.com.evil.test) and a same-target path that merely contains
// a CDN name are NOT dropped.
bool isThirdPartyHost(const QString &absUrl) {
    const QString host = QUrl(absUrl).host();
    if (host.isEmpty()) return false;
    for (const QString &tp : thirdParty()) {
        if (tp.endsWith('.')) {                                  // "cdnjs." -> a host-label prefix
            if (host.startsWith(tp, Qt::CaseInsensitive)
                || host.contains(QLatin1Char('.') + tp, Qt::CaseInsensitive)) return true;
        } else {                                                 // "googleapis.com" -> a registrable domain
            if (host.compare(tp, Qt::CaseInsensitive) == 0
                || host.endsWith(QLatin1Char('.') + tp, Qt::CaseInsensitive)) return true;
        }
    }
    return false;
}

} // namespace

void extractEndpoints(const QString &js, QSet<QString> &out) {
    // Request-shaped CALLS -- the captured string is the URL. Covers the modern
    // consumer set (fetch/axios/ajax/url:/import()/Worker/sendBeacon/EventSource/
    // WebSocket); the {1,2048} cap is generous enough not to drop long URLs.
    static const QRegularExpression rxCall(
        R"((?:fetch|axios(?:\.\w+)?|\.ajax|\burl\s*:|\bimport|navigator\.sendBeacon|new\s+(?:Shared)?Worker|new\s+EventSource|new\s+WebSocket)\s*\(?\s*["'`]([^"'`]{1,2048})["'`])");
    // XHR open(method, url) -- capture the SECOND string (the URL), not the verb.
    static const QRegularExpression rxXhrOpen(
        R"(\.open\s*\(\s*["'`][A-Za-z]+["'`]\s*,\s*["'`]([^"'`]{1,2048})["'`])");
    // Absolute URLs, http(s) AND ws(s).
    static const QRegularExpression rxAbs(
        R"(["'`]((?:https?|wss?)://[\w.-]+(?:/[\w./?=&%-]*)?)["'`])");
    // Path-shaped strings (relative slash optional) -- KEPT only when api-shaped.
    static const QRegularExpression rxPath(
        R"(["'`](/?(?:[\w.@-]+/)+[\w.@-]*)["'`])");

    auto consider = [&](const QString &raw, bool requireApiToken) {
        QString v = raw.trimmed();
        // Template literal: keep the static prefix before the first ${...}.
        const int interp = v.indexOf(QLatin1String("${"));
        if (interp >= 0) v = v.left(interp);
        if (v.length() < 2) return;
        const bool apiShaped = apiBounded().match(v).hasMatch();
        // A bare identifier (an HTTP verb, a DB name, a modal id, a config value)
        // is not an endpoint -- a real endpoint is a path or api-shaped.
        if (!v.contains(QLatin1Char('/')) && !apiShaped) return;
        // An asset extension is not an endpoint -- but keep an api-shaped .map /
        // route (e.g. /api/tiles/region.map, /api/conf.js).
        if (assetRx().match(v).hasMatch() && !apiShaped) return;
        if ((v.endsWith(".js") || v.endsWith(".mjs")) && !apiShaped) return;
        if (v.startsWith(QLatin1String("http")) && isThirdPartyHost(v)) return;
        if (requireApiToken && !apiShaped) return;
        out.insert(v);
    };

    for (const QRegularExpression *rx : { &rxCall, &rxXhrOpen, &rxAbs }) {
        auto it = rx->globalMatch(js);
        while (it.hasNext()) consider(it.next().captured(1), /*requireApiToken=*/false);
    }
    auto pit = rxPath.globalMatch(js);
    while (pit.hasNext()) consider(pit.next().captured(1), /*requireApiToken=*/true);
}

QString sourceMappingUrl(const QString &js) {
    static const QRegularExpression rx(
        R"((?:^|\n)\s*//[#@]\s*sourceMappingURL=(\S+))");
    // The LAST directive is the effective one (per the source-map convention and
    // browsers) -- a stale/decoy earlier directive must not mask the real map.
    auto it = rx.globalMatch(js);
    QString last;
    while (it.hasNext()) last = it.next().captured(1).trimmed();
    return last;
}

namespace {
// Never emit the secret itself -- a prefix + length is enough to locate it.
QString redactSecret(const QString &v) {
    const int keep = qMin(4, v.size());
    return v.left(keep) + QStringLiteral("...[%1 chars]").arg(v.size());
}
} // namespace

void extractSecrets(const QString &js, QList<JsSecret> &out) {
    struct Pat { QString kind; QString sev; QRegularExpression rx; };
    // The provider prefixes that a secret-shape grep keys on (stripe/gitlab) are
    // assembled by concatenation so this SOURCE never contains the literal shape.
    static const QString stripe = QStringLiteral("(") + "sk_" + "live_" + "[0-9A-Za-z]{24})";
    static const QString gitlab = QStringLiteral("(") + "glpat" + "-" + "[0-9A-Za-z_-]{20})";
    static const QList<Pat> pats = {
        { "aws-access-key", "high",     QRegularExpression(R"(\b(AKIA[0-9A-Z]{16})\b)") },
        { "google-api-key", "high",     QRegularExpression(R"(\b(AIza[0-9A-Za-z_\-]{35})\b)") },
        { "github-pat",     "high",     QRegularExpression(R"(\b(ghp_[0-9A-Za-z]{36})\b)") },
        { "gitlab-pat",     "high",     QRegularExpression(gitlab) },
        { "stripe-secret",  "critical", QRegularExpression(stripe) },
        { "slack-token",    "high",     QRegularExpression(R"((xox[baprs]-[0-9A-Za-z\-]{10,}))") },
        { "private-key",    "critical", QRegularExpression(R"((-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----))") },
        { "jwt",            "low",      QRegularExpression(R"((eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}))") },
        // High-FP generic high-entropy assignment -> graded info (a LEAD).
        { "generic-secret", "info",     QRegularExpression(
            R"((?i)(?:api[_\-]?key|secret|token|password|passwd|auth[_\-]?token)["'\s]*[:=]["'\s]*["']?([A-Za-z0-9_\-+/=]{20,})["']?)") },
    };
    QSet<QString> seen;
    for (const Pat &p : pats) {
        auto it = p.rx.globalMatch(js);
        while (it.hasNext()) {
            const auto m = it.next();
            const QString full = m.lastCapturedIndex() >= 1 ? m.captured(1) : m.captured(0);
            if (full.isEmpty() || seen.contains(full)) continue;
            seen.insert(full);
            out.append({ p.kind, p.sev, redactSecret(full) });
        }
    }
}

} // namespace Nullock::Core::JsRecon

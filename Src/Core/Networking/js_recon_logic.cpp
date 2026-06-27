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

} // namespace Nullock::Core::JsRecon

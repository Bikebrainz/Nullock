#include "js_recon.hpp"
#include "networking.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>

namespace Nullock::Core::JsRecon {

namespace {

QByteArray buildGet(const Request &req, const QString &path) {
    QByteArray out;
    out  = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/js-recon\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QString headerOf(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second.trimmed();
    return {};
}

// Absolute URL of a same-origin path, used as the base for resolving
// relative references in that document/script.
QUrl docUrl(const Request &req, const QString &path) {
    QUrl u;
    u.setScheme(req.tls ? "https" : "http");
    u.setHost(req.host);
    if (req.port != (req.tls ? 443 : 80)) u.setPort(req.port);
    const int q = path.indexOf('?');
    u.setPath(q < 0 ? path : path.left(q));
    return u;
}

// Resolve a reference against a base document URL via RFC-3986 rules
// (QUrl::resolved handles protocol-relative, absolute, host- and
// doc-relative refs AND collapses ../ and ./). Returns {sameOrigin,
// pathOrUrl}: same-origin compares host, PORT and scheme (a different
// port is a different origin -- not something to fetch as a local path).
QPair<bool, QString> resolveRef(const Request &req, const QUrl &base,
                                const QString &ref) {
    const QString t = ref.trimmed();
    if (t.isEmpty()) return { false, QString() };
    const QUrl r = base.resolved(QUrl(t));
    const QString scheme = req.tls ? "https" : "http";
    const int rport = r.port(r.scheme() == "https" ? 443 : 80);
    const bool same = r.host() == req.host && rport == req.port
                   && r.scheme().compare(scheme, Qt::CaseInsensitive) == 0;
    if (same) {
        QString p = r.path(QUrl::FullyEncoded);
        if (p.isEmpty()) p = "/";
        if (r.hasQuery()) p += "?" + r.query(QUrl::FullyEncoded);
        return { true, p };
    }
    return { false, r.toString() };
}

void extractEndpoints(const QString &js, QSet<QString> &out) {
    // URLs in fetch/axios/XHR-ish calls, and "/api/..."-shaped strings.
    static const QRegularExpression rxCall(
        R"((?:fetch|axios(?:\.\w+)?|\.open|\.ajax|url\s*:)\s*\(?\s*["'`]([^"'`]{1,256})["'`])");
    static const QRegularExpression rxApiPath(
        R"(["'`](/(?:[\w.-]+/)*[\w.-]*(?:api|graphql|v\d|rest|internal|admin|auth)[\w./-]*)["'`])",
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression rxAbs(
        R"(["'`](https?://[\w.-]+(?:/[\w./?=&%-]*)?)["'`])");
    // A static asset extension -> not an endpoint.
    static const QRegularExpression assetRx(
        R"(\.(?:css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map|mp4|webm|webp|avif)(?:\?|$))",
        QRegularExpression::CaseInsensitiveOption);
    // An API-ish token -> keep even if it ends in .js (e.g. /api/conf.js).
    static const QRegularExpression apiTokenRx(
        R"((?:api|graphql|rest|internal|admin|auth|/v\d))",
        QRegularExpression::CaseInsensitiveOption);
    // Third-party hosts that pollute the endpoint list (CDNs, namespaces,
    // analytics) -- only filtered for absolute URLs.
    static const QStringList thirdParty = {
        "w3.org", "schema.org", "googleapis.com", "gstatic.com",
        "jsdelivr.net", "unpkg.com", "cdnjs.", "google-analytics.com",
        "googletagmanager.com", "jquery.com", "bootstrapcdn.com",
        "fontawesome.com", "polyfill.io",
    };
    auto consider = [&](const QString &raw) {
        const QString v = raw.trimmed();
        if (v.length() < 2 || v.contains("${")) return;
        if (assetRx.match(v).hasMatch()) return;
        // A bundle reference (.js/.mjs) that isn't API-shaped is a script,
        // not an endpoint -- but keep /api/foo.js style routes.
        if ((v.endsWith(".js") || v.endsWith(".mjs")) && !apiTokenRx.match(v).hasMatch())
            return;
        if (v.startsWith("http")) {
            for (const QString &tp : thirdParty)
                if (v.contains(tp, Qt::CaseInsensitive)) return;
        }
        out.insert(v);
    };
    for (const QRegularExpression *rx : { &rxCall, &rxApiPath, &rxAbs }) {
        auto it = rx->globalMatch(js);
        while (it.hasNext()) consider(it.next().captured(1));
    }
}

QString sourceMappingUrl(const QString &js) {
    static const QRegularExpression rx(
        R"((?:^|\n)\s*//[#@]\s*sourceMappingURL=(\S+))");
    const auto m = rx.match(js);
    return m.hasMatch() ? m.captured(1).trimmed() : QString();
}

} // namespace

Result scan(const Request &req, int maxScripts) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (maxScripts < 1)  maxScripts = 1;
    if (maxScripts > 60) maxScripts = 60;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto get = [&](const QString &path) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildGet(req, path));
    };

    // Cap the bytes we transcode + regex-scan so a giant bundle/map can't
    // exhaust memory/CPU on the scanning host.
    constexpr int kMaxScan = 4 * 1024 * 1024;   // 4 MiB of JS/HTML
    constexpr int kMaxMap  = 32 * 1024 * 1024;  // 32 MiB of source-map JSON

    const auto first = get(req.basePath);
    if (!first.ok) { result.error = "fetch failed: " + first.errorMessage; return result; }
    const QString firstBody = QString::fromUtf8(first.parsed.body.left(kMaxScan));

    // Decide: is the target itself a JS bundle, or an HTML page we mine
    // for <script src>? Prefer the Content-Type (robust to arrow-only
    // minified bundles that lack the literal word "function").
    static const QRegularExpression jsPathRx(R"(\.m?js(\?|$))");
    const QString ctype = headerOf(first.parsed.headers, "Content-Type");
    QStringList toFetch;      // same-origin script paths
    const bool looksJs = ctype.contains("javascript", Qt::CaseInsensitive)
                      || ctype.contains("ecmascript", Qt::CaseInsensitive)
                      || req.basePath.contains(jsPathRx)
                      || (first.parsed.statusCode == 200 && !firstBody.contains('<')
                          && firstBody.contains("function"));
    if (looksJs) {
        toFetch << req.basePath;
    } else {
        const QUrl pageBase = docUrl(req, req.basePath);
        static const QRegularExpression rxScript(
            R"(<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'])",
            QRegularExpression::CaseInsensitiveOption);
        auto it = rxScript.globalMatch(firstBody);
        QSet<QString> seen;
        while (it.hasNext()) {
            const auto [sameHost, ref] = resolveRef(req, pageBase, it.next().captured(1));
            if (ref.isEmpty() || seen.contains(ref)) continue;
            seen.insert(ref);
            if (sameHost) { if (toFetch.size() < maxScripts) toFetch << ref; }
            else result.crossOriginScripts << ref;
        }
    }

    QSet<QString> endpoints;
    for (const QString &scriptPath : toFetch) {
        const auto r = get(scriptPath);
        if (!r.ok || r.parsed.statusCode != 200) continue;
        result.scripts << scriptPath;
        const QString js = QString::fromUtf8(r.parsed.body.left(kMaxScan));
        extractEndpoints(js, endpoints);

        // Source map exposure.
        const QString smRef = sourceMappingUrl(js);
        if (smRef.isEmpty() || smRef.startsWith("data:")) continue;
        const auto [sameHost, mapRef] = resolveRef(req, docUrl(req, scriptPath), smRef);
        SourceMap sm;
        sm.jsUrl  = scriptPath;
        sm.mapUrl = mapRef;
        if (sameHost) {
            const auto mr = get(mapRef);
            if (mr.ok && mr.parsed.statusCode == 200
                && mr.parsed.body.size() <= kMaxMap) {
                const QJsonDocument d = QJsonDocument::fromJson(mr.parsed.body);
                if (d.isObject() && d.object().contains("sources")) {
                    sm.accessible = true;
                    for (const QJsonValue &s : d.object().value("sources").toArray())
                        sm.sources << s.toString();
                }
            }
        }
        result.sourceMaps << sm;
    }

    result.endpoints = endpoints.values();
    result.endpoints.sort();
    return result;
}

} // namespace Nullock::Core::JsRecon

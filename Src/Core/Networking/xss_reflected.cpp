#include "xss_reflected.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrlQuery>

#include <algorithm>

namespace Nullock::Core::XssReflected {

// The pure matcher/builder (isHtmlContentType, inExecutingHtmlContext,
// buildRequest, queryWith) lives in xss_logic.cpp so it can be unit-tested
// against Qt6::Core alone. This TU keeps test(), which pulls in HttpClient (the
// Qt6::Network chain via Proxy::HttpResponse) and is therefore I/O.

namespace {

constexpr int kMaxSends = 90;

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

bool isHtmlResponse(const Proxy::HttpResponse &r) {
    const QString ct = headerValue(r, "Content-Type").toLower();
    // A browser only sniffs a typeless body as HTML when nosniff is absent; with
    // X-Content-Type-Options: nosniff an empty/non-HTML type never executes.
    if (ct.isEmpty()
        && headerValue(r, "X-Content-Type-Options").toLower().contains("nosniff"))
        return false;
    return isHtmlContentType(ct);
}

QString randMarker() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 8; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

} // namespace

QStringList defaultParams() {
    return { "q", "query", "search", "s", "name", "message", "msg", "comment",
             "keyword", "term", "id", "page", "lang", "redirect", "ref", "input" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
    }
    // Before truncating, float high-signal param names (the known-reflective set)
    // to the front so the cap can't silently drop the one that's vulnerable.
    if (params.size() > 8) {
        const QStringList known = defaultParams();
        std::stable_sort(params.begin(), params.end(),
            [&](const QString &a, const QString &b) {
                return known.contains(a) && !known.contains(b);
            });
    }
    while (params.size() > 8) params.removeLast();
    result.testedParams = params;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, query));
    };

    const auto base = send(req.query);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;

    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        const QString marker = randMarker();
        const QString tag = "<" + marker + ">";          // the executable proof
        const auto r = send(queryWith(req.query, param, tag));
        if (!r.ok) continue;
        // Must be an HTML response, the tag must reflect with raw (unencoded)
        // angle brackets, and that reflection must sit in element content --
        // not a comment, raw-text element, or attribute -- to actually run.
        if (!isHtmlResponse(r.parsed)) continue;
        const QString body = QString::fromUtf8(r.parsed.body);
        // Check EVERY occurrence, case-insensitively: an app may normalize the
        // value's case, and the first reflection may be inert (a comment or
        // raw-text element) while a later one runs in element content.
        for (int at = body.indexOf(tag, 0, Qt::CaseInsensitive); at >= 0;
             at = body.indexOf(tag, at + 1, Qt::CaseInsensitive)) {
            if (inExecutingHtmlContext(body, at)) {
                result.hits.append({ param, QStringLiteral("html"), tag,
                                     body.mid(at, tag.size()) });
                result.vulnerable = true;
                break;
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::XssReflected

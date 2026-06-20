#include "open_redirect.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::OpenRedirect {

namespace {

struct Payload { const char *technique; QString value; };

// Build the bypass battery against the sentinel. `targetHost` is the request's
// own host, used for the whitelist-prefix and userinfo tricks that beat naive
// "startswith our domain" / "contains our domain" validators.
QList<Payload> payloads(const QString &targetHost) {
    const QString s = sentinelHost();
    return {
        { "absolute-https",     "https://" + s },
        { "scheme-relative",    "//" + s },
        { "backslash-relative", "\\\\" + s },
        { "slash-backslash",    "/\\" + s },
        { "missing-slash",      "https:/" + s },
        { "no-slashes",         "https:" + s },
        { "case-scheme",        "HtTpS://" + s },
        { "whitelist-prefix",   "https://" + targetHost + "." + s },
        { "userinfo",           "https://" + targetHost + "@" + s },
        { "backslash-scheme",   "https:\\\\" + s },
        { "whitespace-prefix",  " //" + s },
    };
}

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// The url= target of a Refresh response header ("<delay>; url=TARGET").
QString refreshHeaderUrl(const QString &refresh) {
    static const QRegularExpression re(QStringLiteral("\\burl\\s*=\\s*[\"']?\\s*([^\"'>\\s]+)"),
                                       QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(refresh);
    return m.hasMatch() ? m.captured(1) : QString();
}

} // namespace

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Resolve which parameter(s) to test: the explicit one, or sweep EVERY known
    // redirect param present in the query (sibling SQLi/XSS probes do the same).
    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        QUrlQuery q(req.query);
        const QStringList known = knownRedirectParams();
        for (const auto &kv : q.queryItems())
            if (known.contains(kv.first.toLower()) && !params.contains(kv.first))
                params << kv.first;
        if (params.size() > 6) params = params.mid(0, 6);   // bound the sweep
        if (params.isEmpty()) {
            result.error = "no redirect parameter given or auto-detected in the query";
            return result;
        }
    }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    // Base for resolving relative/scheme-relative redirect values (RFC-3986).
    QUrl base;
    base.setScheme(req.tls ? "https" : "http");
    base.setHost(req.host);
    base.setPort(req.port);
    base.setPath(req.basePath);

    auto sendWith = [&](const QString &param, const QString &value) {
        QUrlQuery qq(req.query);
        qq.removeAllQueryItems(param);
        qq.addQueryItem(param, value);
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, qq.toString(QUrl::FullyEncoded)));
    };

    int inconclusive = 0;
    bool baselineRecorded = false;
    for (const QString &param : params) {
        const auto baseResp = sendWith(param, QStringLiteral("/account"));
        if (!baseResp.ok) continue;   // transport failure for this param -> skip
        if (!baselineRecorded) {
            result.baselineStatus = baseResp.parsed.statusCode;
            baselineRecorded = true;
        }
        // If the endpoint already redirects to the sentinel with a benign value,
        // the redirect isn't driven by our parameter -- skip it as noise rather
        // than report a hit on every probe.
        if (baseResp.parsed.statusCode >= 300 && baseResp.parsed.statusCode < 400
            && isSentinelHost(resolvedRedirectHost(base, headerValue(baseResp.parsed, "Location")))) {
            ++inconclusive;
            continue;
        }
        result.testedParams << param;

        for (const Payload &p : payloads(req.host)) {
            const auto r = sendWith(param, p.value);
            if (!r.ok) continue;
            const int sc = r.parsed.statusCode;

            // 1) High-confidence: a 3xx whose Location resolves to the sentinel.
            if (sc >= 300 && sc < 400) {
                const QString host = resolvedRedirectHost(base, headerValue(r.parsed, "Location"));
                if (isSentinelHost(host)) {
                    result.hits.append({ p.technique, p.value, "Location", host, param, sc });
                    result.vulnerable = true;
                    continue;
                }
            }
            // 2) High-confidence: a Refresh RESPONSE header (browsers honor it
            //    like Location / <meta refresh>), at any status code.
            const QString refresh = headerValue(r.parsed, "Refresh");
            if (!refresh.isEmpty()) {
                const QString host = resolvedRedirectHost(base, refreshHeaderUrl(refresh));
                if (isSentinelHost(host)) {
                    result.hits.append({ p.technique, p.value, "refresh-header", host, param, sc });
                    result.vulnerable = true;
                    continue;
                }
            }
            // 3) Lower-confidence: a client-side <meta refresh> / JS location
            //    navigation in the body whose resolved host is the sentinel.
            QString via;
            const QString host = clientSideRedirectHost(r.parsed.body, base, &via);
            if (isSentinelHost(host)) {
                result.hits.append({ p.technique, p.value,
                                     via.isEmpty() ? QStringLiteral("client-side") : via,
                                     host, param, sc });
                result.vulnerable = true;
            }
        }
    }

    if (result.testedParams.isEmpty()) {
        result.error = inconclusive
            ? "inconclusive: the endpoint redirects to the sentinel "
              "independent of the parameter"
            : "baseline failed for all candidate parameters";
    }
    result.testedParam = result.testedParams.value(0);
    return result;
}

} // namespace Nullock::Core::OpenRedirect

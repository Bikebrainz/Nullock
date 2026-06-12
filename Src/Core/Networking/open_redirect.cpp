#include "open_redirect.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::OpenRedirect {

namespace {

// The external host every payload aims at. A redirect that resolves here --
// or to any subdomain of it -- left the trusted origin.
const QString kSentinel = QStringLiteral("nullock-oob.test");

bool isSentinelHost(const QString &host) {
    const QString h = host.toLower();
    return h == kSentinel || h.endsWith("." + kSentinel);
}

struct Payload { const char *technique; QString value; };

// Build the bypass battery against the sentinel. `targetHost` is the request's
// own host, used for the whitelist-prefix and userinfo tricks that beat naive
// "startswith our domain" / "contains our domain" validators.
QList<Payload> payloads(const QString &targetHost) {
    const QString s = kSentinel;
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

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/open-redirect\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// The host a Location header actually navigates to, resolved against the
// request URL the way a browser would: backslashes count as slashes, and a
// "scheme:" with too few slashes ("https:/host", "https:host") is the
// browser-normalized "scheme://host". We only touch the authority/path head,
// never the query/fragment, so a backslash inside a same-origin query can't
// be twisted into an off-origin authority.
QString resolvedRedirectHost(const QUrl &base, QString loc) {
    if (loc.isEmpty()) return QString();
    const int cut = loc.indexOf(QRegularExpression(QStringLiteral("[?#]")));
    QString head = cut < 0 ? loc : loc.left(cut);
    const QString tail = cut < 0 ? QString() : loc.mid(cut);
    head.replace('\\', '/');
    static const QRegularExpression sch(QStringLiteral("^(https?):/*"),
                                        QRegularExpression::CaseInsensitiveOption);
    head.replace(sch, QStringLiteral("\\1://"));
    return base.resolved(QUrl(head + tail, QUrl::TolerantMode)).host();
}

// A client-side redirect to the sentinel: meta-refresh URL or a JS location
// assignment. The sentinel must sit as the host right after the scheme/slash
// authority marker -- not arbitrary reflected text -- so a page that merely
// echoes a rejected payload near the word "location" isn't mistaken for one.
bool clientSideRedirect(const QByteArray &body) {
    static const QRegularExpression re(
        "(?:http-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]*url\\s*=|"
        "(?:window\\.)?location(?:\\.href|\\.replace)?\\s*[=(])"
        "\\s*[\"']?\\s*(?:https?:)?[\\\\/]{1,2}(?:[^\"'>\\s/\\\\]*\\.)?nullock-oob\\.test",
        QRegularExpression::CaseInsensitiveOption);
    return re.match(QString::fromUtf8(body.left(256 * 1024))).hasMatch();
}

} // namespace

QStringList knownRedirectParams() {
    return { "url", "next", "redirect", "redirect_uri", "redirecturl", "return",
             "returnurl", "return_to", "returnto", "dest", "destination",
             "continue", "target", "to", "out", "view", "image_url", "go",
             "u", "r", "link", "checkout_url", "callback", "redir" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Resolve which parameter to test.
    QUrlQuery q(req.query);
    if (req.param.isEmpty()) {
        const QStringList known = knownRedirectParams();
        for (const auto &kv : q.queryItems())
            if (known.contains(kv.first.toLower())) { req.param = kv.first; break; }
        if (req.param.isEmpty()) {
            result.error = "no redirect parameter given or auto-detected in the query";
            return result;
        }
    }
    result.testedParam = req.param;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto sendWith = [&](const QString &value) {
        QUrlQuery qq(req.query);
        qq.removeAllQueryItems(req.param);
        qq.addQueryItem(req.param, value);
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, qq.toString(QUrl::FullyEncoded)));
    };

    // Base for resolving relative/scheme-relative Location values (RFC-3986).
    QUrl base;
    base.setScheme(req.tls ? "https" : "http");
    base.setHost(req.host);
    base.setPort(req.port);
    base.setPath(req.basePath.isEmpty() ? "/" : req.basePath);

    const auto baseResp = sendWith(QStringLiteral("/account"));
    if (!baseResp.ok) { result.error = "baseline failed: " + baseResp.errorMessage; return result; }
    result.baselineStatus = baseResp.parsed.statusCode;

    // If the endpoint already redirects to the sentinel with a benign value,
    // the redirect isn't driven by our parameter -- every probe would "hit".
    // Bail as inconclusive rather than report noise.
    if (baseResp.parsed.statusCode >= 300 && baseResp.parsed.statusCode < 400
        && isSentinelHost(resolvedRedirectHost(base, headerValue(baseResp.parsed, "Location")))) {
        result.error = "inconclusive: the endpoint redirects to the sentinel "
                       "independent of the parameter";
        return result;
    }

    for (const Payload &p : payloads(req.host)) {
        const auto r = sendWith(p.value);
        if (!r.ok) continue;
        const int sc = r.parsed.statusCode;

        // Primary, high-confidence: a real redirect whose Location resolves to
        // the sentinel host.
        if (sc >= 300 && sc < 400) {
            const QString host = resolvedRedirectHost(base, headerValue(r.parsed, "Location"));
            if (isSentinelHost(host)) {
                result.hits.append({ p.technique, p.value, "Location", host, sc });
                result.vulnerable = true;
                continue;
            }
        }
        // Secondary, lower-confidence: a client-side redirect to the sentinel.
        if (clientSideRedirect(r.parsed.body)) {
            result.hits.append({ p.technique, p.value, "client-side",
                                 kSentinel, sc });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::OpenRedirect

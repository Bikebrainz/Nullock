#include "xss_reflected.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::XssReflected {

namespace {

constexpr int kMaxSends = 90;

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

bool isHtmlResponse(const Proxy::HttpResponse &r) {
    const QString ct = headerValue(r, "Content-Type").toLower();
    // Only HTML (or no Content-Type, which browsers may sniff as HTML) can
    // execute injected markup; a JSON/text/plain reflection is not XSS.
    return ct.isEmpty() || ct.contains("text/html") || ct.contains("application/xhtml");
}

// Would "<marker>" at offset `at` be parsed as a start tag -- i.e. it's in
// normal element content, NOT inside a comment, a raw-text element
// (script/style/textarea/title/xmp/noscript), or an open tag's attributes?
// Only that position is exploitable; the rest reflect the brackets inertly.
bool inExecutingHtmlContext(const QString &body, int at) {
    static const QStringList rawText = {
        "script", "style", "textarea", "title", "xmp", "noscript" };
    QString openRaw;       // current raw-text element name, or empty
    bool inComment = false;
    bool inTag = false;    // between '<' and its '>'
    const int n = qMin(at, body.size());
    for (int i = 0; i < n; ++i) {
        if (inComment) {
            if (body.mid(i, 3) == QLatin1String("-->")) { inComment = false; i += 2; }
            continue;
        }
        if (!openRaw.isEmpty()) {
            if (body.mid(i, openRaw.size() + 3)
                    .compare("</" + openRaw + ">", Qt::CaseInsensitive) == 0) {
                i += openRaw.size() + 2;
                openRaw.clear();
                inTag = false;
            }
            continue;
        }
        const QChar ch = body[i];
        if (ch == '<') {
            if (body.mid(i, 4) == QLatin1String("<!--")) { inComment = true; i += 3; continue; }
            int j = i + 1;
            const bool closing = (j < body.size() && body[j] == '/');
            if (closing) ++j;
            QString nameStr;
            while (j < body.size() && body[j].isLetterOrNumber()) { nameStr += body[j].toLower(); ++j; }
            if (!closing && rawText.contains(nameStr)) openRaw = nameStr;
            inTag = true;
        } else if (ch == '>') {
            inTag = false;
        }
    }
    return !inComment && openRaw.isEmpty() && !inTag;
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/xss\r\n";
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

QString queryWith(const QString &existing, const QString &param, const QString &value) {
    const QByteArray enc = QUrl::toPercentEncoding(value);
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + QString::fromUtf8(enc);
    return parts.join('&');
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
    while (params.size() > 6) params.removeLast();
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
        const int at = body.indexOf(tag);
        if (at >= 0 && inExecutingHtmlContext(body, at)) {
            result.hits.append({ param, QStringLiteral("html"), tag, tag });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::XssReflected

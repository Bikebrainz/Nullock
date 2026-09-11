// Pure redirect-following logic (see redirect_logic.hpp). Qt6::Core only.

#include "redirect_logic.hpp"
#include <QNetworkCookie>
#include <QSet>

#include <QStringList>
#include <algorithm>

namespace Nullock::Core::RedirectLogic {

FollowPolicy parseFollowPolicy(const QString &s) {
    const QString t = s.trimmed().toLower();
    if (t == "on-site" || t == "onsite")  return FollowOnSite;
    if (t == "in-scope" || t == "inscope") return FollowInScope;
    if (t == "always")   return FollowAlways;
    return FollowNever;   // default / "never" / unknown -> don't follow
}

QString followPolicyName(FollowPolicy p) {
    switch (p) {
        case FollowOnSite:  return QStringLiteral("on-site");
        case FollowInScope: return QStringLiteral("in-scope");
        case FollowAlways:  return QStringLiteral("always");
        case FollowNever:   break;
    }
    return QStringLiteral("never");
}

bool isRedirectStatus(int status) {
    return status == 301 || status == 302 || status == 303
        || status == 307 || status == 308;
}

QUrl resolveRedirect(const QUrl &current, const QString &location) {
    const QString loc = location.trimmed();
    if (loc.isEmpty()) return {};
    const QUrl rel(loc);
    if (!rel.isValid()) return {};
    const QUrl resolved = current.resolved(rel);
    if (!resolved.isValid() || resolved.host().isEmpty()) return {};
    return resolved;
}

QString methodAfterRedirect(int status, const QString &currentMethod) {
    const QString m = currentMethod.trimmed().toUpper();
    if (status == 307 || status == 308) return m;               // preserve
    if (status == 303) return m == QLatin1String("HEAD") ? m : QStringLiteral("GET");
    if (status == 301 || status == 302)
        return m == QLatin1String("POST") ? QStringLiteral("GET") : m;
    return m;
}

bool redirectPreservesBody(int status, const QString &method) {
    return status != 303 && methodAfterRedirect(status, method) == method.trimmed().toUpper();
}

bool followAllowed(FollowPolicy policy, const QString &originHost,
                   const QString &nextHost, bool nextInScope) {
    if (nextHost.trimmed().isEmpty()) return false;
    switch (policy) {
        case FollowNever:   return false;
        case FollowAlways:  return true;
        case FollowOnSite:  return nextHost.compare(originHost, Qt::CaseInsensitive) == 0;
        case FollowInScope: return nextInScope;
    }
    return false;
}

void seedRequestCookies(CookieJar &jar, const QUrl &origin, const QByteArray &request) {
    const auto head = request.left(request.indexOf("\r\n\r\n") < 0 ? request.size() : request.indexOf("\r\n\r\n"));
    for (auto line : head.split('\n')) {
        const int c = line.indexOf(':');
        if (c < 0 || line.left(c).trimmed().toLower() != "cookie") continue;
        for (auto pair : line.mid(c + 1).trimmed().split(';')) {
            const int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            QNetworkCookie cookie(pair.left(eq).trimmed(), pair.mid(eq + 1).trimmed());
            cookie.setPath("/");
            cookie.setSecure(origin.scheme() == "https");
            jar.setCookiesFromUrl({cookie}, origin);
        }
    }
}

void mergeSetCookies(CookieJar &jar, const QUrl &origin,
                     const QList<QPair<QString, QString>> &headers) {
    for (const auto &h : headers) {
        if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) == 0)
            jar.setCookiesFromUrl(QNetworkCookie::parseCookies(h.second.toLatin1()), origin);
    }
}

QString renderCookieHeader(const CookieJar &jar, const QUrl &destination) {
    QStringList pairs;
    for (const auto &cookie : jar.cookiesForUrl(destination))
        pairs << QString::fromLatin1(cookie.toRawForm(QNetworkCookie::NameAndValueOnly));
    return pairs.join(QStringLiteral("; "));
}

QByteArray buildFollowRequest(const QUrl &url, const QString &method,
                              const QString &cookieHeader, const QByteArray &body,
                              const QByteArray &previousRequest, const QUrl &previousUrl,
                              bool preserveBody) {
    QString target = url.path(QUrl::FullyEncoded);
    if (target.isEmpty()) target = "/";
    if (!url.query(QUrl::FullyEncoded).isEmpty()) target += "?" + url.query(QUrl::FullyEncoded);
    const bool tls = url.scheme() == "https";
    QString authority = url.host();
    if (authority.contains(':')) authority = "[" + authority + "]";
    if (url.port() > 0 && url.port() != (tls ? 443 : 80)) authority += ":" + QString::number(url.port());
    const bool sameOrigin = previousUrl.scheme() == url.scheme()
        && previousUrl.host().compare(url.host(), Qt::CaseInsensitive) == 0
        && previousUrl.port(previousUrl.scheme() == "https" ? 443 : 80) == url.port(tls ? 443 : 80);
    const int sep = previousRequest.indexOf("\r\n\r\n");
    const auto lines = previousRequest.left(sep < 0 ? previousRequest.size() : sep).split('\n');
    QSet<QByteArray> skip{"host", "cookie", "content-length", "transfer-encoding", "connection",
        "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "proxy-authorization"};
    for (auto line : lines) {
        const int c = line.indexOf(':');
        if (c >= 0 && line.left(c).trimmed().toLower() == "connection")
            for (auto token : line.mid(c+1).split(',')) skip.insert(token.trimmed().toLower());
    }
    // Unknown custom headers may contain credentials. Cross-origin follows use
    // only representation/negotiation headers; same-origin follows retain others.
    const QSet<QByteArray> crossOriginSafe{"accept", "accept-language", "accept-encoding", "user-agent",
        "content-type", "content-encoding", "content-language", "content-location"};
    QByteArray out = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\nHost: " + authority.toUtf8() + "\r\n";
    bool hasAccept = false;
    for (auto line : lines) {
        if (line.endsWith('\r')) line.chop(1);
        const int c = line.indexOf(':');
        if (c < 0) continue;
        const auto name = line.left(c).trimmed().toLower();
        if (skip.contains(name) || (!sameOrigin && !crossOriginSafe.contains(name))) continue;
        if (!preserveBody && name.startsWith("content-")) continue;
        if (name == "accept") hasAccept = true;
        out += line + "\r\n";
    }
    if (!hasAccept) out += "Accept: */*\r\n";
    if (!cookieHeader.isEmpty()) out += "Cookie: " + cookieHeader.toLatin1() + "\r\n";
    if (!body.isEmpty() || method == "POST" || method == "PUT" || method == "PATCH")
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    return out + body;
}

static QByteArray firstLine(const QByteArray &raw) {
    int end = raw.indexOf('\n');
    if (end < 0) end = raw.size();
    QByteArray line = raw.left(end);
    if (line.endsWith('\r')) line.chop(1);
    return line;
}

QString requestMethod(const QByteArray &rawRequest) {
    const QByteArray line = firstLine(rawRequest);
    const int sp = line.indexOf(' ');
    if (sp <= 0) return {};
    return QString::fromUtf8(line.left(sp)).toUpper();
}

QString requestTarget(const QByteArray &rawRequest) {
    const QByteArray line = firstLine(rawRequest);
    const int sp1 = line.indexOf(' ');
    if (sp1 < 0) return {};
    const int sp2 = line.indexOf(' ', sp1 + 1);
    const QByteArray tgt = sp2 < 0 ? line.mid(sp1 + 1) : line.mid(sp1 + 1, sp2 - sp1 - 1);
    return QString::fromUtf8(tgt);
}

QUrl requestUrl(bool tls, const QString &host, int port, const QByteArray &rawRequest) {
    QUrl u;
    u.setScheme(tls ? QStringLiteral("https") : QStringLiteral("http"));
    u.setHost(host);
    if (port > 0 && port != (tls ? 443 : 80)) u.setPort(port);
    const QString tgt = requestTarget(rawRequest);
    // An absolute-form target (proxied request) already carries scheme+host.
    if (tgt.startsWith(QLatin1String("http://")) || tgt.startsWith(QLatin1String("https://")))
        return QUrl(tgt);
    const int q = tgt.indexOf(QLatin1Char('?'));
    if (q >= 0) {
        u.setPath(tgt.left(q));
        u.setQuery(tgt.mid(q + 1));
    } else {
        u.setPath(tgt.isEmpty() ? QStringLiteral("/") : tgt);
    }
    return u;
}

} // namespace Nullock::Core::RedirectLogic

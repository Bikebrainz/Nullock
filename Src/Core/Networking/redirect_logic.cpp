// Pure redirect-following logic (see redirect_logic.hpp). Qt6::Core only.

#include "redirect_logic.hpp"

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

bool redirectPreservesBody(int status) {
    return status == 307 || status == 308;
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

void mergeSetCookies(QHash<QString, QString> &jar,
                     const QList<QPair<QString, QString>> &headers) {
    for (const auto &h : headers) {
        if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
        // First ';'-segment is the name=value cookie pair; the rest are attributes.
        const QString seg = h.second.section(QLatin1Char(';'), 0, 0).trimmed();
        const int eq = seg.indexOf(QLatin1Char('='));
        if (eq <= 0) continue;
        const QString name = seg.left(eq).trimmed();
        const QString val  = seg.mid(eq + 1).trimmed();
        if (!name.isEmpty()) jar.insert(name, val);   // last write wins
    }
}

QString renderCookieHeader(const QHash<QString, QString> &jar) {
    if (jar.isEmpty()) return {};
    QStringList keys = jar.keys();
    std::sort(keys.begin(), keys.end());   // deterministic order
    QStringList pairs;
    pairs.reserve(keys.size());
    for (const QString &k : keys) pairs << (k + QLatin1Char('=') + jar.value(k));
    return pairs.join(QStringLiteral("; "));
}

QByteArray buildFollowRequest(const QUrl &url, const QString &method,
                              const QString &cookieHeader, const QByteArray &body) {
    QString pathAndQuery = url.path(QUrl::FullyEncoded);
    if (pathAndQuery.isEmpty()) pathAndQuery = QStringLiteral("/");
    const QString q = url.query(QUrl::FullyEncoded);
    if (!q.isEmpty()) pathAndQuery += QLatin1Char('?') + q;

    // Host header: include the port only when it is non-default for the scheme.
    const QString host = url.host();
    const int port = url.port();
    const bool tls = url.scheme().compare("https", Qt::CaseInsensitive) == 0;
    QString hostHeader = host;
    if (port > 0 && port != (tls ? 443 : 80))
        hostHeader += QLatin1Char(':') + QString::number(port);

    QByteArray out;
    out += method.toUtf8() + " " + pathAndQuery.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + hostHeader.toUtf8() + "\r\n";
    out += "Accept: */*\r\n";
    if (!cookieHeader.isEmpty())
        out += "Cookie: " + cookieHeader.toUtf8() + "\r\n";
    if (!body.isEmpty())
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
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

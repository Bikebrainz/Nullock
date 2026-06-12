#include "cache_poison.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QRegularExpression>
#include <QUrlQuery>

namespace Nullock::Core::CachePoison {

namespace {

using Proxy::HttpResponse;

// The unkeyed-header probes worth trying, with the shape of value each one
// takes. Host-class headers reflect into absolute URLs / Host-derived links;
// path-class headers reflect into routing / Location.
struct Probe {
    const char *header;
    bool        pathLike;   // value is a "/..." path rather than a host
};
const QList<Probe> &probes() {
    static const QList<Probe> p = {
        { "X-Forwarded-Host",   false },
        { "X-Host",             false },
        { "X-Forwarded-Server", false },
        { "X-Forwarded-Prefix", true  },
        { "X-Original-URL",     true  },
        { "X-Rewrite-URL",      true  },
        { "X-Original-Host",    false },
    };
    return p;
}

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("np");
    for (int i = 0; i < 10; ++i)
        s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// Does the response reflect `tok` anywhere a cache would serve back? Returns
// a short location label, or empty if absent.
QString reflectionSite(const HttpResponse &r, const QString &tok) {
    if (QString::fromUtf8(r.body).contains(tok)) return QStringLiteral("body");
    for (const auto &h : r.headers)
        if (h.second.contains(tok))
            return QStringLiteral("header:") + h.first;
    return QString();
}

// A response that demonstrably came from / lives in a shared cache: it
// carries an Age, or a hit verdict from a recognized cache front-end.
bool cacheHitSignal(const HttpResponse &r) {
    if (!headerValue(r, "Age").isEmpty()) return true;
    const QString xc = headerValue(r, "X-Cache") + " "
                     + headerValue(r, "X-Cache-Status") + " "
                     + headerValue(r, "CF-Cache-Status") + " "
                     + headerValue(r, "X-Served-By");
    return xc.contains("hit", Qt::CaseInsensitive);
}

// Parse a Cache-Control directive's seconds value; -1 if the directive is
// absent. Used to tell a shareable fresh lifetime (>0) from max-age=0, which
// forces revalidation and is not a free hit.
int ccSeconds(const QString &cc, const QString &directive) {
    QRegularExpression re(directive + "\\s*=\\s*\"?(\\d+)",
                          QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(cc);
    return m.hasMatch() ? m.captured(1).toInt() : -1;
}

// Heuristic: would a shared cache store and re-serve this response to others?
bool looksCacheable(const HttpResponse &r) {
    if (cacheHitSignal(r)) return true;
    const QString cc = headerValue(r, "Cache-Control").toLower();
    // no-store / private are never shared. (no-cache means store-but-
    // revalidate, so it does NOT by itself rule out a shared hit.)
    if (cc.contains("no-store") || cc.contains("private")) return false;
    // s-maxage is the shared-cache directive and wins; then max-age. A zero
    // lifetime is revalidate-on-every-use, not a free shareable hit.
    const int s = ccSeconds(cc, "s-maxage");
    if (s > 0) return true;
    if (s == 0) return false;
    const int ma = ccSeconds(cc, "max-age");
    if (ma > 0) return true;
    if (ma == 0) return false;
    if (cc.contains("public")) return true;
    if (!headerValue(r, "Expires").isEmpty()) return true;
    return false;
}

QByteArray buildRequest(const Request &req, const QString &query,
                        const QString &extraHeader, const QString &extraValue) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cache-poison\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!extraHeader.isEmpty())
        out += extraHeader.toUtf8() + ": " + extraValue.toUtf8() + "\r\n";
    out += "Connection: close\r\n\r\n";
    return out;
}

QString withBuster(const QString &query, const QString &cb) {
    QUrlQuery q(query);
    q.removeAllQueryItems(QStringLiteral("ncb"));
    q.addQueryItem(QStringLiteral("ncb"), cb);
    return q.toString(QUrl::FullyEncoded);
}

} // namespace

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query, const QString &hdr, const QString &val) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, query, hdr, val));
    };

    // SAFETY GATE. We only inject a poison once we've shown the buster is part
    // of the cache key -- otherwise the poison would land on the real key and
    // be served to actual users. Probe: two requests with the SAME buster
    // (look for a miss->hit), then one with a DIFFERENT buster. If that's
    // still a hit, the cache ignores the buster (unkeyed) and we must NOT
    // proceed. This doubles as the baseline. All requests here are clean (no
    // injected header), so they can't poison anything.
    const QString k1 = randTok();
    const auto a = send(withBuster(req.query, k1), QString(), QString());
    if (!a.ok) { result.error = "baseline failed: " + a.errorMessage; return result; }
    result.baselineStatus = a.parsed.statusCode;
    const auto b = send(withBuster(req.query, k1), QString(), QString());
    const bool busterCached = b.ok && cacheHitSignal(b.parsed);
    if (busterCached) {
        const auto c = send(withBuster(req.query, randTok()), QString(), QString());
        if (c.ok && cacheHitSignal(c.parsed)) {
            result.error = "aborted: the cache ignores the buster parameter "
                "(unkeyed) -- injecting here could poison the response served "
                "to real users, so no header was injected";
            return result;
        }
    }

    for (const Probe &p : probes()) {
        const QString header = QString::fromUtf8(p.header);
        const QString tok = randTok();
        const QString cb = randTok();
        const QString value = p.pathLike ? "/" + tok
                                          : tok + QStringLiteral(".nullock-poison.test");
        const QString query = withBuster(req.query, cb);

        // 1) Poison our own throwaway key.
        const auto pr = send(query, header, value);
        if (!pr.ok) continue;
        const QString site = reflectionSite(pr.parsed, tok);
        if (site.isEmpty()) continue;          // not reflected -> no poisoning vector
        // A path-class header (X-Original-URL: /<tok>) the server *routes* to
        // typically yields a 404 page echoing the path -- that's routing, not
        // a cacheable poisoning vector. Don't count a 404 body reflection.
        if (p.pathLike && pr.parsed.statusCode == 404 && site == QStringLiteral("body"))
            continue;

        Hit hit;
        hit.header = header;
        hit.sentValue = value;
        hit.where = site;
        hit.reflected = true;
        hit.cacheable = looksCacheable(pr.parsed);

        // 2) Re-request the SAME key with NO header. The server cannot reflect
        //    a header it never received, so a surviving token served *from the
        //    cache* (a hit signal on this clean response) proves the poisoning
        //    end to end. Requiring the hit signal -- not just token survival --
        //    rejects servers that merely echo the last-seen header from app
        //    state rather than a shared cache.
        const auto clean = send(query, QString(), QString());
        if (clean.ok && !reflectionSite(clean.parsed, tok).isEmpty()
                     && cacheHitSignal(clean.parsed))
            hit.cacheConfirmed = true;

        if (hit.cacheConfirmed) result.anyConfirmed = true;
        if (hit.cacheable)      result.anyCacheable = true;
        result.hits.append(hit);
    }

    return result;
}

} // namespace Nullock::Core::CachePoison

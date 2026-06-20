// Pure (no-network) logic for the cache-poisoning probe: sentinel generation,
// reflection-surface detection, cache-signal / cacheability heuristics, the
// request builder's CR/LF guards, and the FAIL-CLOSED safety decision. Split
// out of cache_poison.cpp so Tests/cache_poison can link Qt6::Core alone (no
// HttpClient / Network / GUI chain) and regression-lock the safety logic.

#include "cache_poison.hpp"

#include <QRandomGenerator>
#include <QRegularExpression>
#include <QStringList>
#include <QUrlQuery>

namespace Nullock::Core::CachePoison {

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("np");
    for (int i = 0; i < 10; ++i)
        s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

QString headerValue(const Headers &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

QString reflectionSite(const QByteArray &body, const Headers &headers, const QString &tok) {
    if (QString::fromUtf8(body).contains(tok)) return QStringLiteral("body");
    // Only headers a shared cache stores and replays cross-user count as a
    // poisoning surface. Set-Cookie and other per-response / hop-by-hop headers
    // are stripped or not replayed by compliant caches (RFC 9111 7.3 / 3), so a
    // token landing only there is a cookie-scoping / header-injection issue,
    // not web cache poisoning -- excluding them kills that false-positive class.
    static const QStringList replayed = {
        QStringLiteral("Location"),
        QStringLiteral("Content-Location"),
        QStringLiteral("Link"),
    };
    for (const auto &h : headers) {
        if (!h.second.contains(tok)) continue;
        for (const QString &name : replayed)
            if (h.first.compare(name, Qt::CaseInsensitive) == 0)
                return QStringLiteral("header:") + h.first;
    }
    return QString();
}

bool cacheHitSignal(const Headers &headers) {
    if (!headerValue(headers, "Age").isEmpty()) return true;
    const QString xc = headerValue(headers, "X-Cache") + " "
                     + headerValue(headers, "X-Cache-Status") + " "
                     + headerValue(headers, "CF-Cache-Status") + " "
                     + headerValue(headers, "X-Served-By");
    return xc.contains("hit", Qt::CaseInsensitive);
}

int ccSeconds(const QString &cc, const QString &directive) {
    QRegularExpression re(directive + "\\s*=\\s*\"?(\\d+)",
                          QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(cc);
    return m.hasMatch() ? m.captured(1).toInt() : -1;
}

bool looksCacheable(const Headers &headers, const QString &injectedHeader) {
    if (cacheHitSignal(headers)) return true;
    // A response that Varys on the very header we injected is keyed on it: the
    // cache stores one entry per header value, so a victim sending a different
    // (or no) value is served a different entry -- not poisonable cross-user.
    // "*" means uncacheable by definition. Mirrors passive_scanner's Vary read.
    const QString vary = headerValue(headers, "Vary");
    if (!vary.isEmpty()) {
        if (vary.contains('*')) return false;
        if (!injectedHeader.isEmpty()) {
            const auto parts = vary.split(',');
            for (const QString &p : parts)
                if (p.trimmed().compare(injectedHeader, Qt::CaseInsensitive) == 0)
                    return false;
        }
    }
    const QString cc = headerValue(headers, "Cache-Control").toLower();
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
    if (!headerValue(headers, "Expires").isEmpty()) return true;
    return false;
}

QByteArray buildRequest(const Request &req, const QString &query,
                        const QString &extraHeader, const QString &extraValue) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // The request line and Host are attacker-influenceable on the HAR-import /
    // deep-audit path (method/host/basePath are set raw, bypassing the JSON
    // method choke-point). A CR/LF in any of them would smuggle a second
    // request line or header -- refuse to build rather than emit it.
    if (crlf(req.method) || crlf(req.host) || crlf(req.basePath))
        return QByteArray();

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
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!extraHeader.isEmpty() && !crlf(extraHeader) && !crlf(extraValue))
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

Gate gateDecision(bool bOk, bool bHit, bool cOk, bool cHit) {
    // FAIL CLOSED. Inject only when the buster is PROVEN to partition the cache
    // key. "No observable hit" or "couldn't confirm" both block injection --
    // never permit it -- so a silent cache (stores+serves but emits no hit
    // header) can no longer slip an unkeyed poison onto the real shared key.
    if (!bOk || !bHit) return Gate::AbortNoHitSignal;
    if (!cOk)          return Gate::AbortConfirmFailed;
    if (cHit)          return Gate::AbortUnkeyed;  // different buster also hit
    return Gate::Inject;                           // same buster hit, different missed
}

} // namespace Nullock::Core::CachePoison

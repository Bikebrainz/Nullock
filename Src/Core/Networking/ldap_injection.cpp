#include "ldap_injection.hpp"
#include "networking.hpp"

#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::LdapInjection {

namespace {

constexpr int kMaxSends  = 80;
constexpr int kMaxParams = 12;

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

} // namespace

QStringList defaultParams() {
    // Ordered by LDAP yield so the cap keeps the highest-signal names; overflow
    // (for caller-supplied query params) goes to droppedParams.
    return { "filter", "cn", "uid", "user", "username", "login",
             "search", "q", "name", "email", "id", "group" };
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
    if (params.size() > kMaxParams) {
        result.droppedParams = params.mid(kMaxParams);   // surfaced so a clean
        params = params.mid(0, kMaxParams);              // result isn't silently partial
    }
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
    // If the baseline already shows an LDAP error, we can't attribute one to us.
    const bool baselineErrored = !matchError(base.parsed.body).first.isEmpty();

    // Filter-breakers (unbalanced parens / metacharacters likely to break the
    // search filter) and a benign value that should NOT error if the breaker did.
    struct Probe { const char *breaker; const char *safe; };
    static const QList<Probe> probes = {
        { "*)(",      "nullocksafe" },
        { ")(",       "nullocksafe" },
        { ")",        "nullocksafe" },
        { "*))",      "nullocksafe" },
        { ")(cn=*)",  "nullocksafe" },
    };

    QSet<QString> confirmedParams;
    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        if (confirmedParams.contains(param)) continue;
        for (const Probe &p : probes) {
            if (result.requestsSent >= kMaxSends) break;
            const auto r = send(queryWith(req.query, param, QString::fromUtf8(p.breaker)));
            if (!r.ok) continue;
            const auto err = matchError(r.parsed.body);
            if (err.first.isEmpty()) continue;
            // A generic-family match on a block-ish status is a WAF/edge block,
            // not a backend filter break -- reject (engine-specific fingerprints,
            // which a block page won't carry, are trusted on any status).
            if (err.first == "generic" && isBlockStatus(r.parsed.statusCode)) continue;
            // Corroborate: a benign metacharacter-free value should NOT produce
            // the LDAP error. If it ALSO errors (or the baseline already did),
            // the error isn't driven by our filter break -- skip.
            if (baselineErrored) continue;
            const auto rs = send(queryWith(req.query, param, QString::fromUtf8(p.safe)));
            if (!rs.ok || !matchError(rs.parsed.body).first.isEmpty()) continue;
            result.hits.append({ param, err.first,
                                 QString::fromUtf8(p.breaker), err.second });
            result.vulnerable = true;
            confirmedParams.insert(param);
            break;
        }
    }

    return result;
}

} // namespace Nullock::Core::LdapInjection

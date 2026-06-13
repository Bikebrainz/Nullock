#include "nosql_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::NoSqlInjection {

namespace {

constexpr int kMaxSends = 90;

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/nosqli\r\n";
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

bool lenDiffers(int a, int b) {
    const int mx = qMax(a, b), d = qAbs(a - b);
    return mx > 0 && d > 40 && double(d) / mx > 0.25;
}
// Strict complement of lenDiffers -- every pair is classified exactly once,
// so there's no dead zone where a response is neither similar nor different.
bool lenSimilar(int a, int b) { return !lenDiffers(a, b); }

QString randVal() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 8; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

} // namespace

QStringList defaultParams() {
    return { "user", "username", "email", "login", "id", "name", "search",
             "q", "query", "filter", "role", "account", "password" };
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
        if (result.requestsSent + 4 > kMaxSends) break;
        const QString rv = randVal();
        // TWO literal probes first: they must agree, or the page is dynamic and
        // the differential can't be trusted -- skip rather than false-positive.
        const auto lit1 = send(queryLiteral(req.query, param, rv));
        const auto lit2 = send(queryLiteral(req.query, param, rv));
        if (!lit1.ok || !lit2.ok) continue;
        const int lit1Len = lit1.parsed.body.size();
        const int lit2Len = lit2.parsed.body.size();
        const int litStatus = lit1.parsed.statusCode;
        if (litStatus != lit2.parsed.statusCode || !lenSimilar(lit1Len, lit2Len))
            continue;   // unstable baseline

        // Then the always-true ($ne) and always-false ($eq) operators, same value.
        const auto ne = send(queryOp(req.query, param, "ne", rv));
        const auto eq = send(queryOp(req.query, param, "eq", rv));
        if (!ne.ok || !eq.ok) continue;
        const int neLen = ne.parsed.body.size();
        const int eqLen = eq.parsed.body.size();

        // An ERROR status on $ne over an OK literal is type-confusion (the app
        // got an object where it wanted a string), NOT a NoSQL over-match.
        if (ne.parsed.statusCode >= 400 && litStatus < 400) continue;

        // $ne interpreted as an operator: it matched a different/larger set
        // (length diverges beyond the baseline noise) or flipped to a *success*
        // status the literal didn't have. $eq must track the literal (matched
        // nothing, like the bogus value).
        const bool neStatusSuccessDiverge = ne.parsed.statusCode != litStatus
            && ne.parsed.statusCode >= 200 && ne.parsed.statusCode < 400;
        const bool neDiverged = (lenDiffers(neLen, lit1Len) && lenDiffers(neLen, lit2Len))
                             || neStatusSuccessDiverge;
        const bool eqTracksLit = lenSimilar(eqLen, lit1Len)
                             && (eq.parsed.statusCode == litStatus);
        if (neDiverged && eqTracksLit) {
            result.hits.append({ param,
                QStringLiteral("$ne len=%1/status=%2 vs literal len=%3/status=%4; "
                               "$eq tracked literal (len=%5)")
                    .arg(neLen).arg(ne.parsed.statusCode)
                    .arg(lit1Len).arg(litStatus).arg(eqLen) });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::NoSqlInjection

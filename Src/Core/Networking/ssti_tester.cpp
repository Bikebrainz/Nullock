#include "ssti_tester.hpp"
#include "networking.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QUrlQuery>

namespace Nullock::Core::Ssti {

namespace {

// Each delimiter family, with the wrapper either side of the arithmetic.
// The candidate engines are the ones that evaluate that exact syntax, so
// the family that fires is a real fingerprint, not a guess.
struct Family {
    const char *wrapL;
    const char *wrapR;
    const char *engines;
};
const QList<Family> &families() {
    static const QList<Family> f = {
        { "{{",   "}}",  "Jinja2, Twig, Nunjucks, Liquid, Django" },
        { "${{",  "}}",  "Tornado" },
        { "${",    "}",  "Freemarker, JSP EL, Mako, Thymeleaf" },
        { "<%= ", " %>", "ERB, EJS" },
        { "#{",    "}",  "Ruby (#{}), JSF EL, Slim" },
        { "*{",    "}",  "Thymeleaf" },
        { "@(",    ")",  "Razor (.NET)" },
        { "{",     "}",  "Smarty" },
    };
    return f;
}

// A short alphanumeric token that survives query/form percent-encoding and
// won't be mangled by a template engine -- used to bracket the injected
// expression so we can locate exactly where it was rendered.
QString randToken() {
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    QString s;
    for (int i = 0; i < 7; ++i)
        s += alpha[QRandomGenerator::global()->bounded(int(sizeof(alpha) - 1))];
    return s;
}

QByteArray buildRequest(const Request &req, const QString &path,
                        const QString &query, const QByteArray &body) {
    const QString target = query.isEmpty() ? path : path + "?" + query;
    const bool bodyMethod = req.method.compare("POST",  Qt::CaseInsensitive) == 0
                         || req.method.compare("PUT",   Qt::CaseInsensitive) == 0
                         || req.method.compare("PATCH", Qt::CaseInsensitive) == 0;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ssti\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!body.isEmpty() || bodyMethod) {
        const QString ct = req.contentType.isEmpty()
            ? (req.paramIn == "json" ? QStringLiteral("application/json")
                                     : QStringLiteral("application/x-www-form-urlencoded"))
            : req.contentType;
        out += "Content-Type: " + ct.toUtf8() + "\r\n";
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

// Place `value` into the named parameter, returning the (query, body) pair
// to send. Only the targeted location is rewritten.
QPair<QString, QByteArray> withParam(const Request &req, const QString &value) {
    QString query = req.query;
    QByteArray body = req.body;
    if (req.paramIn == "json") {
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(req.body, &err);
        QJsonObject obj = (err.error == QJsonParseError::NoError && doc.isObject())
                          ? doc.object() : QJsonObject{};
        obj.insert(req.paramName, value);
        body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    } else if (req.paramIn == "form") {
        QUrlQuery q(QString::fromUtf8(req.body));
        q.removeAllQueryItems(req.paramName);
        q.addQueryItem(req.paramName, value);
        body = q.toString(QUrl::FullyEncoded).toUtf8();
    } else { // query
        QUrlQuery q(query);
        q.removeAllQueryItems(req.paramName);
        q.addQueryItem(req.paramName, value);
        query = q.toString(QUrl::FullyEncoded);
    }
    return { query, body };
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty())      { result.error = "host required";  return result; }
    if (req.paramName.isEmpty()) { result.error = "paramName required"; return result; }
    // For a JSON endpoint with a real body, injecting into a guessed object
    // would clobber every other field; refuse rather than test an error page.
    if (req.paramIn == "json" && !req.body.isEmpty()) {
        QJsonParseError e; QJsonDocument::fromJson(req.body, &e);
        if (e.error != QJsonParseError::NoError) {
            result.error = "body is not valid JSON (required for in=json)";
            return result;
        }
    }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query, const QByteArray &body) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, req.basePath, query, body));
    };

    // Operands: randomized unless caller pinned them (clamped to a sane size
    // so the product stays a recognizable 7-10 digit number).
    auto pick = [] { return QRandomGenerator::global()->bounded(1000u, 9999u); };
    const quint64 a = req.seedA ? qBound(1000u, req.seedA, 999999u) : pick();
    const quint64 b = req.seedB ? qBound(1000u, req.seedB, 999999u) : pick();
    const QString expr    = QStringLiteral("%1*%2").arg(a).arg(b);
    const QString product = QString::number(a * b);
    // Bracket the expression with random sentinels. Evaluation yields
    // "<pre><product><suf>"; plain reflection yields "<pre>{{<expr>}}<suf>".
    // Matching the sentinel-delimited region -- not the bare product -- is
    // what makes confirmation immune to coincidental digits elsewhere on the
    // page and to engines that group/format the number.
    const QString pre = "z" + randToken();
    const QString suf = randToken() + "z";

    // Baseline with a benign value: establishes status and that the param is
    // actually rendered (the sentinels come back) without any template syntax.
    const auto basePair = withParam(req, pre + QStringLiteral("nullock") + suf);
    const auto base = send(basePair.first, basePair.second);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    result.injected = true;

    // Pull the text the server placed between our sentinels, if any. Bounded
    // so a stray suffix far down the page can't make us scan a huge span.
    auto rendered = [&](const QString &body) -> QString {
        int p = body.indexOf(pre);
        while (p >= 0) {
            const int from = p + pre.size();
            const int s = body.indexOf(suf, from);
            if (s < 0) break;
            if (s - from <= 64) return body.mid(from, s - from);
            p = body.indexOf(pre, from);
        }
        return QString();
    };

    for (const Family &fam : families()) {
        const QString payload = pre + QString::fromUtf8(fam.wrapL) + expr
                              + QString::fromUtf8(fam.wrapR) + suf;
        const auto pr = withParam(req, payload);
        const auto r = send(pr.first, pr.second);
        if (!r.ok) continue;
        const QString region = rendered(QString::fromUtf8(r.parsed.body));
        if (region.isEmpty()) continue;
        // Evaluated iff the rendered region carries the product (after
        // stripping locale grouping/space) and is NOT the literal expression.
        QString norm = region; norm.remove(',').remove(' ');
        if (norm.contains(product) && !region.contains(expr)) {
            const QString fired = QString::fromUtf8(fam.wrapL) + " "
                                + QString::fromUtf8(fam.wrapR);
            result.hits.append({ fired.trimmed(), QString::fromUtf8(fam.engines),
                QStringLiteral("evaluated %1 to %2").arg(expr, product) });
            result.confirmed = true;
        }
    }
    if (!result.hits.isEmpty()) result.engines = result.hits.first().engines;

    // Secondary, weaker signal: a template syntax break that 5xx's a
    // previously-OK endpoint. To avoid flagging servers that simply 500 on
    // any odd input, require a control payload with the *same* special chars
    // but no template delimiters to come back clean.
    if (!result.confirmed && result.baselineStatus < 500) {
        const auto bp = withParam(req, pre + QStringLiteral("${{<%[%'\"}}%\\") + suf);
        const auto br = send(bp.first, bp.second);
        const bool delimBroke = br.ok && br.parsed.statusCode >= 500;
        if (delimBroke) {
            const auto cp = withParam(req, pre + QStringLiteral("[%'\"\\]abc") + suf);
            const auto cr = send(cp.first, cp.second);
            const bool ctrlBroke = cr.ok && cr.parsed.statusCode >= 500;
            if (!ctrlBroke) result.engineLikely = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::Ssti

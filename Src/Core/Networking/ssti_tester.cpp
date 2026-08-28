#include "ssti_tester.hpp"
#include "networking.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QUrlQuery>

namespace Nullock::Core::Ssti {

namespace {

// Each delimiter family, with the wrapper either side of the arithmetic.
// The candidate engines are the ones that evaluate that exact INFIX syntax, so
// the family that fires is a real fingerprint, not a guess. (Go text/template
// uses {{mul a b}} function-call form, not infix a*b -- tracked as a follow-up.)
struct Family {
    const char *wrapL;
    const char *wrapR;
    const char *engines;
};
const QList<Family> &families() {
    static const QList<Family> f = {
        { "{{",   "}}",  "Jinja2, Twig, Nunjucks, Liquid, Pebble" },
        { "${{",  "}}",  "Tornado" },
        { "${",    "}",  "Freemarker, JSP EL, Mako, Thymeleaf" },
        // OGNL: Apache Struts2 evaluates %{...} as an OGNL expression wherever
        // user input reaches an OGNL-parsed sink (the S2-0xx / CVE-2017-5638
        // class). No other engine here uses the %{ } pair, so a confirmed hit
        // fingerprints OGNL/Struts specifically -- the active probe the roadmap
        // wanted beyond version-based CVE correlation.
        { "%{",    "}",  "OGNL (Apache Struts2)" },
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

// A letters-only literal separator placed BETWEEN the two delimited
// expressions; a template renders it verbatim while evaluating both sides, but
// a single-expression calculator cannot reproduce "<productA><sep><productB>".
QString randAlpha(int n) {
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
    QString s;
    for (int i = 0; i < n; ++i)
        s += alpha[QRandomGenerator::global()->bounded(int(sizeof(alpha) - 1))];
    return s;
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

    // Two independent operand pairs (a*b, c*d). a,b honor caller seeds; clamped
    // so the products stay recognizable multi-digit numbers.
    auto pick = [] { return QRandomGenerator::global()->bounded(1000u, 9999u); };
    const quint64 a = req.seedA ? qBound(1000u, req.seedA, 999999u) : pick();
    const quint64 b = req.seedB ? qBound(1000u, req.seedB, 999999u) : pick();
    const quint64 c = pick();
    const quint64 d = pick();
    const QString exprA = QStringLiteral("%1*%2").arg(a).arg(b);
    const QString exprB = QStringLiteral("%1*%2").arg(c).arg(d);
    const QString productA = QString::number(a * b);
    const QString productB = QString::number(c * d);
    // Random sentinels bracket the whole construct; a letters-only separator
    // sits between the two delimited expressions. Evaluation yields
    // "<pre><productA><sep><productB><suf>"; reflection yields the literals.
    const QString pre = "z" + randToken();
    const QString suf = randToken() + "z";
    const QString sep = randAlpha(5);

    // Baseline with a benign value: establishes status and that the param is
    // actually rendered (the sentinels come back) without any template syntax.
    const auto basePair = withParam(req, pre + QStringLiteral("nullock") + suf);
    const auto base = send(basePair.first, basePair.second);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    result.injected = true;

    for (const Family &fam : families()) {
        const QString wL = QString::fromUtf8(fam.wrapL);
        const QString wR = QString::fromUtf8(fam.wrapR);
        const QString payload = pre + wL + exprA + wR + sep + wL + exprB + wR + suf;
        const auto pr = withParam(req, payload);
        const auto r = send(pr.first, pr.second);
        if (!r.ok) continue;
        const auto regions = renderedRegions(QString::fromUtf8(r.parsed.body), pre, suf);
        // Confirmed only when BOTH delimited expressions evaluated with the
        // literal separator preserved between them -- template behavior, not a
        // calculator computing a single a*b.
        if (confirmsArithmetic(regions, productA, sep, productB, exprA, exprB)) {
            const QString fired = wL.trimmed() + " " + wR.trimmed();
            result.hits.append({ fired.trimmed(), QString::fromUtf8(fam.engines),
                QStringLiteral("evaluated %1 and %2 to %3 / %4")
                    .arg(exprA, exprB, productA, productB) });
            result.confirmed = true;
        }
    }
    if (!result.hits.isEmpty()) result.engines = result.hits.first().engines;

    // Secondary, weaker signal: a template syntax break that 5xx's a
    // previously-OK endpoint. The control is a TRUE minimal pair -- the same
    // length and the same multiset of special characters, with ONLY the
    // template-delimiter bigrams (${{, {{, <%, }}) broken up -- so a WAF or a
    // char/length-sensitive 500 fires on BOTH and cancels, leaving only a
    // genuine template-parse 5xx to credit.
    if (!result.confirmed && result.baselineStatus < 500) {
        const auto bp = withParam(req, pre + QStringLiteral("${{<%[%'\"}}%\\") + suf);
        const auto br = send(bp.first, bp.second);
        const bool delimBroke = br.ok && br.parsed.statusCode >= 500;
        if (delimBroke) {
            const auto cp = withParam(req, pre + QStringLiteral("{%{%<[%$'\"}\\}") + suf);
            const auto cr = send(cp.first, cp.second);
            // Fail-closed: only credit the syntax-break 5xx when the minimal-pair
            // control actually completed and did NOT itself 5xx.
            result.engineLikely = engineLikelyFrom(result.baselineStatus, br.ok,
                                                   br.parsed.statusCode,
                                                   cr.ok, cr.parsed.statusCode);
        }
    }

    return result;
}

} // namespace Nullock::Core::Ssti

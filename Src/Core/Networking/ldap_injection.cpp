#include "ldap_injection.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::LdapInjection {

namespace {

constexpr int kMaxSends = 80;
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *engine; QRegularExpression re; };

const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        { "Java/JNDI", QRegularExpression("javax\\.naming\\.|com\\.sun\\.jndi\\.ldap|"
                                          "org\\.springframework\\.ldap|"
                                          "InvalidSearchFilterException|LDAPException", ci) },
        { ".NET",      QRegularExpression("System\\.DirectoryServices|DirectoryServicesCOMException|"
                                          "DirectoryEntry", ci) },
        { "PHP",       QRegularExpression("ldap_(search|bind|list|read|modify|add|delete)\\s*\\(\\)|"
                                          "supplied argument is not a valid ldap", ci) },
        { "Python",   QRegularExpression("ldap\\.(FILTER_ERROR|INVALID_SYNTAX|OPERATIONS_ERROR|"
                                          "INVALID_DN_SYNTAX)|python-ldap", ci) },
        { "generic",  QRegularExpression("Bad search filter|Invalid DN syntax|invalid search filter|"
                                          "LDAP: error code|LDAP error", ci) },
    };
    return s;
}

// Match an LDAP error in `body`; returns {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.engine), m.captured(0) };
    }
    return {};
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ldapi\r\n";
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

} // namespace

QStringList defaultParams() {
    return { "user", "username", "uid", "login", "search", "q", "name",
             "email", "cn", "id", "filter", "group" };
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

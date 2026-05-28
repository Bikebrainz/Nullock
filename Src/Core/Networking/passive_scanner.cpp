#include "passive_scanner.hpp"

#include <QDateTime>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QStringList>

namespace Nullock::Core {

namespace {

// Tokens/keys that show up in URL query strings are almost always a
// mistake -- they end up in proxy logs, referer headers, and browser
// history. Substring match against lowercased parameter names.
const QStringList kSensitiveQueryKeys = {
    "token", "access_token", "id_token", "auth", "authorization",
    "api_key", "apikey", "key", "secret", "password", "passwd",
    "session", "sid", "sessionid", "jwt", "code",
};

constexpr int kCap = 1000;

bool isHtmlResponse(const QString &contentType) {
    return contentType.contains("text/html",          Qt::CaseInsensitive)
        || contentType.contains("application/xhtml",  Qt::CaseInsensitive);
}

} // namespace

PassiveScanner::PassiveScanner(QObject *parent) : QObject(parent) {}

int PassiveScanner::count() const {
    QMutexLocker lock(&m_mutex);
    return m_findings.size();
}

QList<Finding> PassiveScanner::findings(int limit) const {
    QMutexLocker lock(&m_mutex);
    if (limit >= m_findings.size()) return m_findings;
    // Return the newest-first slice so the UI list is interesting at the
    // top without sorting client-side.
    QList<Finding> out;
    out.reserve(limit);
    for (int i = m_findings.size() - 1; i >= 0 && out.size() < limit; --i)
        out.append(m_findings[i]);
    return out;
}

void PassiveScanner::setNextRowId(int n) {
    QMutexLocker lock(&m_mutex);
    m_nextRowId = n;
}

void PassiveScanner::clear() {
    {
        QMutexLocker lock(&m_mutex);
        m_findings.clear();
        m_nextId = 1;
    }
    emit findingsChanged();
}

void PassiveScanner::reportFinding(int rowId,
                                   const QString &severity,
                                   const QString &kind,
                                   const QString &summary,
                                   const QString &evidence,
                                   const QString &host,
                                   const QString &url) {
    Finding f;
    {
        QMutexLocker lock(&m_mutex);
        f.id    = m_nextId++;
        f.rowId = rowId;
    }
    f.ts       = QDateTime::currentDateTime();
    f.severity = severity;
    f.kind     = kind;
    f.summary  = summary;
    f.evidence = evidence;
    f.host     = host;
    f.url      = url;
    {
        QMutexLocker lock(&m_mutex);
        m_findings.append(f);
        if (m_findings.size() > 1000) m_findings.removeFirst();
    }
    emit findingsChanged();
}

QString PassiveScanner::headerOf(const QList<QPair<QString, QString>> &headers,
                                 const QString &name) const {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QList<QString> PassiveScanner::allHeaderValues(
        const QList<QPair<QString, QString>> &headers,
        const QString &name) const {
    QList<QString> out;
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out.append(h.second);
    return out;
}

void PassiveScanner::onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                                        const Nullock::Proxy::HttpResponse &resp) {
    // We only audit "normal" HTTP responses, not the synthetic WS frame
    // entries the proxy emits.
    if (req.method.startsWith("WS")) return;
    // Each call to responseReceived corresponds to one history row. We
    // claim the row id here -- shared across every finding emitted while
    // this response is being checked.
    int rowId = 0;
    {
        QMutexLocker lock(&m_mutex);
        rowId = m_nextRowId++;
    }
    checkResponse(rowId, req, resp);
}

void PassiveScanner::addFinding(int rowId,
                                const Nullock::Proxy::HttpRequest &req,
                                const Nullock::Proxy::HttpResponse &resp,
                                const QString &severity,
                                const QString &kind,
                                const QString &summary,
                                const QString &evidence) {
    Finding f;
    {
        QMutexLocker lock(&m_mutex);
        f.id       = m_nextId++;
        f.rowId    = rowId;
    }
    f.ts       = QDateTime::currentDateTime();
    f.severity = severity;
    f.kind     = kind;
    f.summary  = summary;
    f.evidence = evidence;
    f.host     = req.host;
    QString proto = resp.wasTls ? "https" : "http";
    QString port  = (req.port == 80 || req.port == 443)
                    ? QString() : ":" + QString::number(req.port);
    f.url      = proto + "://" + req.host + port + (req.path.startsWith('/')
                                                    ? req.path
                                                    : "/" + req.path);
    bool over = false;
    {
        QMutexLocker lock(&m_mutex);
        m_findings.append(f);
        over = (m_findings.size() > kCap);
        if (over) m_findings.removeFirst();
    }
    emit findingsChanged();
}

void PassiveScanner::checkResponse(int rowId,
                                   const Nullock::Proxy::HttpRequest &req,
                                   const Nullock::Proxy::HttpResponse &resp) {
    // Only audit HTML pages for the missing-header set -- application/json
    // / images / etc don't need a CSP. The cookie checks fire regardless.
    const QString contentType = headerOf(resp.headers, "Content-Type");
    const bool html = isHtmlResponse(contentType);

    if (html && resp.statusCode >= 200 && resp.statusCode < 400) {
        struct Rule {
            const char *header;
            const char *kind;
            const char *summary;
            const char *severity;
        };
        const Rule rules[] = {
            { "Content-Security-Policy", "missing-csp",
              "No Content-Security-Policy header",                "medium" },
            { "Strict-Transport-Security", "missing-hsts",
              "No Strict-Transport-Security header on TLS resp",  "medium" },
            { "X-Frame-Options", "missing-xfo",
              "No X-Frame-Options header (clickjacking risk)",    "low" },
            { "X-Content-Type-Options", "missing-xcto",
              "No X-Content-Type-Options: nosniff",               "low" },
            { "Referrer-Policy", "missing-rp",
              "No Referrer-Policy header",                        "info" },
        };
        for (const auto &r : rules) {
            const QString v = headerOf(resp.headers, r.header);
            if (v.isEmpty()) {
                // HSTS only matters on TLS responses.
                if (QString::fromLatin1(r.kind) == "missing-hsts" && !resp.wasTls) continue;
                addFinding(rowId, req, resp, r.severity, r.kind, r.summary,
                           QString("absent on %1").arg(req.host));
            }
        }
    }

    // Set-Cookie hardening flags. Most servers set the cookie multiple
    // times in one response (auth + csrf + lang) so walk every one.
    for (const QString &cookie : allHeaderValues(resp.headers, "Set-Cookie")) {
        const QString lc = cookie.toLower();
        const QString name = cookie.section('=', 0, 0).trimmed();
        if (!lc.contains("httponly"))
            addFinding(rowId, req, resp, "low", "cookie-no-httponly",
                       "Cookie set without HttpOnly: " + name,
                       cookie.left(240));
        if (resp.wasTls && !lc.contains("secure"))
            addFinding(rowId, req, resp, "low", "cookie-no-secure",
                       "Cookie set on TLS without Secure: " + name,
                       cookie.left(240));
        if (!lc.contains("samesite"))
            addFinding(rowId, req, resp, "info", "cookie-no-samesite",
                       "Cookie set without SameSite: " + name,
                       cookie.left(240));
    }

    // Server header version leak. The bare product name is normally
    // fine; "Apache/2.4.41 (Ubuntu)" is information disclosure.
    const QString server = headerOf(resp.headers, "Server");
    if (server.contains(QChar('/')) && server.contains(QRegularExpression("\\d"))) {
        addFinding(rowId, req, resp, "low", "server-version-leak",
                   "Server header leaks software version",
                   "Server: " + server);
    }
    const QString xpb = headerOf(resp.headers, "X-Powered-By");
    if (!xpb.isEmpty()) {
        addFinding(rowId, req, resp, "info", "x-powered-by",
                   "X-Powered-By header discloses stack",
                   "X-Powered-By: " + xpb);
    }

    // CORS misconfig: ACAO: * with credentials is the dangerous shape,
    // but plain "*" is still surfaced as info since it's often wrong.
    const QString acao = headerOf(resp.headers, "Access-Control-Allow-Origin");
    const QString acac = headerOf(resp.headers, "Access-Control-Allow-Credentials");
    if (acao == "*" && acac.compare("true", Qt::CaseInsensitive) == 0) {
        addFinding(rowId, req, resp, "high", "cors-wildcard-creds",
                   "ACAO: * with Allow-Credentials: true (browsers reject "
                   "but the intent is dangerous)",
                   "ACAO: " + acao + " · ACAC: " + acac);
    } else if (acao == "*") {
        addFinding(rowId, req, resp, "info", "cors-wildcard",
                   "Access-Control-Allow-Origin: *",
                   "ACAO: *");
    }

    // Sensitive token in URL query string. Picks up GETs that leak
    // bearer-style auth.
    const int qmark = req.path.indexOf('?');
    if (qmark >= 0) {
        const QString query = req.path.mid(qmark + 1);
        const QStringList parts = query.split('&', Qt::SkipEmptyParts);
        for (const QString &p : parts) {
            const QString key = p.section('=', 0, 0).toLower();
            for (const QString &sk : kSensitiveQueryKeys) {
                if (key == sk || key.contains(sk)) {
                    addFinding(rowId, req, resp, "medium", "secret-in-url",
                               "Sensitive parameter in URL query: " + key,
                               p.left(240));
                    break;
                }
            }
        }
    }

    // Bearer / Authorization on a non-TLS connection.
    if (!resp.wasTls) {
        const QString authz = headerOf(req.headers, "Authorization");
        if (!authz.isEmpty()) {
            addFinding(rowId, req, resp, "high", "auth-over-http",
                       "Authorization header sent over plaintext HTTP",
                       "Authorization: " + authz.left(80) + (authz.size() > 80 ? "..." : ""));
        }
    }
}

} // namespace Nullock::Core

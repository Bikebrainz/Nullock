#include "secret_scanner.hpp"
#include "networking.hpp"

#include <QHash>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <cmath>

namespace Nullock::Core::SecretScanner {

namespace {

struct Pattern {
    const char *type;
    const char *severity;
    QRegularExpression re;
    int  group;          // capture group holding the secret (0 = whole match)
    bool entropyGated;   // require the captured value to look random
};

// All entries are regexes describing key *shapes* -- never literal secrets, so
// nothing here trips a secret scanner of our own. High-signal provider prefixes
// keep false positives near zero; the one generic rule is entropy-gated.
const QList<Pattern> &patterns() {
    static const QList<Pattern> p = {
        { "private-key-block", "critical",
          QRegularExpression("-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0, false },
        { "aws-access-key-id", "high",
          QRegularExpression("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"), 0, false },
        { "google-api-key", "high",
          QRegularExpression("\\bAIza[0-9A-Za-z_\\-]{35}\\b"), 0, false },
        { "stripe-secret-key", "high",
          QRegularExpression("\\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\\b"), 0, false },
        { "github-token", "high",
          QRegularExpression("\\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\\b"), 0, false },
        { "github-pat", "high",
          QRegularExpression("\\bgithub_pat_[0-9A-Za-z_]{22,}\\b"), 0, false },
        { "slack-token", "high",
          QRegularExpression("\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b"), 0, false },
        { "sendgrid-key", "high",
          QRegularExpression("\\bSG\\.[0-9A-Za-z_\\-]{22}\\.[0-9A-Za-z_\\-]{43}\\b"), 0, false },
        { "npm-token", "high",
          QRegularExpression("\\bnpm_[0-9A-Za-z]{36}\\b"), 0, false },
        { "twilio-account-sid", "medium",
          QRegularExpression("\\bAC[0-9a-fA-F]{32}\\b"), 0, false },
        { "json-web-token", "medium",
          QRegularExpression("\\beyJ[A-Za-z0-9_\\-]{8,}\\.eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,}\\b"), 0, false },
        { "assigned-secret", "medium",
          QRegularExpression("(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|"
                             "auth[_-]?token|client[_-]?secret|private[_-]?key)"
                             "\"?\\s*[:=]\\s*([\"'])([A-Za-z0-9+/_\\-]{20,120})\\1"), 2, true },
    };
    return p;
}

// Cap the bytes we run the regex table over -- a malicious or just large
// minified bundle could otherwise pin a core across ~13 sweeps per resource.
constexpr int kMaxScanBytes = 2 * 1024 * 1024;

double shannon(const QString &s) {
    if (s.isEmpty()) return 0.0;
    QHash<QChar, int> freq;
    for (QChar c : s) ++freq[c];
    double h = 0.0;
    const double n = s.size();
    for (auto it = freq.begin(); it != freq.end(); ++it) {
        const double pr = it.value() / n;
        h -= pr * std::log2(pr);
    }
    return h;
}

// Obvious non-secrets that an entropy gate alone would miss. Word/structural
// tokens are strong signals as substrings; for repetition we require a long
// run so a real key that merely contains "1234"/"0000" isn't discarded.
bool looksPlaceholder(const QString &v) {
    static const QRegularExpression words(
        "(?i)example|placeholder|your[_-]?|change[_-]?me|dummy|sample|redacted|"
        "process\\.env|import\\.meta|\\$\\{|<[a-z]");
    if (words.match(v).hasMatch()) return true;
    static const QRegularExpression run("(.)\\1{5,}"); // same char repeated 6+ times
    return run.match(v).hasMatch();
}

QString mask(const QString &secret) {
    const int n = secret.size();
    if (n <= 8) return QString("…(len %1)").arg(n);
    return secret.left(4) + "…" + secret.right(2) + QString(" (len %1)").arg(n);
}

QByteArray buildGet(const Request &req, const QString &path, const QString &query) {
    const QString target = query.isEmpty() ? path : path + "?" + query;
    QByteArray out;
    out  = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/secret-scan\r\n";
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

// Same-origin <script src> URLs from an HTML body, resolved to paths.
QStringList sameOriginScripts(const QString &body, const QUrl &base, int cap) {
    QStringList out;
    static const QRegularExpression re("<script[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']",
                                       QRegularExpression::CaseInsensitiveOption);
    const int basePort = base.port(base.scheme() == "https" ? 443 : 80);
    auto it = re.globalMatch(body);
    while (it.hasNext() && out.size() < cap) {
        const QUrl u = base.resolved(QUrl(it.next().captured(1), QUrl::TolerantMode));
        // Same origin only -- host, scheme AND port -- because every script is
        // fetched against the base's host/port/tls, so a differing port/scheme
        // would scan the wrong server.
        if (u.host().compare(base.host(), Qt::CaseInsensitive) != 0) continue;
        if (u.scheme().compare(base.scheme(), Qt::CaseInsensitive) != 0) continue;
        if (u.port(u.scheme() == "https" ? 443 : 80) != basePort) continue;
        QString pq = u.path();
        if (pq.isEmpty()) pq = "/";
        if (!u.query(QUrl::FullyEncoded).isEmpty()) pq += "?" + u.query(QUrl::FullyEncoded);
        if (!out.contains(pq)) out << pq;
    }
    return out;
}

} // namespace

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    QSet<QString> seen;   // de-dupe by type|value

    auto scanBody = [&](const QString &body, const QString &loc) {
        ++result.resourcesScanned;
        for (const Pattern &p : patterns()) {
            auto it = p.re.globalMatch(body);
            while (it.hasNext()) {
                const auto m = it.next();
                const QString secret = m.captured(p.group);
                if (secret.isEmpty()) continue;
                if (p.entropyGated) {
                    if (shannon(secret) < 3.8) continue;
                    if (looksPlaceholder(secret)) continue;
                }
                const QString dedupe = QString(p.type) + "|" + secret;
                if (seen.contains(dedupe)) continue;
                seen.insert(dedupe);
                // Build the context by splicing the mask in at the secret's
                // exact bounds -- never include the raw secret bytes, so a
                // long key can't leak in a truncated window (the secret is
                // the part we must NOT echo, masked or not).
                const int secStart = m.capturedStart(p.group);
                const int secEnd = secStart + secret.size();
                const int from = qMax(0, secStart - 12);
                const QString pre = body.mid(from, secStart - from);
                const QString post = body.mid(secEnd, qMin(12, body.size() - secEnd));
                const QString ctx = (pre + mask(secret) + post).simplified();
                result.hits.append({ p.type, p.severity, loc, mask(secret), ctx });
            }
        }
    };

    QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    ++result.requestsSent;
    const auto main = client.send(req.host, port, req.tls, buildGet(req, path, req.query));
    if (!main.ok) { result.error = "request failed: " + main.errorMessage; return result; }
    const QString mainBody = QString::fromUtf8(main.parsed.body.left(kMaxScanBytes));
    scanBody(mainBody, req.tls ? "https://" + req.host + path : "http://" + req.host + path);

    if (req.followScripts) {
        QUrl base;
        base.setScheme(req.tls ? "https" : "http");
        base.setHost(req.host); base.setPort(req.port); base.setPath(path);
        for (const QString &sp : sameOriginScripts(mainBody, base, req.maxScripts)) {
            const int q = sp.indexOf('?');
            const QString spath = q < 0 ? sp : sp.left(q);
            const QString squery = q < 0 ? QString() : sp.mid(q + 1);
            ++result.requestsSent;
            const auto sr = client.send(req.host, port, req.tls, buildGet(req, spath, squery));
            if (!sr.ok) continue;
            scanBody(QString::fromUtf8(sr.parsed.body.left(kMaxScanBytes)),
                     (req.tls ? "https://" : "http://") + req.host + spath);
        }
    }

    return result;
}

} // namespace Nullock::Core::SecretScanner

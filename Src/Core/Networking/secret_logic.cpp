// Pure (no-network) logic for the client-side secret scanner: the provider
// key-shape table, the entropy + placeholder filters (now applied to EVERY
// match), masking, the per-body scan, same-origin script extraction, and the
// GET builder's CR/LF guards. Split out of secret_scanner.cpp so
// Tests/secret_scanner links Qt6::Core alone.

#include "secret_scanner.hpp"

#include <QHash>
#include <QRegularExpression>
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

// All entries are regexes describing key *shapes* -- never literal secrets.
// High-signal provider prefixes keep false positives near zero; every match is
// additionally run through looksPlaceholder() (so documented EXAMPLE keys are
// dropped), and the one generic rule is entropy-gated.
const QList<Pattern> &patterns() {
    static const QList<Pattern> p = {
        { "private-key-block", "critical",
          QRegularExpression("-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0, false },
        { "aws-access-key-id", "high",
          QRegularExpression("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"), 0, false },
        { "google-api-key", "high",
          // Negative lookahead, NOT a trailing \b: a real 39-char Google key
          // whose final char is '-' (in the key's own charset) can't hold a word
          // boundary there, and the fixed {35} count can't backtrack, so \b made
          // ~1/64 of keys (dash-terminated) undetectable. The lookahead still
          // rejects an over-long run. (Same fix as passive_scanner/js_recon.)
          QRegularExpression("\\bAIza[0-9A-Za-z_\\-]{35}(?![0-9A-Za-z_\\-])"), 0, false },
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
        // An account SID is an IDENTIFIER, not a secret (the auth token is); and
        // "AC"+32-hex is the shape of any MD5/128-bit id -> low severity.
        { "twilio-account-sid", "low",
          QRegularExpression("\\bAC[0-9a-fA-F]{32}\\b"), 0, false },
        // A JWT in client code is frequently a PUBLIC token (e.g. a Supabase
        // anon key) -> low severity, operator judges.
        { "json-web-token", "low",
          QRegularExpression("\\beyJ[A-Za-z0-9_\\-]{8,}\\.eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,}\\b"), 0, false },
        { "assigned-secret", "medium",
          QRegularExpression("(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|"
                             "auth[_-]?token|client[_-]?secret|private[_-]?key)"
                             "\"?\\s*[:=]\\s*([\"'])([A-Za-z0-9+/_=\\-]{20,120})\\1"), 2, true },
    };
    return p;
}

constexpr int kMaxScanBytes = 2 * 1024 * 1024;

} // namespace

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

bool looksPlaceholder(const QString &v) {
    // Word/structural tokens that mark a non-secret. Kept to DISTINCTIVE tokens
    // (low collision with real high-entropy keys) plus the documented AWS
    // example body; short common substrings (foo/bar/test) are deliberately
    // excluded so they don't drop a real key that merely contains them.
    static const QRegularExpression words(
        "(?i)example|placeholder|your[_-]?|change[_-]?me|dummy|sample|redacted|"
        "deadbeef|0123456789|test[_-]?key|fake[_-]?key|notreal|insert[_-]?your|"
        "iosfodnn7|process\\.env|import\\.meta|\\$\\{|<[a-z]");
    if (words.match(v).hasMatch()) return true;
    static const QRegularExpression run("(.)\\1{5,}"); // same char repeated 6+ times
    return run.match(v).hasMatch();
}

bool acceptSecret(const QString &value, bool entropyGated) {
    if (value.isEmpty()) return false;
    if (looksPlaceholder(value)) return false;            // applied to EVERY match now
    if (entropyGated && shannon(value) < 3.8) return false;
    return true;
}

QString mask(const QString &secret) {
    const int n = secret.size();
    if (n <= 8) return QString("…(len %1)").arg(n);
    return secret.left(4) + "…" + secret.right(2) + QString(" (len %1)").arg(n);
}

QList<Hit> scanText(const QString &body, const QString &location) {
    QList<Hit> hits;
    for (const Pattern &p : patterns()) {
        auto it = p.re.globalMatch(body);
        while (it.hasNext()) {
            const auto m = it.next();
            const QString secret = m.captured(p.group);
            if (!acceptSecret(secret, p.entropyGated)) continue;
            // Splice the mask in at the secret's exact bounds -- never include
            // the raw secret bytes in the context window.
            const int secStart = m.capturedStart(p.group);
            const int secEnd = secStart + secret.size();
            const int from = qMax(0, secStart - 12);
            const QString pre = body.mid(from, secStart - from);
            const QString post = body.mid(secEnd, qMin(12, body.size() - secEnd));
            const QString ctx = (pre + mask(secret) + post).simplified();
            hits.append({ QString::fromUtf8(p.type), QString::fromUtf8(p.severity),
                          location, mask(secret), ctx });
        }
    }
    return hits;
}

QStringList sameOriginScripts(const QString &body, const QUrl &base, int cap) {
    QStringList out;
    static const QRegularExpression re("<script[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']",
                                       QRegularExpression::CaseInsensitiveOption);
    const int basePort = base.port(base.scheme() == "https" ? 443 : 80);
    auto it = re.globalMatch(body);
    while (it.hasNext() && out.size() < cap) {
        const QUrl u = base.resolved(QUrl(it.next().captured(1), QUrl::TolerantMode));
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

QByteArray buildGet(const Request &req, const QString &path, const QString &query) {
    if (req.host.contains('\r') || req.host.contains('\n')) return {};
    if (path.contains('\r') || path.contains('\n')) return {};
    if (query.contains('\r') || query.contains('\n')) return {};   // query is spliced into the request line raw
    const QString target = query.isEmpty() ? path : path + "?" + query;
    QByteArray out;
    out  = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/secret-scan\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // This probe emits a body-less GET; a carried Content-Length / Transfer-
        // Encoding from the source request would strand it (the server waits for a
        // body that never arrives -> the fetch times out, the page and its
        // same-origin scripts are never scanned -> secrets missed). Drop both.
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding: line 161 forces "identity" so the response
        // body is scanned as PLAINTEXT; a surviving "gzip, br" combines (RFC 7230
        // 3.2.2), the server compresses, the raw compressed bytes are scanned as UTF-8
        // text -> a real leaked secret is never matched (false clean).
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Connection: it is hop-by-hop and would duplicate / conflict
        // with the forced "Connection: close" (line 174).
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

int maxScanBytes() { return kMaxScanBytes; }

} // namespace Nullock::Core::SecretScanner

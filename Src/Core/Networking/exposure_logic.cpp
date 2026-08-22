// Pure (no-network) logic for the sensitive-file exposure scanner: the curated
// signature table, the content matcher (case-sensitivity / HTML rejection /
// min-match / evidence redaction), the GET builder's CR/LF guards, and the
// soft-404 calibration token. Split out of exposure_scan.cpp so
// Tests/exposure_scan links Qt6::Core alone.
//
// SIGNATURE POLICY: a 2xx alone is never enough (a catch-all 200s everything).
// A config FILE is never the HTML app shell, so rejectHtml drops a catch-all
// shell returned at /.env etc.; generic one-line signatures require >=2 matches;
// and scan() additionally calibrates against a bogus path (soft-404 control).

#include "exposure_scan.hpp"

#include <QRandomGenerator>
#include <QRegularExpression>

namespace Nullock::Core::ExposureScan {

namespace {
constexpr int kMaxBody = 256 * 1024;
} // namespace

const QList<Signature> &signatures() {
    // {path, pattern, severity, summary, caseSensitive, rejectHtml, minMatches, redact}
    static const QList<Signature> p = {
        { "/.git/config", "\\[core\\]|repositoryformatversion", "high",
          "Git repository config exposed -- full source + history is downloadable",
          false, true, 1, false },
        { "/.git/HEAD", "ref:\\s*refs/", "high", "Git repository exposed (.git/HEAD)",
          false, true, 1, false },
        { "/.env", "^[A-Z][A-Z0-9_]{2,}=\\S", "high",
          ".env file exposed -- application secrets/config readable",
          /*caseSensitive*/ true, /*rejectHtml*/ true, /*minMatches*/ 2, /*redact*/ true },
        { "/.svn/entries", "^\\s*\\d+\\s*$", "medium", "SVN metadata exposed",
          false, true, 3, false },
        { "/phpinfo.php", "phpinfo\\(\\)|<title>PHP [0-9]", "medium",
          "phpinfo() exposed -- full environment/config disclosure",
          false, false, 1, false },
        { "/server-status", "Apache Server Status", "medium",
          "Apache server-status exposed (request/IP disclosure)",
          false, false, 1, false },
        { "/.DS_Store", "Bud1", "low", ".DS_Store exposed -- leaks directory names",
          false, true, 1, false },
        { "/wp-config.php.bak", "DB_PASSWORD|DB_NAME|define\\s*\\(", "high",
          "WordPress config backup exposed -- database credentials",
          false, true, 1, true },
        { "/.aws/credentials", "aws_access_key_id", "high", "AWS credentials file exposed",
          false, true, 1, true },
        { "/docker-compose.yml", "^services:|^\\s+image:", "low",
          "docker-compose.yml exposed -- infrastructure detail",
          false, true, 2, false },
        { "/actuator/env", "\"propertySources\"|activeProfiles", "high",
          "Spring Boot Actuator /env exposed -- config + secrets",
          false, false, 1, true },
        { "/.git/", "Index of|Parent Directory", "medium", "Git directory listing exposed",
          false, false, 1, false },
        { "/config.php.bak", "DB_PASSWORD|mysql_connect|define\\s*\\(", "high",
          "PHP config backup exposed -- credentials",
          false, true, 1, true },
    };
    return p;
}

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 8; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

bool looksHtml(const QByteArray &body) {
    const QString head = QString::fromUtf8(body.left(1024)).toLower();
    return head.contains("<!doctype html") || head.contains("<html")
        || head.contains("<head") || head.contains("<script") || head.contains("<body");
}

QString matchSignature(const QByteArray &body, const Signature &sig) {
    // A plain-text/binary config file is never the HTML app shell -- if the
    // response is an HTML document, it's a catch-all/soft-404, not the file.
    if (sig.rejectHtml && looksHtml(body)) return QString();

    const QString text = QString::fromUtf8(body.left(kMaxBody));
    QRegularExpression::PatternOptions opts =
        QRegularExpression::MultilineOption;
    if (!sig.caseSensitive) opts |= QRegularExpression::CaseInsensitiveOption;
    const QRegularExpression re(sig.pattern, opts);

    int count = 0;
    QString first;
    auto it = re.globalMatch(text);
    while (it.hasNext()) {
        const auto m = it.next();
        if (first.isEmpty()) first = m.captured(0).left(80);
        if (++count >= sig.minMatches) break;
    }
    if (count < sig.minMatches) return QString();
    // Name the file; do not dump its (possibly secret) contents.
    return sig.redact ? QStringLiteral("(content signature matched; value redacted)")
                      : first;
}

QByteArray buildGet(const Request &req, const QString &path) {
    if (req.host.contains('\r') || req.host.contains('\n')) return {};
    if (path.contains('\r') || path.contains('\n')) return {};
    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/exposure\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers that fight the ones this body-less GET
        // forces (Accept-Encoding: identity line 108, Connection: close line 115):
        //  - Accept-Encoding: else the server gzips and the file-content signature
        //    matcher scans compressed bytes -> a real exposed .env/.git/credentials
        //    file reads CLEAN.
        //  - Connection: a carried "keep-alive" contradicts the forced close.
        //  - Content-Length / Transfer-Encoding: a copied framing header on a body-less
        //    GET strands the request (server waits for an absent body) or desyncs.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

bool suppressAsCatchAll(bool controlIs2xx, const QByteArray &controlBody,
                        const Signature &sig) {
    // Only a host that 200s a bogus path can be a catch-all; and only when the
    // SAME signature fires on that control body is the match non-file-specific.
    return controlIs2xx && !matchSignature(controlBody, sig).isEmpty();
}

} // namespace Nullock::Core::ExposureScan

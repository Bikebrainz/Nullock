#include "exposure_scan.hpp"
#include "networking.hpp"

#include <QRegularExpression>

namespace Nullock::Core::ExposureScan {

namespace {

constexpr int kMaxBody = 256 * 1024;

struct Probe {
    const char *path;
    const char *pattern;     // content signature (regex) confirming exposure
    const char *severity;
    const char *summary;
};

const QList<Probe> &probes() {
    static const QList<Probe> p = {
        { "/.git/config", "\\[core\\]|repositoryformatversion", "high",
          "Git repository config exposed -- full source + history is downloadable" },
        { "/.git/HEAD", "ref:\\s*refs/", "high", "Git repository exposed (.git/HEAD)" },
        { "/.env", "(?m)^[A-Z][A-Z0-9_]{2,}=", "high",
          ".env file exposed -- application secrets/config readable" },
        { "/.svn/entries", "(?m)^\\s*\\d+\\s*$|svn://", "medium", "SVN metadata exposed" },
        { "/phpinfo.php", "phpinfo\\(\\)|<title>PHP [0-9]", "medium",
          "phpinfo() exposed -- full environment/config disclosure" },
        { "/server-status", "Apache Server Status", "medium",
          "Apache server-status exposed (request/IP disclosure)" },
        { "/.DS_Store", "Bud1", "low", ".DS_Store exposed -- leaks directory names" },
        { "/wp-config.php.bak", "DB_PASSWORD|DB_NAME|define\\s*\\(", "high",
          "WordPress config backup exposed -- database credentials" },
        { "/.aws/credentials", "aws_access_key_id", "high", "AWS credentials file exposed" },
        { "/docker-compose.yml", "(?m)^services:|^\\s+image:", "low",
          "docker-compose.yml exposed -- infrastructure detail" },
        { "/actuator/env", "\"propertySources\"|activeProfiles", "high",
          "Spring Boot Actuator /env exposed -- config + secrets" },
        { "/.git/", "Index of|Parent Directory", "medium", "Git directory listing exposed" },
        { "/config.php.bak", "DB_PASSWORD|mysql_connect|define\\s*\\(", "high",
          "PHP config backup exposed -- credentials" },
    };
    return p;
}

QByteArray buildGet(const Request &req, const QString &path) {
    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/exposure\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    for (const Probe &p : probes()) {
        ++result.probed;
        const QString path = req.basePrefix + QString::fromUtf8(p.path);
        const auto r = client.send(req.host, port, req.tls, buildGet(req, path));
        if (!r.ok) continue;
        if (r.parsed.statusCode < 200 || r.parsed.statusCode >= 300) continue;
        const QString body = QString::fromUtf8(r.parsed.body.left(kMaxBody));
        const QRegularExpression re(QString::fromUtf8(p.pattern),
                                    QRegularExpression::CaseInsensitiveOption);
        const auto m = re.match(body);
        if (!m.hasMatch()) continue;
        result.hits.append({ QString::fromUtf8(p.path), QString::fromUtf8(p.severity),
                             QString::fromUtf8(p.summary), r.parsed.statusCode,
                             m.captured(0).left(80) });
    }
    return result;
}

} // namespace Nullock::Core::ExposureScan

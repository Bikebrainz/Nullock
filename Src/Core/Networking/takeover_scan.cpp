#include "takeover_scan.hpp"
#include "networking.hpp"

#include <QRegularExpression>

namespace Nullock::Core::TakeoverScan {

namespace {

constexpr int kMaxBody = 256 * 1024;

struct Fingerprint { const char *service; const char *pattern; const char *confidence; };

// Curated dangling-service fingerprints (subjack/can-i-take-over-xyz class).
const QList<Fingerprint> &fingerprints() {
    static const QList<Fingerprint> f = {
        { "GitHub Pages", "There isn't a GitHub Pages site here\\.", "high" },
        { "GitHub Pages", "For root URLs \\(like http://example\\.com/\\) you must provide an index\\.html file", "medium" },
        { "AWS/S3",       "NoSuchBucket|The specified bucket does not exist", "high" },
        { "Heroku",       "No such app|herokucdn\\.com/error-pages/no-such-app\\.html", "high" },
        { "Fastly",       "Fastly error: unknown domain", "high" },
        { "Azure",        "404 Web Site not found|Error 404 - Web app not found", "medium" },
        { "Shopify",      "Sorry, this shop is currently unavailable", "medium" },
        { "Bitbucket",    "Repository not found", "medium" },
        { "Surge.sh",     "project not found", "medium" },
        { "Pantheon",     "The gods are wise, but do not know of the site which you seek", "high" },
        { "Tumblr",       "Whatever you were looking for doesn't currently exist at this address", "high" },
        { "Zendesk",      "Help Center Closed", "medium" },
        { "Cargo",        "<title>404 &mdash; File not found</title>|If you're moving your domain away from Cargo", "medium" },
        { "Unbounce",     "The requested URL was not found on this server", "medium" },
        { "Ghost",        "The thing you were looking for is no longer here, or never was", "high" },
        { "Read the Docs","unknown to Read the Docs", "high" },
        { "Help Scout",   "No settings were found for this company", "high" },
    };
    return f;
}

QByteArray buildGet(const Request &req) {
    QByteArray out = "GET " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/takeover\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
    return out;
}

} // namespace

QList<Hit> match(const QString &body) {
    QList<Hit> hits;
    const QString b = body.left(kMaxBody);
    for (const Fingerprint &fp : fingerprints()) {
        const QRegularExpression re(QString::fromUtf8(fp.pattern),
                                    QRegularExpression::CaseInsensitiveOption);
        const auto m = re.match(b);
        if (m.hasMatch())
            hits.append({ QString::fromUtf8(fp.service), m.captured(0),
                          QString::fromUtf8(fp.confidence) });
    }
    return hits;
}

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = "request failed: " + r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    result.hits = match(QString::fromUtf8(r.parsed.body));
    return result;
}

} // namespace Nullock::Core::TakeoverScan

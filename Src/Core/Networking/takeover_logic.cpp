// Pure (no-network) logic for the subdomain-takeover probe: the curated
// dangling-service fingerprint table, the body matcher, and the GET builder's
// CR/LF guards. Split out of takeover_scan.cpp so Tests/takeover_scan links
// Qt6::Core alone.
//
// FINGERPRINT POLICY: every pattern must be vendor-BRANDED / service-specific.
// Generic 404 copy is banned -- it fires on healthy, owned servers and produces
// pure false positives (the stock Apache "The requested URL was not found on
// this server" is NOT an Unbounce takeover; a bare "Repository not found" is any
// git host; "project not found" is any dashboard). Only unambiguous pages count.

#include "takeover_scan.hpp"

#include <QRegularExpression>

namespace Nullock::Core::TakeoverScan {

namespace {

constexpr int kMaxBody = 256 * 1024;

struct Fingerprint { const char *service; const char *pattern; const char *confidence; };

const QList<Fingerprint> &fingerprints() {
    static const QList<Fingerprint> f = {
        { "GitHub Pages", "There isn't a GitHub Pages site here\\.", "high" },
        { "GitHub Pages", "For root URLs \\(like http://example\\.com/\\) you must provide an index\\.html file", "medium" },
        { "AWS/S3",       "NoSuchBucket|The specified bucket does not exist", "high" },
        { "Heroku",       "herokucdn\\.com/error-pages/no-such-app\\.html|No such app", "high" },
        { "Fastly",       "Fastly error: unknown domain", "high" },
        { "Azure",        "Error 404 - Web app not found|404 Web Site not found", "medium" },
        { "Shopify",      "Sorry, this shop is currently unavailable", "medium" },
        { "Pantheon",     "The gods are wise, but do not know of the site which you seek", "high" },
        { "Tumblr",       "Whatever you were looking for doesn't currently exist at this address", "high" },
        { "Zendesk",      "Help Center Closed", "medium" },
        { "Cargo",        "If you're moving your domain away from Cargo", "high" },   // branded only; generic 404 title dropped
        { "Ghost",        "The thing you were looking for is no longer here, or never was", "high" },
        { "Read the Docs","unknown to Read the Docs", "high" },
        { "Help Scout",   "No settings were found for this company", "high" },
        // Added (branded/specific only):
        { "WordPress.com", "Do you want to register [^\\s\"'<]*\\.wordpress\\.com", "medium" },
        { "Pingdom",       "public report page has not been activated|Sorry, couldn't find the status page", "medium" },
        { "Teamwork",      "Oops - We didn't find your site\\.", "medium" },
        { "LaunchRock",    "It looks like you may have taken a wrong turn somewhere\\. Don't worry\\.\\.\\.it happens to all of us\\.", "medium" },
        // REMOVED as pure false positives (generic, non-branded):
        //   Unbounce  "The requested URL was not found on this server"  (= stock Apache 404)
        //   Bitbucket "Repository not found"                            (= any git host 404)
        //   Surge.sh  "project not found"                               (= any dashboard)
        //   Cargo     "<title>404 ... File not found</title>"           (= generic 404 title)
    };
    return f;
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

QByteArray buildGet(const Request &req) {
    // host/basePath flow into the request line / Host header; a CR/LF would
    // smuggle a second request line or header -- refuse to build.
    if (req.host.contains('\r') || req.host.contains('\n')) return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    QByteArray out = "GET " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/takeover\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::TakeoverScan

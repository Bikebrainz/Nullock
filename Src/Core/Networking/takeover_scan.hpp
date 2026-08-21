#pragma once

// Subdomain-takeover detection. A dangling DNS record (CNAME to a de-provisioned
// GitHub Pages / S3 bucket / Heroku app / Azure site / Fastly / Shopify / ...)
// lets an attacker claim that service and serve content on the victim's domain.
// We fetch the host and match the response against a curated table of
// dangling-service fingerprints (the subjack/nuclei approach). A match is a
// takeover *candidate* -- the operator should confirm the CNAME and claim path.
// Read-only HTTP GET; identification, not exploitation.

#include <QByteArray>
#include <QList>
#include <QString>

namespace Nullock::Core::TakeoverScan {

struct Hit {
    QString service;     // "GitHub Pages", "AWS/S3", "Heroku", ...
    QString evidence;    // the matched fingerprint fragment
    QString confidence;  // "high" | "medium"
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath = QStringLiteral("/");
};

struct Result {
    int     status = 0;
    QList<Hit> hits;
    QString error;
};

// GET the host and match the response body/headers against the fingerprint
// table. Exposed for tests: match() runs the table over a body string.
//
// Fingerprints are deliberately BRANDED/service-specific: a generic 404 phrase
// (the stock Apache "The requested URL was not found on this server", a bare
// "Repository not found" / "project not found") is NOT a takeover signal -- it
// fires on healthy owned servers -- so only unambiguous, vendor-named pages are
// matched. A body match is still a *candidate*: confirm the dangling CNAME.
Result scan(const Request &req);
QList<Hit> match(const QString &body);

// Status-aware match: a dangling service serves its "unclaimed" page as an HTTP
// error (4xx/5xx). The same branded phrase on a 2xx/3xx is almost always quoted
// in LIVE content, not a takeover, so those matches are demoted to "possible"
// (without a DNS/CNAME dangling check we never claim "confirmed"; an error-status
// hit keeps its curated confidence as a strong lead). scan() uses this overload.
QList<Hit> match(const QString &body, int status);

// Build the GET. Returns empty if host or basePath carries a CR/LF.
QByteArray buildGet(const Request &req);

} // namespace Nullock::Core::TakeoverScan

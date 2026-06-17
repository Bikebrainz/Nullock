#pragma once

// Subdomain-takeover detection. A dangling DNS record (CNAME to a de-provisioned
// GitHub Pages / S3 bucket / Heroku app / Azure site / Fastly / Shopify / ...)
// lets an attacker claim that service and serve content on the victim's domain.
// We fetch the host and match the response against a curated table of
// dangling-service fingerprints (the subjack/nuclei approach). A match is a
// takeover *candidate* -- the operator should confirm the CNAME and claim path.
// Read-only HTTP GET; identification, not exploitation.

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
Result scan(const Request &req);
QList<Hit> match(const QString &body);

} // namespace Nullock::Core::TakeoverScan

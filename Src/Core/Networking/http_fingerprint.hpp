#pragma once

// Active HTTP technology fingerprinting (WhatWeb / Wappalyzer class). Fetches a
// URL on demand and identifies the stack from response headers (Server,
// X-Powered-By, X-Generator), Set-Cookie names (PHPSESSID, JSESSIONID,
// laravel_session, wordpress_*, csrftoken+sessionid, ...), and body/meta markers
// (generator meta, wp-content, jquery-X.js, bootstrap, react/vue/angular).
// Versioned server/CMS detections are correlated against the CVE database.
// Read-only -- a single GET; identification, not attack.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::HttpFingerprint {

struct Tech {
    QString name;        // "WordPress", "Apache", "PHP", "jQuery", ...
    QString version;     // may be empty
    QString source;      // "header" | "cookie" | "body" | "meta"
    QString cveKind;     // cve_database kind to correlate, or empty
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QString query;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    int     status = 0;
    QList<Tech> tech;
    QString error;
};

// GET the URL and return the detected technologies (deduped by name).
Result fingerprint(const Request &req);

} // namespace Nullock::Core::HttpFingerprint

#pragma once

// WAF / CDN / load-balancer detection (wafw00f-class), from response headers and
// cookies on a normal GET -- PASSIVE: it sends no attack payload, it just reads
// the signatures fronting infrastructure announces about itself (cf-ray, x-iinfo,
// AkamaiGHost, BIGipServer cookies, ...). Knowing what's in front of a target
// shapes the rest of the engagement. Identification only.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::WafDetect {

struct Detection {
    QString name;       // "Cloudflare", "Akamai", "Imperva Incapsula", ...
    QString kind;       // "waf" | "cdn" | "lb" | "cache"
    QString evidence;   // which header/cookie matched
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath = QStringLiteral("/");
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QString host;
    int     status = 0;
    QList<Detection> detections;
    QString error;
};

Result detect(const Request &req);

// Exposed for tests: match the signature table against a response's headers
// (Set-Cookie entries included). Deduplicated by product name.
QList<Detection> detectFromHeaders(const QList<QPair<QString, QString>> &headers);

} // namespace Nullock::Core::WafDetect

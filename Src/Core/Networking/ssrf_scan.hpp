#pragma once

// SSRF (CWE-918: Server-Side Request Forgery, OWASP A10:2021). A parameter
// whose value the server fetches lets an attacker pivot the request inside the
// trust boundary -- read cloud-instance credentials, hit internal services, or
// exfiltrate local files via file://. It is the highest-impact cloud finding:
// AWS/GCP/Azure metadata endpoints hand out IAM credentials to anyone the
// instance will fetch for.
//
// This is the IN-BAND, deterministically-confirmable half of SSRF testing:
// inject a battery of cloud-metadata (incl. decimal/hex IP-encoding denylist
// bypasses), file://, and internal-service (loopback) URLs and confirm only
// when a RESPONSE-ONLY signature comes back -- a string that lives in the
// fetched resource (root:x:0:0:, an IMDS AccessKeyId/ami-id, a service banner)
// but never in the URL we sent. Three layers keep a hit fetch-PROVEN, not just
// reflection-proof:
//   1. the signature can't appear in the URL we sent (defeats verbatim echo);
//   2. it must be ABSENT from the baseline (defeats always-served tokens);
//   3. on a match, a same-shape but non-fetchable "shaped control" URL is
//      fetched -- if the signature shows up there too, it tracks the input
//      SHAPE (an error/WAF/echo template keyed on file:// or 169.254.x.x), not
//      a real fetch, so the hit is suppressed.
//
// The OUT-OF-BAND half (blind SSRF that never echoes -- confirmed by an OAST
// callback) is covered by the parameter-sweep + OAST correlator path; this
// module deliberately stays synchronous and dependency-free so it is fully
// CI-regression-testable.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::SsrfScan {

struct Hit {
    QString technique;   // "aws-imds-v1", "aws-imds-iam", "azure-imds", "file-unix-passwd", ...
    QString payload;     // the URL injected as the parameter value
    QString signal;      // the response-only signature that confirmed the fetch
    QString severity;    // "critical" (cloud metadata) | "high" (internal/file)
    QString kind;        // "ssrf-cloud-metadata" | "ssrf-internal"
    QString param;       // the parameter the payload went into
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QString param;                              // param to test; empty = auto-detect
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QString testedParam;
    bool    vulnerable = false;
    QList<Hit> hits;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject the metadata/file battery into `param` (or the first auto-detected
// URL-typed query param if empty). Confirmation is by a response-only
// signature absent from the baseline, so reflected input can't false-positive.
// The payloads go into the query string only -- a sink that reads the target
// URL from a POST body isn't covered here (use the parameter sweep for that).
Result test(const Request &req);

// Query keys treated as likely URL-typed (SSRF-prone) parameters when
// auto-detecting which parameter to inject.
QStringList knownSsrfParams();

} // namespace Nullock::Core::SsrfScan

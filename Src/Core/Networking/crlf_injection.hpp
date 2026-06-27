#pragma once

// CRLF / HTTP response splitting (CWE-113: Improper Neutralization of CRLF in
// HTTP Headers). When user input reaches a response header -- a redirect
// Location, a reflected Set-Cookie, a custom header -- without stripping CR/LF,
// an attacker injects their own header lines and even a response body: cache
// poisoning, a forced Set-Cookie (session fixation), or reflected XSS in the
// split body. We confirm it unambiguously: inject an encoded CRLF plus a
// uniquely-named marker header and check whether that header actually appears
// in the parsed response -- the server split the header, no guessing.
//
// The reflecting source is selectable via Request::in -- the same CR/LF payload
// is driven through four distinct sinks: query-string params (default), POST body
// params (application/x-www-form-urlencoded), path segments, and reflected request
// HEADER values (a server that echoes an incoming Referer / X-Forwarded-Host /
// ... into a response header).

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CrlfInjection {

struct Hit {
    QString point;       // injection point: "query" | "body" | "path" | "header"
    QString param;       // locus the payload went into (param/header name; "path")
    QString technique;   // "crlf", "lf-only", "double-encoded", "unicode", ...
    QString payload;     // the raw (URL-encoded) value injected
    QString evidence;    // the injected header that came back
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QByteArray body;                            // existing POST body (encoded form params)
    QString param;                              // locus to test; empty => auto.
                                                //   query/body: param name; header: header name
    QString in;                                 // injection point selector:
                                                //   ""/"query" (default) | "body" | "path" |
                                                //   "header" | "all" | comma-separated mix
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    QStringList testedParams;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject CRLF-bearing payloads into the target parameter(s) and flag any that
// land an attacker-controlled header in the response. If `param` is empty,
// every existing query parameter is tried (capped), or a small default set.
Result test(const Request &req);

QStringList defaultParams();

// Common request headers a server may echo into a response header (the reflected
// request-header response-splitting sink). Used when `in == "header"` and no
// explicit header name (`param`) is given.
QStringList defaultHeaderNames();

// Parse the `in` selector into the concrete injection points to probe. Empty or
// "query" => {"query"} (backward-compatible default); "all" => every point.
QStringList selectedPoints(const QString &in);

// --- Pure helpers, exposed for the unit test (no network I/O; in crlf_logic.cpp) ---
//   buildRequest   -- render the request, stripping CR/LF from method/host/path/query
//                     and dropping any CR/LF-bearing carried header. When method is
//                     body-bearing (POST/PUT/...) and `body` is supplied, emit it with
//                     Content-Type: application/x-www-form-urlencoded + Content-Length.
//   queryWith      -- set `param` to a RAW (already-encoded) value, preserving others.
//   bodyWith       -- same, for an x-www-form-urlencoded request body.
//   pathWith       -- splice a RAW (already-encoded) payload as a trailing path segment.
//   buildHeaderProbe -- OPT-IN raw-send builder: write one named request header's value
//                     VERBATIM so a CR/LF payload reaches a header-reflecting sink. The
//                     request line and every OTHER carried header stay CR/LF-guarded, so
//                     it can't be repurposed for request-line/extra-header smuggling.
//                     Kept separate from buildRequest so the audit/HAR replay path (which
//                     uses buildRequest's drop-guard) stays safe.
//   splitConfirmed -- did the server split our CR/LF into a real header line?
//                     parsed-header match OR a colon-less line at a header-block
//                     boundary that starts with the marker name and holds the marker.
QByteArray buildRequest(const Request &req, const QString &query,
                        const QByteArray &body = QByteArray());
QString queryWith(const QString &existing, const QString &param, const QString &rawValue);
QString bodyWith(const QString &existingBody, const QString &param, const QString &rawValue);
QString pathWith(const QString &basePath, const QString &rawValue);
QByteArray buildHeaderProbe(const Request &req, const QString &headerName,
                            const QString &rawValue);
bool splitConfirmed(const QByteArray &rawResponse,
                    const QList<QPair<QString, QString>> &parsedHeaders,
                    const QString &markerName, const QString &marker);

} // namespace Nullock::Core::CrlfInjection

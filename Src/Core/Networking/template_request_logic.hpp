#pragma once

// Template HTTP request builder -- the "active" half of the template engine
// (nuclei-style). A template can now CRAFT the request (method/path/headers/
// body) with variable substitution and payload expansion, not just GET a URL
// and match the response.
//
// PURE: a request spec + target vars in, raw HTTP request bytes out. No I/O --
// links against Qt6::Core alone. Sending the bytes and matching the response is
// the caller's job (control_server + template_engine_logic).
//
// SAFETY:
//   * expansion is HARD-CAPPED at kMaxRequests so a huge payload list can't OOM
//     or hang (same lesson as the Intruder generators);
//   * substituted VARIABLE VALUES (payloads / BaseURL / Hostname) have CR and LF
//     stripped before they go into the request-line or headers, so a payload
//     can't smuggle a header or split the request (CRLF-injection lesson). The
//     body is length-delimited (Content-Length is computed after substitution),
//     so payload newlines there are harmless and preserved.
//   * parseRequest is default-safe: missing/garbage fields yield sane defaults
//     (method GET, path /), never a crash.

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::TemplateRequest {

// Hard cap on how many requests one spec can expand to.
constexpr int kMaxRequests = 10000;

struct RequestSpec {
    QString method = QStringLiteral("GET");
    QString path   = QStringLiteral("/");
    QList<QPair<QString, QString>> headers;
    QString body;
    // One payload list per {{payloadN}} variable ({{payload}} == {{payload1}}).
    QList<QStringList> payloads;
    // false = cluster bomb (cartesian product); true = pitchfork (index-zip).
    bool pitchfork = false;
};

// Target-derived variables. {{BaseURL}} -> baseUrl, {{Hostname}} -> hostname.
struct Vars {
    QString baseUrl;
    QString hostname;
};

struct BuiltRequest {
    QByteArray  bytes;          // raw HTTP/1.1 request, ready for HttpClient::send
    QStringList usedPayloads;   // the payload combo (for per-result reporting)
};

// Parse a "request" object (default-safe). Shape:
//   { "method","path","headers":{..}|[{name,value}],"body",
//     "payloads":[[...],[...]] | [...], "attack":"cluster"|"pitchfork" }
RequestSpec parseRequest(const QJsonObject &obj);

// Expand payloads (capped), substitute variables, and assemble each raw request.
// A Host header, Content-Length (when a body is present), and Connection: close
// are added if the spec didn't provide them.
QList<BuiltRequest> buildRequests(const RequestSpec &spec, const Vars &vars);

} // namespace Nullock::Core::TemplateRequest

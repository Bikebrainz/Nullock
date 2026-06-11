#pragma once

// Active CORS exploitability analyzer. The passive scanner notices when a
// response *already* reflects an Origin; this actively proves whether a
// cross-origin attacker can read the response by sending a battery of
// crafted Origin headers and inspecting Access-Control-Allow-Origin
// (ACAO) + Access-Control-Allow-Credentials (ACAC):
//
//   - arbitrary attacker origin reflected + credentials -> critical: any
//     site can make authenticated cross-origin reads of this endpoint.
//   - "null" origin reflected -> sandboxed-iframe / data-URL bypass.
//   - target-as-substring origins (https://target.attacker.com,
//     http scheme) reflected -> naive allow-list (contains/startsWith)
//     that an attacker-controlled hostname satisfies.
//   - ACAO:* with credentials -> a misconfiguration (browsers reject it,
//     but it signals a broken policy worth flagging).
//
// Each probe is one request; classification is from the two response
// headers only, so this is safe to run against any endpoint.
//
// Scope: this sends a "simple" GET with an Origin header, which reveals
// the ACAO/ACAC a browser would see for simple cross-origin reads -- the
// most common misconfiguration. CORS policies that ONLY emit headers on
// the OPTIONS preflight (non-simple requests) aren't exercised here; for
// those, replay the endpoint's real preflight through the Repeater.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CorsTester {

struct Probe {
    QString origin;        // the Origin we sent
    QString label;         // what it tests, e.g. "arbitrary", "null", "subdomain"
    QString acao;          // Access-Control-Allow-Origin we got back
    bool    credentials = false;   // ACAC: true
    bool    reflected = false;     // ACAO == the origin we sent
    QString severity;      // set when this probe is a finding ("" = clean)
    QString kind;          // finding kind when severity set
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QList<QPair<QString, QString>> headers;   // session cookies optional
};

struct Result {
    QList<Probe> probes;
    int     requestsSent = 0;
    int     findingCount = 0;   // probes with a non-empty severity
    QString error;
};

// Fire the Origin battery against the target and classify each response.
Result test(const Request &req);

} // namespace Nullock::Core::CorsTester

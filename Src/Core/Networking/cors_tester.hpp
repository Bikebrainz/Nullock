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
//   - target-as-PREFIX origins (https://target.attacker.example) reflected
//     -> naive contains/startsWith allow-list an attacker hostname satisfies.
//   - target-as-SUFFIX origins (https://attacker-<regDomain>, e.g.
//     attacker-target.com) reflected -> naive origin.endsWith("target.com")
//     allow-list (no leading dot) that an attacker-registrable sibling domain
//     satisfies. The registrable domain is a best-effort eTLD+1 guess; a wrong
//     guess only misses, it cannot false-positive.
//   - trailing-dot origin (https://attacker.example.) reflected -> a host
//     parser that strips the FQDN root dot before its allow-list check then
//     reflects the raw dotted origin (graded low/medium, narrow precondition).
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

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

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

// A probe's finding verdict: empty severity/kind = no finding for that probe.
struct CorsVerdict {
    QString severity;
    QString kind;
};

// Exposed for the unit test (pure logic, no I/O):
//  - registrableDomain: best-effort eTLD+1 ("" for IPs / single-label hosts).
//  - originSpecs: the (origin, label) battery for a target host.
//  - buildRequest: the raw GET, with CR/LF guards on every tainted field.
//  - classifyCorsProbe: map a probe outcome (label + reflected/credentials/
//    wildcard) to the finding {severity, kind}. This is the core verdict logic
//    the network test() applies; extracted so it can be regression-tested.
QString registrableDomain(const QString &host);
QList<QPair<QString, QString>> originSpecs(const QString &host, bool tls);
QByteArray buildRequest(const Request &req, const QString &origin);
CorsVerdict classifyCorsProbe(const QString &label, bool reflected,
                              bool credentials, bool wildcard);

// The reflection derivation (pure) -- how the network test() decides the
// `reflected` / `wildcard` / `credentials` inputs it feeds to classifyCorsProbe.
// This was inline in test() (which the test binary excludes), so the ACAO-match
// semantics -- the load-bearing part -- were unit-tested only downstream of the
// bool. Extracted here so they are pinned:
//
//  - corsNormalizeOrigin: case-fold + strip trailing slash for the ACAO-vs-sent
//    comparison, but DELIBERATELY keep a trailing DOT (so the trailing-dot probe
//    detects a verbatim dotted reflection instead of it collapsing to a match).
//  - corsOriginReflected: true if ANY of the response's ACAO values (a response
//    can carry more than one) normalizes equal to the sent origin.
//  - corsHasWildcard: true if any ACAO value is "*".
//  - corsCredentialsAllowed: Access-Control-Allow-Credentials is exactly "true"
//    (case-insensitive, trimmed) -- the critical-vs-high severity tiebreak.
QString corsNormalizeOrigin(const QString &origin);
bool corsOriginReflected(const QStringList &acaoValues, const QString &sentOrigin);
bool corsHasWildcard(const QStringList &acaoValues);
bool corsCredentialsAllowed(const QString &acacValue);

} // namespace Nullock::Core::CorsTester

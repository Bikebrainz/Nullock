#include "cors_tester.hpp"
#include "networking.hpp"

namespace Nullock::Core::CorsTester {

namespace {

QString headerOf(const QList<QPair<QString, QString>> &headers, const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second.trimmed();
    return {};
}

// ALL values for a header name -- a response can carry more than one
// Access-Control-Allow-Origin (framework default + a proxy-added one),
// and reading only the first would miss the malicious reflection.
QStringList allHeaderValues(const QList<QPair<QString, QString>> &headers,
                            const QString &name) {
    QStringList out;
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) out << h.second.trimmed();
    return out;
}

// Origin comparison is case-insensitive (scheme + host are) and ignores a
// trailing slash, so a server that re-cases or normalizes our origin when
// reflecting it doesn't slip past as a false negative. Note: a trailing DOT is
// deliberately NOT stripped -- we want https://attacker.example. to compare
// distinct from https://attacker.example so the trailing-dot probe can detect a
// verbatim reflection of the dotted form.
QString normOrigin(const QString &s) {
    QString t = s.trimmed();
    while (t.endsWith('/')) t.chop(1);
    return t.toLower();
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    for (const auto &spec : originSpecs(req.host, req.tls)) {
        const QString origin = spec.first;
        const QString label  = spec.second;
        Probe p;
        p.origin = origin;
        p.label  = label;

        const QByteArray raw = buildRequest(req, origin);
        if (raw.isEmpty()) { result.probes.append(p); continue; }   // CR/LF-tainted -> skip
        ++result.requestsSent;
        const auto r = client.send(req.host, port, req.tls, raw);
        if (!r.ok) { result.probes.append(p); continue; }

        const QStringList acaoVals =
            allHeaderValues(r.parsed.headers, "Access-Control-Allow-Origin");
        p.acao = acaoVals.isEmpty() ? QString() : acaoVals.first();
        p.credentials = headerOf(r.parsed.headers, "Access-Control-Allow-Credentials")
                            .compare("true", Qt::CaseInsensitive) == 0;
        // Reflected if ANY ACAO value (normalized) equals the origin we sent;
        // note a wildcard among them separately.
        bool wildcard = false;
        for (const QString &v : acaoVals) {
            if (normOrigin(v) == normOrigin(origin)) { p.reflected = true; p.acao = v; }
            if (v == "*") wildcard = true;
        }

        // Classify. scheme-swap is the site's own host (network-position only).
        // trailing-dot is a host-normalization bypass with a narrow precondition
        // (attacker page served from a rooted FQDN), so it's never critical. The
        // remaining origins (arbitrary/null/subdomain-suffix/suffix-domain) are
        // attacker-controlled.
        if (label == "scheme-swap") {
            if (p.reflected) { p.severity = "low"; p.kind = "cors-scheme-downgrade"; }
        } else if (label == "trailing-dot") {
            if (p.reflected) {
                p.severity = p.credentials ? "medium" : "low";
                p.kind = "cors-origin-normalization";
            }
        } else if (p.reflected && p.credentials) {
            p.severity = "critical";
            p.kind = "cors-reflected-credentialed";
        } else if (p.reflected) {
            p.severity = (label == "null") ? "medium" : "high";
            p.kind = (label == "null") ? "cors-null-origin" : "cors-arbitrary-origin";
        } else if (wildcard && p.credentials) {
            // ACAO:* with credentials is a contradiction browsers reject, but it
            // means the policy is broken/confused -- worth a flag.
            p.severity = "medium";
            p.kind = "cors-wildcard-credentials";
        }
        if (!p.severity.isEmpty()) ++result.findingCount;
        result.probes.append(p);
    }

    return result;
}

} // namespace Nullock::Core::CorsTester

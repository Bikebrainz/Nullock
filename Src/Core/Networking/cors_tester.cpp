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
// reflecting it doesn't slip past as a false negative.
QString normOrigin(const QString &s) {
    QString t = s.trimmed();
    while (t.endsWith('/')) t.chop(1);
    return t.toLower();
}

QByteArray buildRequest(const Request &req, const QString &origin) {
    QByteArray out;
    out  = req.method.toUtf8() + " " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cors-tester\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Origin: " + origin.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        const QString k = h.first;
        if (k.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (k.compare("Origin", Qt::CaseInsensitive) == 0) continue;
        out += k.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    const QString target = req.host;
    // The Origin battery. attacker.example is reserved-for-docs and will
    // never be a real allowed origin, so any reflection of it is a finding.
    struct Spec { QString origin; QString label; };
    const QList<Spec> specs = {
        { "https://attacker.example",                 "arbitrary" },
        { "null",                                     "null" },
        // Tests a naive allow-list that does a substring/contains check on
        // the target host -- an attacker-controlled hostname that embeds it.
        { "https://" + target + ".attacker.example",  "subdomain-suffix" },
        // The site's OWN host over the other scheme. NOT attacker-controlled,
        // so reflecting it is only exploitable from a network (MITM) position
        // -- graded low, never critical, to avoid a false high.
        { (req.tls ? "http://" : "https://") + target, "scheme-swap" },
    };

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    for (const Spec &s : specs) {
        ++result.requestsSent;
        const auto r = client.send(req.host, port, req.tls, buildRequest(req, s.origin));
        Probe p;
        p.origin = s.origin;
        p.label  = s.label;
        if (!r.ok) { result.probes.append(p); continue; }

        const QStringList acaoVals =
            allHeaderValues(r.parsed.headers, "Access-Control-Allow-Origin");
        p.acao = acaoVals.isEmpty() ? QString() : acaoVals.first();
        p.credentials = headerOf(r.parsed.headers, "Access-Control-Allow-Credentials")
                            .compare("true", Qt::CaseInsensitive) == 0;
        // Reflected if ANY ACAO value (normalized) equals the origin we
        // sent; note a wildcard among them separately.
        bool wildcard = false;
        for (const QString &v : acaoVals) {
            if (normOrigin(v) == normOrigin(s.origin)) { p.reflected = true; p.acao = v; }
            if (v == "*") wildcard = true;
        }

        // Classify. The scheme-swap origin is the site's own host, so it's
        // only a network-position issue -- low, never the attacker-origin
        // criticals. The others are attacker-controlled origins.
        if (s.label == "scheme-swap") {
            if (p.reflected) {
                p.severity = "low";
                p.kind = "cors-scheme-downgrade";
            }
        } else if (p.reflected && p.credentials) {
            p.severity = "critical";
            p.kind = "cors-reflected-credentialed";
        } else if (p.reflected) {
            p.severity = (s.label == "null") ? "medium" : "high";
            p.kind = (s.label == "null") ? "cors-null-origin" : "cors-arbitrary-origin";
        } else if (wildcard && p.credentials) {
            // ACAO:* with credentials is a contradiction browsers reject,
            // but it means the policy is broken/confused -- worth a flag.
            p.severity = "medium";
            p.kind = "cors-wildcard-credentials";
        }
        if (!p.severity.isEmpty()) ++result.findingCount;
        result.probes.append(p);
    }

    return result;
}

} // namespace Nullock::Core::CorsTester

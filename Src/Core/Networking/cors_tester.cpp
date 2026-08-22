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
        // Reflection / wildcard / credentials derivation is now the pure,
        // unit-tested cors* helpers (this test() is excluded from the test
        // binary, so those semantics were previously uncovered).
        p.credentials = corsCredentialsAllowed(
            headerOf(r.parsed.headers, "Access-Control-Allow-Credentials"));
        p.reflected = corsOriginReflected(acaoVals, origin);
        const bool wildcard = corsHasWildcard(acaoVals);
        // Capture the matched ACAO value for display (last normalized match, as
        // the original loop did); p.acao otherwise keeps the first value above.
        for (const QString &v : acaoVals)
            if (corsNormalizeOrigin(v) == corsNormalizeOrigin(origin)) p.acao = v;

        // Classify via the extracted, unit-tested pure verdict function.
        const CorsVerdict v = classifyCorsProbe(label, p.reflected, p.credentials, wildcard);
        p.severity = v.severity;
        p.kind     = v.kind;
        if (!p.severity.isEmpty()) ++result.findingCount;
        result.probes.append(p);
    }

    return result;
}

} // namespace Nullock::Core::CorsTester

#include "header_audit.hpp"
#include "networking.hpp"

#include <QUrl>

namespace Nullock::Core::HeaderAudit {

// The pure analysis (analyze/auditCsp/parseCsp/hostOf/hostMatches) and
// buildRequest live in header_logic.cpp so they can be unit-tested against
// Qt6::Core alone. This TU keeps test(), which pulls in HttpClient (the
// Qt6::Network chain via Proxy::HttpResponse) and is therefore I/O.

namespace {

using Proxy::HttpResponse;

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    Request cur = req;
    HttpResponse resp;
    bool effTls = req.tls;
    bool got = false;
    // Follow up to two SAME-ORIGIN redirects so we audit the real landing
    // page's headers, not a header-bare 301 stub. Off-origin redirects stop
    // the chain (we only audit the host we were asked about).
    for (int hop = 0; hop <= 2; ++hop) {
        ++result.requestsSent;
        const auto r = client.send(cur.host, static_cast<quint16>(cur.port),
                                   effTls, buildRequest(cur));
        if (!r.ok) {
            if (got) break;
            result.error = "request failed: " + r.errorMessage;
            return result;
        }
        resp = r.parsed; got = true;
        if (resp.statusCode < 300 || resp.statusCode >= 400) break;
        const QString loc = headerValue(resp, "Location");
        if (loc.isEmpty()) break;
        QUrl base;
        base.setScheme(effTls ? "https" : "http");
        base.setHost(cur.host); base.setPort(cur.port);
        base.setPath(cur.basePath.isEmpty() ? "/" : cur.basePath);
        const QUrl next = base.resolved(QUrl(loc, QUrl::TolerantMode));
        // Only follow a SAME-ORIGIN redirect (same scheme+host+port). A scheme
        // downgrade, host change, or port change is a different origin: the
        // captured Cookie/Authorization must not be re-emitted to it (over
        // cleartext on a downgrade), and its verdicts must not be bound to the
        // original URL. Stop the chain and audit what we have.
        if (!isSameOriginRedirect(effTls, cur.host, cur.port, next)) break;
        // Same origin -> scheme/host/port are unchanged; only the path/query move.
        cur.basePath = next.path().isEmpty() ? QStringLiteral("/") : next.path();
        cur.query = next.query(QUrl::FullyEncoded);
    }
    result.status = resp.statusCode;

    // All header analysis is pure -- run it on the fetched response's headers.
    analyze(resp.headers, effTls, result);
    return result;
}

} // namespace Nullock::Core::HeaderAudit

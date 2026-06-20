#include "verb_tamper.hpp"
#include "networking.hpp"

namespace Nullock::Core::VerbTamper {

// (Pure helpers -- isDenied, isAllowed, buildRequest, caseVariants,
// overrideAddedNothing, headIsBypass -- live in verb_tamper_logic.cpp so the
// regression test can exercise them without the network stack.)

namespace {
int contentLengthOf(const HttpClient::SendResult &r) {
    for (const auto &h : r.parsed.headers)
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) {
            bool ok = false; const int v = h.second.trimmed().toInt(&ok);
            return ok ? v : -1;
        }
    return -1;
}
} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &method,
                    const QList<QPair<QString, QString>> &extra = {}) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, method, extra));
    };

    // Baseline as-is.
    const auto base = send(req.method);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    result.baselineDenied = isDenied(result.baselineStatus);
    if (!result.baselineDenied) return result;   // nothing to bypass
    const QByteArray denialBody = base.parsed.body;
    const int denialCL = contentLengthOf(base);

    // Control probe: a bogus method no router defines. If the server still
    // answers 2xx, it doesn't discriminate by method at all (a catch-all /
    // SPA backend that 200s everything) -- so any "bypass" we'd report is
    // noise. Suppress the whole method/override signal in that case.
    const auto control = send("XYZZY");
    const bool methodControlOpen = control.ok && isAllowed(control.parsed.statusCode);
    if (methodControlOpen) return result;

    // A body-bearing variant is a real bypass only if it returns 2xx AND its
    // body differs from the denial page -- a 200 re-serving the same "forbidden"
    // page isn't access to the protected resource.
    auto consider = [&](const QString &technique, const QString &detail,
                        const HttpClient::SendResult &r) {
        if (!r.ok || !isAllowed(r.parsed.statusCode)) return;
        if (r.parsed.body == denialBody) return;   // same denial page
        result.bypasses.append({ technique, detail, r.parsed.statusCode });
    };

    // Carrier used by the override technique; captured here so an override whose
    // response is identical to the plain carrier (the header did nothing) can be
    // suppressed rather than mis-reported as a bypass.
    const QString carrier = (req.method.compare("POST", Qt::CaseInsensitive) == 0)
                            ? QStringLiteral("GET") : QStringLiteral("POST");
    int carrierStatus = -1;
    QByteArray carrierBody;

    // 1) Alternate content-serving methods (OPTIONS/TRACE excluded: their
    //    2xx is preflight/echo, not resource access).
    static const QStringList methods = {
        "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE",
    };
    for (const QString &m : methods) {
        if (m.compare(req.method, Qt::CaseInsensitive) == 0) continue;
        const auto r = send(m);
        if (m.compare(carrier, Qt::CaseInsensitive) == 0) {
            carrierStatus = r.ok ? r.parsed.statusCode : -1;
            carrierBody = r.parsed.body;
        }
        if (m == QStringLiteral("HEAD")) {
            // HEAD has no body to compare; corroborate via Content-Length so a
            // generic framework HEAD that just re-serves the denial isn't flagged.
            if (r.ok && headIsBypass(r.parsed.statusCode, contentLengthOf(r), denialCL))
                result.bypasses.append({ "method:HEAD",
                    "HEAD returns " + QString::number(r.parsed.statusCode)
                    + " with distinct Content-Length while " + req.method + " is denied",
                    r.parsed.statusCode });
            continue;
        }
        consider("method:" + m,
                 "served under " + m + " while " + req.method + " is denied", r);
    }

    // 2) Case-varied method (get / Get) -- a front end may denylist "GET" while
    //    the back end routes the lower-cased form. (Advertised by the contract;
    //    now implemented.)
    for (const QString &cv : caseVariants(req.method)) {
        consider("method-case:" + cv,
                 "served under case-varied method '" + cv + "' while " + req.method
                     + " is denied", send(cv));
    }

    // 3) Method-override headers. Carry the request under a method a front end
    //    is unlikely to block and ask the back end to route it as the denied
    //    method -- but only count it if the override actually changed the
    //    response vs the plain carrier (otherwise the carrier was just allowed).
    static const QStringList overrideHeaders = {
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    };
    for (const QString &h : overrideHeaders) {
        const auto r = send(carrier, {{ h, req.method }});
        if (!r.ok || !isAllowed(r.parsed.statusCode)) continue;
        if (r.parsed.body == denialBody) continue;
        if (overrideAddedNothing(r.parsed.statusCode, r.parsed.body, carrierStatus, carrierBody))
            continue;   // the override header changed nothing -- carrier was simply allowed
        result.bypasses.append({ "override:" + h,
            h + ": " + req.method + " (carried as " + carrier
                + ") flipped a denied request to allowed",
            r.parsed.statusCode });
    }

    return result;
}

} // namespace Nullock::Core::VerbTamper

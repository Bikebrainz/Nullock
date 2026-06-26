#include "crlf_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrlQuery>

#include <algorithm>

namespace Nullock::Core::CrlfInjection {

// The pure builder/matcher (buildRequest, queryWith, splitConfirmed) lives in
// crlf_logic.cpp so it can be unit-tested against Qt6::Core alone. This TU keeps
// test(), which pulls in HttpClient (the Qt6::Network chain via
// Proxy::HttpResponse) and is therefore I/O.

namespace {

// The marker header an injected payload tries to plant. If it comes back in
// the response, the server split our CR/LF into a new header line.
const QString kMarkerName = QStringLiteral("X-Nullock-Crlf");

struct Technique { const char *name; const char *sep; };

// Each separator is the CR/LF encoding a vulnerable decoder might accept.
const QList<Technique> &techniques() {
    static const QList<Technique> t = {
        { "crlf",            "%0d%0a" },
        { "lf-only",         "%0a" },
        { "cr-only",         "%0d" },
        { "double-encoded",  "%250d%250a" },
        { "unicode-overlong","%e5%98%8a%e5%98%8d" },
    };
    return t;
}

QString headerValue(const Proxy::HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

} // namespace

QStringList defaultParams() {
    return { "redirect", "url", "next", "return", "returnurl", "dest", "lang",
             "page", "q", "ref", "callback", "goto" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Which params to probe.
    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
    }
    // Before truncating, float high-signal sink names (the known redirect/
    // callback set) to the front so the cap can't silently drop the one that's
    // actually vulnerable.
    if (params.size() > 8) {
        const QStringList known = defaultParams();
        std::stable_sort(params.begin(), params.end(),
            [&](const QString &a, const QString &b) {
                return known.contains(a) && !known.contains(b);
            });
    }
    while (params.size() > 8) params.removeLast();   // cap work
    result.testedParams = params;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, query));
    };

    const auto base = send(req.query);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    // If the marker header somehow already exists, we can't attribute it.
    if (!headerValue(base.parsed, kMarkerName).isEmpty()) {
        result.error = "inconclusive: the marker header is present at baseline";
        return result;
    }

    for (const QString &param : params) {
        for (const Technique &t : techniques()) {
            // A fresh random marker per probe so a hit is unambiguous.
            const QString marker = QStringLiteral("nlk")
                + QString::number(QRandomGenerator::global()->bounded(100000, 999999));
            const QString payload = QStringLiteral("nlk") + QString::fromUtf8(t.sep)
                + kMarkerName + "%3a" + marker;   // %3a == ':'
            const auto r = send(queryWith(req.query, param, payload));
            if (!r.ok) continue;
            // Confirmed iff the server split our CR/LF into a real header line --
            // caught either as a parsed header or (when the server decoded the
            // CR/LF but not the %3a colon) as a colon-less line in the raw
            // header block.
            if (splitConfirmed(r.rawResponse, r.parsed.headers, kMarkerName, marker)) {
                result.hits.append({ param, QString::fromUtf8(t.name),
                                     payload, kMarkerName + ": " + marker });
                result.vulnerable = true;
                break;   // this param is proven; move to the next
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::CrlfInjection

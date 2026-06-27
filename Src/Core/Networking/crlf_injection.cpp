#include "crlf_injection.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QStringList>
#include <QUrlQuery>

#include <algorithm>

namespace Nullock::Core::CrlfInjection {

// The pure builders/matcher (buildRequest, queryWith, bodyWith, pathWith,
// buildHeaderProbe, selectedPoints, splitConfirmed) live in crlf_logic.cpp so
// they can be unit-tested against Qt6::Core alone. This TU keeps test(), which
// pulls in HttpClient (the Qt6::Network chain via Proxy::HttpResponse) and is
// therefore I/O.

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

    // Which injection point(s) to drive the same CR/LF payload through.
    const QStringList points = selectedPoints(req.in);

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto sendBytes = [&](const QByteArray &bytes) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, bytes);
    };

    // Baseline (a normal request): proves the target is reachable and that the
    // marker header isn't already present, so any later hit is unambiguous.
    const auto base = sendBytes(buildRequest(req, req.query));
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    if (!headerValue(base.parsed, kMarkerName).isEmpty()) {
        result.error = "inconclusive: the marker header is present at baseline";
        return result;
    }

    // Auto-select the key=value loci to fuzz for a query- or body-param source:
    // an explicit param, else every existing key, else the default sink set; with
    // the known high-signal names floated to the front before the work cap so the
    // cap can't silently drop the one that's actually vulnerable.
    auto chooseParams = [&](const QString &encoded) {
        QStringList params;
        if (!req.param.isEmpty()) { params << req.param; return params; }
        const QUrlQuery q(encoded);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
        if (params.size() > 8) {
            const QStringList known = defaultParams();
            std::stable_sort(params.begin(), params.end(),
                [&](const QString &a, const QString &b) {
                    return known.contains(a) && !known.contains(b);
                });
        }
        while (params.size() > 8) params.removeLast();   // cap work
        return params;
    };

    // Probe one locus across every technique; record + stop at the first confirmed
    // split. `build` renders the full request bytes for a given encoded payload.
    auto probeLocus = [&](const QString &point, const QString &locus, auto build) {
        for (const Technique &t : techniques()) {
            // A fresh random marker per probe so a hit is unambiguous.
            const QString marker = QStringLiteral("nlk")
                + QString::number(QRandomGenerator::global()->bounded(100000, 999999));
            const QString payload = QStringLiteral("nlk") + QString::fromUtf8(t.sep)
                + kMarkerName + "%3a" + marker;   // %3a == ':'
            const auto r = sendBytes(build(payload));
            if (!r.ok) continue;
            // Confirmed iff the server split our CR/LF into a real header line --
            // caught either as a parsed header or (when the server decoded the
            // CR/LF but not the %3a colon) as a colon-less line in the raw block.
            if (splitConfirmed(r.rawResponse, r.parsed.headers, kMarkerName, marker)) {
                Hit hit;
                hit.point = point; hit.param = locus;
                hit.technique = QString::fromUtf8(t.name);
                hit.payload = payload;
                hit.evidence = kMarkerName + ": " + marker;
                result.hits.append(hit);
                result.vulnerable = true;
                return;   // this locus is proven; move to the next
            }
        }
    };

    for (const QString &point : points) {
        if (point == QLatin1String("query")) {
            for (const QString &p : chooseParams(req.query)) {
                result.testedParams << ("query:" + p);
                probeLocus("query", p, [&](const QString &payload) {
                    return buildRequest(req, queryWith(req.query, p, payload));
                });
            }
        } else if (point == QLatin1String("body")) {
            // An x-www-form-urlencoded body needs a body-bearing method.
            Request br = req;
            if (br.method.isEmpty() || br.method.compare("GET", Qt::CaseInsensitive) == 0)
                br.method = QStringLiteral("POST");
            const QString existingBody = QString::fromUtf8(br.body);
            for (const QString &p : chooseParams(existingBody)) {
                result.testedParams << ("body:" + p);
                probeLocus("body", p, [&](const QString &payload) {
                    return buildRequest(br, br.query,
                                        bodyWith(existingBody, p, payload).toUtf8());
                });
            }
        } else if (point == QLatin1String("path")) {
            result.testedParams << QStringLiteral("path");
            probeLocus("path", QStringLiteral("path"), [&](const QString &payload) {
                Request pr = req;
                pr.basePath = pathWith(req.basePath, payload);
                return buildRequest(pr, pr.query);
            });
        } else if (point == QLatin1String("header")) {
            QStringList names;
            if (!req.param.isEmpty()) names << req.param;   // param doubles as header name
            else names = defaultHeaderNames();
            while (names.size() > 8) names.removeLast();
            for (const QString &n : names) {
                result.testedParams << ("header:" + n);
                probeLocus("header", n, [&](const QString &payload) {
                    return buildHeaderProbe(req, n, payload);
                });
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::CrlfInjection

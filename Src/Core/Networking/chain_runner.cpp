#include "chain_runner.hpp"
#include "networking.hpp"

#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>

namespace Nullock::Core::ChainRunner {

namespace {

// findHeader/findCookieValue/jsonPathGet/sanitizeExtractedValue/substituteStr/
// normalizeContentLength are pure and live in chain_runner_logic.cpp so they can be
// unit-tested against Qt6::Core alone. This TU keeps extractOne() (it needs the
// Proxy::HttpResponse struct) and run() (HttpClient I/O).

QString extractOne(const Extract &e,
                   const Nullock::Proxy::HttpResponse &resp) {
    switch (e.from) {
        case Extract::Header:
            return findHeader(resp.headers, e.key);
        case Extract::Cookie:
            for (const auto &h : resp.headers) {
                if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
                const QString v = findCookieValue(h.second, e.key);
                if (!v.isEmpty()) return v;
            }
            return {};
        case Extract::Json:
            return jsonPathGet(resp.body, e.key);
        case Extract::Regex: {
            QRegularExpression rx(e.key,
                QRegularExpression::DotMatchesEverythingOption);
            if (!rx.isValid()) return {};
            const QByteArray buf = resp.body.left(1 * 1024 * 1024);
            auto m = rx.match(QString::fromUtf8(buf));
            if (!m.hasMatch()) return {};
            return m.lastCapturedIndex() >= 1 ? m.captured(1) : m.captured(0);
        }
        case Extract::Status:
            return QString::number(resp.statusCode);
    }
    return {};
}

} // namespace

Result run(const QList<Step> &steps, bool continueOnError) {
    Result result;
    HttpClient client;

    for (const Step &step : steps) {
        StepResult sr;
        sr.name = step.name;

        // Substitute {{var}} into the host + raw request, then fix length. The
        // request is substituted at the BYTE level (substituteBytes) so a binary
        // body / 0x80-0xFF byte in the template survives -- a QString UTF-8 round
        // trip would corrupt it into U+FFFD before it ever hit the wire.
        const QString host = substituteStr(step.host, result.vars);
        QByteArray req = substituteBytes(step.request, result.vars);
        req = normalizeContentLength(req);
        sr.requestSize = static_cast<int>(req.size());

        QElapsedTimer timer;
        timer.start();
        const auto res = client.send(host, static_cast<quint16>(step.port),
                                     step.tls, req);
        sr.ms = timer.elapsed();

        if (!res.ok) {
            sr.ok = false;
            sr.error = res.errorMessage.isEmpty() ? "send failed" : res.errorMessage;
            result.steps.append(sr);
            if (continueOnError) continue;
            break;
        }

        sr.ok = true;
        sr.status = res.parsed.statusCode;
        sr.responseSize = static_cast<int>(res.parsed.body.size());
        sr.responsePreview = res.rawResponse.left(2 * 1024);

        // Extract variables from this response into the bag. SANITIZE first: the
        // value is target-controlled and gets substituted into the next on-the-wire
        // request, so a raw CR/LF (legal in a JSON string / regex capture) would be
        // a header-injection / request-splitting / Content-Length-desync primitive.
        for (const Extract &e : step.extracts) {
            if (e.var.isEmpty()) continue;
            const QString val = sanitizeExtractedValue(extractOne(e, res.parsed));
            sr.extracted.insert(e.var, val);
            if (!val.isEmpty()) result.vars.insert(e.var, val);
        }
        result.steps.append(sr);
    }

    return result;
}

} // namespace Nullock::Core::ChainRunner

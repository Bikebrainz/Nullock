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

// ---- extraction helpers (mirrors session_rules; kept local so the
//      chain engine has no dependency on the session-rule object) ------
QString findHeader(const QList<QPair<QString, QString>> &headers,
                   const QString &name) {
    for (const auto &h : headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return {};
}

QString findCookieValue(const QString &raw, const QString &name) {
    for (const QString &seg : raw.split(';')) {
        const QString s = seg.trimmed();
        const int eq = s.indexOf('=');
        if (eq <= 0) continue;
        if (s.left(eq).trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return s.mid(eq + 1).trimmed();
    }
    return {};
}

QString jsonPathGet(const QByteArray &body, const QString &path) {
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(body, &err);
    if (err.error != QJsonParseError::NoError) return {};
    QJsonValue cur = doc.isArray() ? QJsonValue(doc.array())
                                   : QJsonValue(doc.object());
    // Accept a leading "$." (jq/JSONPath flavour) and dotted segments.
    QString p = path;
    if (p.startsWith("$.")) p = p.mid(2);
    else if (p.startsWith("$")) p = p.mid(1);
    for (const QString &seg : p.split('.', Qt::SkipEmptyParts)) {
        if (cur.isObject()) {
            cur = cur.toObject().value(seg);
        } else if (cur.isArray()) {
            bool ok = false;
            const int idx = seg.toInt(&ok);
            if (!ok || idx < 0 || idx >= cur.toArray().size()) return {};
            cur = cur.toArray().at(idx);
        } else {
            return {};
        }
    }
    if (cur.isString()) return cur.toString();
    if (cur.isDouble()) return QString::number(cur.toDouble());
    if (cur.isBool())   return cur.toBool() ? "true" : "false";
    return {};
}

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

// ---- {{var}} substitution ---------------------------------------------
QString substituteStr(const QString &in, const QHash<QString, QString> &vars) {
    QString out = in;
    static const QRegularExpression rx(R"(\{\{([A-Za-z_][A-Za-z0-9_]*)\}\})");
    int offset = 0;
    while (true) {
        auto m = rx.match(out, offset);
        if (!m.hasMatch()) break;
        auto it = vars.find(m.captured(1));
        if (it == vars.end()) { offset = m.capturedEnd(); continue; }
        out.replace(m.capturedStart(), m.capturedLength(), *it);
        offset = m.capturedStart() + it->size();
    }
    return out;
}

// After substitution the body length may have changed. If the request
// carries a body, set Content-Length to match so the upstream doesn't
// read a truncated/over-long body. Leaves bodyless requests untouched.
QByteArray normalizeContentLength(const QByteArray &req) {
    const int sep = req.indexOf("\r\n\r\n");
    if (sep < 0) return req;                       // no header/body split
    QByteArray head = req.left(sep);
    const QByteArray bodyAndTail = req.mid(sep + 4);
    const int bodyLen = bodyAndTail.size();

    // Find an existing Content-Length header (case-insensitive) and rewrite,
    // else only add one when there's actually a body.
    const QList<QByteArray> lines = head.split('\n');
    QByteArray rebuilt;
    bool sawCl = false;
    for (QByteArray line : lines) {
        QByteArray trimmed = line;
        if (trimmed.endsWith('\r')) trimmed.chop(1);
        const int colon = trimmed.indexOf(':');
        if (colon > 0) {
            const QByteArray name = trimmed.left(colon).trimmed().toLower();
            if (name == "content-length") {
                sawCl = true;
                rebuilt += "Content-Length: " + QByteArray::number(bodyLen) + "\r\n";
                continue;
            }
        }
        rebuilt += trimmed + "\r\n";
    }
    if (!sawCl && bodyLen > 0)
        rebuilt += "Content-Length: " + QByteArray::number(bodyLen) + "\r\n";
    rebuilt += "\r\n";
    rebuilt += bodyAndTail;
    return rebuilt;
}

} // namespace

Result run(const QList<Step> &steps, bool continueOnError) {
    Result result;
    HttpClient client;

    for (const Step &step : steps) {
        StepResult sr;
        sr.name = step.name;

        // Substitute {{var}} into the host + raw request, then fix length.
        const QString host = substituteStr(step.host, result.vars);
        QByteArray req = substituteStr(QString::fromUtf8(step.request), result.vars).toUtf8();
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

        // Extract variables from this response into the bag.
        for (const Extract &e : step.extracts) {
            if (e.var.isEmpty()) continue;
            const QString val = extractOne(e, res.parsed);
            sr.extracted.insert(e.var, val);
            if (!val.isEmpty()) result.vars.insert(e.var, val);
        }
        result.steps.append(sr);
    }

    return result;
}

} // namespace Nullock::Core::ChainRunner

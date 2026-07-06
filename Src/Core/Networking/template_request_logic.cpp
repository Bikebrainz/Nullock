#include "template_request_logic.hpp"

#include <QJsonArray>

namespace Nullock::Core::TemplateRequest {

namespace {

// Strip CR/LF so a substituted value can't inject a header or split the request.
QString stripCrlf(const QString &s) {
    QString out = s;
    out.remove(QLatin1Char('\r'));
    out.remove(QLatin1Char('\n'));
    return out;
}

// Substitute {{Key}} tokens. `values` maps token name -> replacement. When
// `sanitize` is true (request-line / headers) the replacement has CR/LF removed;
// the body path passes sanitize=false (length-delimited, newlines are fine).
QString substitute(const QString &text, const QList<QPair<QString, QString>> &values,
                   bool sanitize) {
    QString out = text;
    for (const auto &kv : values) {
        const QString token = QStringLiteral("{{") + kv.first + QStringLiteral("}}");
        const QString val = sanitize ? stripCrlf(kv.second) : kv.second;
        out.replace(token, val);
    }
    return out;
}

// Expand payload sets into combos. Empty sets -> a single empty combo (no
// payloads). Cluster = cartesian (odometer); pitchfork = index-zip. Capped.
QList<QStringList> expand(const QList<QStringList> &sets, bool pitchfork, int cap) {
    if (sets.isEmpty()) return { QStringList() };
    // Any empty set makes the product empty for both modes.
    for (const QStringList &s : sets) if (s.isEmpty()) return {};

    QList<QStringList> out;
    if (pitchfork) {
        int minLen = sets.constFirst().size();
        for (const QStringList &s : sets) minLen = qMin(minLen, s.size());
        for (int i = 0; i < minLen && out.size() < cap; ++i) {
            QStringList combo;
            for (const QStringList &s : sets) combo << s[i];
            out << combo;
        }
        return out;
    }
    // Cluster bomb (cartesian) via an odometer over the set indices.
    QList<int> idx(sets.size(), 0);
    while (out.size() < cap) {
        QStringList combo;
        combo.reserve(sets.size());
        for (int k = 0; k < sets.size(); ++k) combo << sets[k][idx[k]];
        out << combo;
        int p = sets.size() - 1;
        for (; p >= 0; --p) {
            if (++idx[p] < sets[p].size()) break;
            idx[p] = 0;
        }
        if (p < 0) break;   // odometer wrapped -> done
    }
    return out;
}

bool hasHeader(const QList<QPair<QString, QString>> &hs, const QString &name) {
    for (const auto &h : hs)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return true;
    return false;
}

QStringList jsonStrings(const QJsonValue &v) {
    QStringList out;
    if (v.isArray()) for (const QJsonValue &e : v.toArray()) out.append(e.toString());
    else if (v.isString()) out.append(v.toString());
    return out;
}

} // namespace

RequestSpec parseRequest(const QJsonObject &obj) {
    RequestSpec s;
    s.method = obj.value("method").toString(QStringLiteral("GET")).trimmed();
    if (s.method.isEmpty()) s.method = QStringLiteral("GET");
    s.path = obj.value("path").toString(QStringLiteral("/"));
    if (s.path.isEmpty()) s.path = QStringLiteral("/");
    s.body = obj.value("body").toString();
    s.pitchfork = obj.value("attack").toString().toLower() == QLatin1String("pitchfork");

    // headers: an object {name:value} or an array [{name,value}].
    const QJsonValue hv = obj.value("headers");
    if (hv.isObject()) {
        const QJsonObject ho = hv.toObject();
        for (auto it = ho.begin(); it != ho.end(); ++it)
            s.headers.append({ it.key(), it.value().toString() });
    } else if (hv.isArray()) {
        for (const QJsonValue &e : hv.toArray()) {
            const QJsonObject eo = e.toObject();
            s.headers.append({ eo.value("name").toString(), eo.value("value").toString() });
        }
    }

    // payloads: an array of arrays (one per var) or a single array (one var).
    const QJsonValue pv = obj.value("payloads");
    if (pv.isArray()) {
        const QJsonArray pa = pv.toArray();
        bool nested = false;
        for (const QJsonValue &e : pa) if (e.isArray()) { nested = true; break; }
        if (nested) {
            for (const QJsonValue &e : pa) s.payloads.append(jsonStrings(e));
        } else {
            s.payloads.append(jsonStrings(pv));
        }
    }
    return s;
}

QList<BuiltRequest> buildRequests(const RequestSpec &spec, const Vars &vars) {
    QList<BuiltRequest> out;
    const QList<QStringList> combos = expand(spec.payloads, spec.pitchfork, kMaxRequests);

    for (const QStringList &combo : combos) {
        // Build the substitution table for this combo.
        QList<QPair<QString, QString>> vals;
        vals.append({ QStringLiteral("BaseURL"),  vars.baseUrl });
        vals.append({ QStringLiteral("Hostname"), vars.hostname });
        if (!combo.isEmpty()) {
            vals.append({ QStringLiteral("payload"), combo.constFirst() });
            for (int i = 0; i < combo.size(); ++i)
                vals.append({ QStringLiteral("payload") + QString::number(i + 1), combo[i] });
        }

        const QString method = substitute(spec.method, vals, /*sanitize*/ true);
        const QString path    = substitute(spec.path,   vals, /*sanitize*/ true);
        const QByteArray body = substitute(spec.body,   vals, /*sanitize*/ false).toUtf8();

        QByteArray req;
        req += method.toUtf8();
        req += ' ';
        req += path.toUtf8();
        req += " HTTP/1.1\r\n";

        if (!hasHeader(spec.headers, QStringLiteral("Host")) && !vars.hostname.isEmpty()) {
            req += "Host: ";
            req += stripCrlf(vars.hostname).toUtf8();
            req += "\r\n";
        }
        for (const auto &h : spec.headers) {
            const QString name  = substitute(h.first,  vals, true);
            const QString value = substitute(h.second, vals, true);
            if (name.isEmpty()) continue;
            req += name.toUtf8();
            req += ": ";
            req += value.toUtf8();
            req += "\r\n";
        }
        if (!body.isEmpty() && !hasHeader(spec.headers, QStringLiteral("Content-Length"))) {
            req += "Content-Length: ";
            req += QByteArray::number(body.size());
            req += "\r\n";
        }
        if (!hasHeader(spec.headers, QStringLiteral("Connection"))) {
            req += "Connection: close\r\n";
        }
        req += "\r\n";
        req += body;

        out.append({ req, combo });
    }
    return out;
}

} // namespace Nullock::Core::TemplateRequest

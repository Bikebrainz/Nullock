#include "inspector_logic.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QList>
#include <QPair>
#include <QRegularExpression>
#include <QString>
#include <QStringList>
#include <QUrl>

namespace Nullock::Core::Inspector {

namespace {

// application/x-www-form-urlencoded / query decode: '+' -> space, then percent.
// formDecode=false skips the '+'->space step for RFC 6265 cookie values, whose
// octets are opaque -- a '+' there is literal (base64 tokens must not corrupt).
QString urlDecode(const QString &s, bool formDecode = true) {
    QString t = s;
    if (formDecode) t.replace('+', ' ');
    return QUrl::fromPercentEncoding(t.toUtf8());
}

QJsonObject nv(const QString &name, const QString &value) {
    return QJsonObject{ { "name", name }, { "value", value } };
}

// Parse "k=v&k=v" (query string / form body) into name/value pairs.
QJsonArray parsePairs(const QString &s, QChar sep = '&', bool formDecode = true) {
    QJsonArray arr;
    if (s.isEmpty()) return arr;
    for (const QString &rawPart : s.split(sep, Qt::SkipEmptyParts)) {
        // Trim surrounding whitespace (cookie pairs are "; "-separated). An
        // encoded space in a value is "%20"/"+" -- inside the token, not stripped.
        const QString part = rawPart.trimmed();
        if (part.isEmpty()) continue;
        const int eq = part.indexOf('=');
        if (eq < 0) arr.append(nv(urlDecode(part, formDecode), QString()));
        else arr.append(nv(urlDecode(part.left(eq), formDecode), urlDecode(part.mid(eq + 1), formDecode)));
    }
    return arr;
}

// Split a raw message into (start line, header lines, body). Tolerant of LF-only.
struct Parsed {
    QString start;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
};

Parsed splitMessage(const QByteArray &rawIn) {
    Parsed p;
    QByteArray raw = rawIn.left(kMaxInput);
    // Header/body boundary: CRLFCRLF or LFLF.
    int sep = raw.indexOf("\r\n\r\n");
    int seplen = 4;
    if (sep < 0) { sep = raw.indexOf("\n\n"); seplen = 2; }
    QByteArray head = sep < 0 ? raw : raw.left(sep);
    p.body = sep < 0 ? QByteArray() : raw.mid(sep + seplen);

    const QString headStr = QString::fromUtf8(head);
    QStringList lines = headStr.split('\n');
    for (QString &l : lines) if (l.endsWith('\r')) l.chop(1);
    if (lines.isEmpty()) return p;
    p.start = lines.first();
    for (int i = 1; i < lines.size(); ++i) {
        const QString &l = lines[i];
        if (l.trimmed().isEmpty()) continue;
        const int c = l.indexOf(':');
        if (c < 0) continue;
        p.headers.append({ l.left(c).trimmed(), l.mid(c + 1).trimmed() });
    }
    return p;
}

QString headerValue(const QList<QPair<QString, QString>> &hs, const QString &name) {
    for (const auto &h : hs)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

QJsonArray headersJson(const QList<QPair<QString, QString>> &hs) {
    QJsonArray arr;
    for (const auto &h : hs) arr.append(nv(h.first, h.second));
    return arr;
}

// b64url-decode a JWT segment -> JSON object (no crypto, decode only).
QJsonObject b64urlJson(const QString &seg, bool &ok) {
    ok = false;
    const QByteArray dec = QByteArray::fromBase64(
        seg.toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(dec, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) return {};
    ok = true;
    return doc.object();
}

// If `value` is a compact JWT ("a.b.c" of base64url segments whose header
// decodes to a JSON object), return the decoded {alg,typ,header,payload}.
bool decodeJwt(const QString &value, QJsonObject &out) {
    static const QRegularExpression re(
        QStringLiteral("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$"));
    const QString v = value.trimmed();
    if (v.size() < 20 || v.size() > 8192) return false;   // bound
    if (!re.match(v).hasMatch()) return false;
    const QStringList parts = v.split('.');
    if (parts.size() != 3) return false;
    bool hok = false, pok = false;
    const QJsonObject header = b64urlJson(parts[0], hok);
    if (!hok || !header.contains("alg")) return false;     // must look like a JOSE header
    const QJsonObject payload = b64urlJson(parts[1], pok);
    out = QJsonObject{
        { "alg", header.value("alg").toString() },
        { "typ", header.value("typ").toString() },
        { "header", header },
        { "payload", pok ? QJsonValue(payload) : QJsonValue(QJsonValue::Null) },
    };
    return true;
}

// Scan header + cookie values for JWTs. `where` labels the source.
void collectJwts(const QList<QPair<QString, QString>> &hs, QJsonArray &out) {
    for (const auto &h : hs) {
        // A bare token, or "Bearer <token>".
        QString v = h.second;
        if (v.startsWith(QLatin1String("Bearer "), Qt::CaseInsensitive)) v = v.mid(7).trimmed();
        QJsonObject jwt;
        if (decodeJwt(v, jwt)) {
            jwt.insert("where", "header:" + h.first);
            out.append(jwt);
        }
        // Cookie header: scan each cookie value.
        if (h.first.compare("Cookie", Qt::CaseInsensitive) == 0
            || h.first.compare("Set-Cookie", Qt::CaseInsensitive) == 0) {
            for (const QString &c : h.second.split(';', Qt::SkipEmptyParts)) {
                const int eq = c.indexOf('=');
                if (eq < 0) continue;
                QJsonObject cjwt;
                if (decodeJwt(c.mid(eq + 1), cjwt)) {
                    cjwt.insert("where", "cookie:" + c.left(eq).trimmed());
                    out.append(cjwt);
                }
            }
        }
    }
}

} // namespace

QJsonObject inspectRequest(const QByteArray &raw) {
    const Parsed p = splitMessage(raw);
    QJsonObject out;

    // Request line: METHOD TARGET VERSION.
    const QStringList sl = p.start.split(' ', Qt::SkipEmptyParts);
    out["method"]  = sl.size() > 0 ? sl[0] : QString();
    const QString target = sl.size() > 1 ? sl[1] : QString();
    out["target"]  = target;
    out["version"] = sl.size() > 2 ? sl[2] : QString();

    const int q = target.indexOf('?');
    out["path"]  = q < 0 ? target : target.left(q);
    const QString query = q < 0 ? QString() : target.mid(q + 1);
    out["query"] = query;
    out["queryParams"] = parsePairs(query);

    out["headers"] = headersJson(p.headers);

    // Cookies from the Cookie header. RFC 6265 cookie values are opaque octets --
    // '+' is literal (do NOT form-decode it to a space, which corrupts base64).
    out["cookies"] = parsePairs(headerValue(p.headers, "Cookie"), ';', /*formDecode=*/false);

    const QString ct = headerValue(p.headers, "Content-Type");
    out["contentType"] = ct;
    out["bodySize"] = p.body.size();

    // Body params: form-urlencoded pairs, or JSON top-level keys.
    QJsonArray bodyParams;
    QString bodyKind;
    if (ct.contains("application/x-www-form-urlencoded", Qt::CaseInsensitive)) {
        bodyKind = "form";
        bodyParams = parsePairs(QString::fromUtf8(p.body));
    } else if (ct.contains("application/json", Qt::CaseInsensitive) || p.body.trimmed().startsWith("{")) {
        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(p.body, &pe);
        if (pe.error == QJsonParseError::NoError && doc.isObject()) {
            bodyKind = "json";
            const QJsonObject o = doc.object();
            for (auto it = o.begin(); it != o.end(); ++it) {
                const QJsonValue v = it.value();
                QString sval;
                if      (v.isString()) sval = v.toString();
                else if (v.isDouble()) {
                    // Preserve exact integer text -- a bare QString::number(double)
                    // emits 6-sig-fig scientific notation for 64-bit IDs / epochs.
                    const double d = v.toDouble();
                    const qint64 i = v.toInteger();
                    sval = (static_cast<double>(i) == d) ? QString::number(i)
                                                         : QString::number(d, 'g', 17);
                }
                else if (v.isBool())   sval = v.toBool() ? QStringLiteral("true") : QStringLiteral("false");
                else if (v.isNull())   sval = QStringLiteral("null");
                else if (v.isObject()) sval = QStringLiteral("{…}");
                else if (v.isArray())  sval = QStringLiteral("[…]");
                bodyParams.append(nv(it.key(), sval));
            }
        } else if (ct.contains("json", Qt::CaseInsensitive)) {
            bodyKind = "json";   // declared JSON but didn't parse as an object
        } else {
            // Reached only through the `body starts with '{'` SNIFF above (a
            // Content-Type declaring json is caught by the branch just above), so the
            // body is non-empty by construction but is neither parseable JSON nor
            // declared as JSON -- it is just an opaque body. Falling through here left
            // bodyKind EMPTY, which is the exact value the Inspector uses to mean "no
            // body at all": a non-empty body was reported as having no kind purely
            // because its first byte happened to be '{'.
            bodyKind = "other";
        }
    } else if (!p.body.isEmpty()) {
        bodyKind = "other";
    }
    out["bodyKind"] = bodyKind;
    out["bodyParams"] = bodyParams;

    QJsonArray jwts;
    collectJwts(p.headers, jwts);
    out["jwts"] = jwts;

    return out;
}

QJsonObject inspectResponse(const QByteArray &raw) {
    const Parsed p = splitMessage(raw);
    QJsonObject out;

    // Status line: VERSION STATUS REASON...
    const QStringList sl = p.start.split(' ', Qt::SkipEmptyParts);
    out["version"] = sl.size() > 0 ? sl[0] : QString();
    out["status"]  = sl.size() > 1 ? sl[1].toInt() : 0;
    out["reason"]  = sl.size() > 2 ? sl.mid(2).join(' ') : QString();

    out["headers"] = headersJson(p.headers);

    // Every Set-Cookie header, name=value + the attribute string.
    QJsonArray setCookies;
    for (const auto &h : p.headers) {
        if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
        const QStringList segs = h.second.split(';');
        const QString first = segs.isEmpty() ? QString() : segs.first();
        const int eq = first.indexOf('=');
        QJsonObject c;
        c["name"]  = eq < 0 ? first.trimmed() : first.left(eq).trimmed();
        c["value"] = eq < 0 ? QString() : first.mid(eq + 1).trimmed();
        c["attributes"] = segs.size() > 1 ? segs.mid(1).join(';').trimmed() : QString();
        setCookies.append(c);
    }
    out["setCookies"] = setCookies;

    out["contentType"] = headerValue(p.headers, "Content-Type");
    out["bodySize"] = p.body.size();
    out["bodyPreview"] = QString::fromUtf8(p.body.left(kBodyPreview));

    QJsonArray jwts;
    collectJwts(p.headers, jwts);
    out["jwts"] = jwts;

    return out;
}

} // namespace Nullock::Core::Inspector

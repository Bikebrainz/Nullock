#include "inspector_logic.hpp"

#include "transcode.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QXmlStreamReader>
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

// For each {name,value} param, run the bounded recursive Transcode::smartDecode
// over the value; when it makes progress (e.g. a URL-then-base64-encoded token),
// attach `decoded` (the final value) and `decodeChain` (the ordered ops) to that
// param so the Inspector can reveal what an encoded value really is. Params that
// don't decode are left untouched. Bounded: smartDecode itself caps at 12 steps.
void attachDecodeChains(QJsonArray &params) {
    for (int i = 0; i < params.size(); ++i) {
        QJsonObject o = params[i].toObject();
        const QString v = o.value(QStringLiteral("value")).toString();
        if (v.size() < 4) continue;                       // too short to be an encoded value
        QStringList chain;
        const Transcode::Result r = Transcode::smartDecode(v, &chain);
        if (r.ok && !chain.isEmpty()) {
            o[QStringLiteral("decoded")]     = r.output;
            o[QStringLiteral("decodeChain")] = QJsonArray::fromStringList(chain);
            params[i] = o;
        }
    }
}

// A JSON SCALAR rendered as a parameter value. Preserves exact 64-bit integer
// text -- a bare QString::number(double) mangles a big ID / epoch into 6-sig-fig
// scientific notation. Non-scalars are handled by flattenJson, not here.
QString jsonScalar(const QJsonValue &v) {
    if (v.isString()) return v.toString();
    if (v.isBool())   return v.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    if (v.isNull())   return QStringLiteral("null");
    if (v.isDouble()) {
        const double d = v.toDouble();
        const qint64 i = v.toInteger();
        return (static_cast<double>(i) == d) ? QString::number(i)
                                             : QString::number(d, 'g', 17);
    }
    return QString();
}

// Recursively flatten a JSON value into Burp-style dotted / bracketed parameter
// leaves: an object key appends ".key" ("key" at the root), an array element
// appends "[i]". Each scalar becomes one {name,value} leaf; an EMPTY object or
// array becomes a single "{}"/"[]" placeholder leaf so a key never silently
// vanishes. Bounded: at maxDepth a deeper node collapses to a "{…}"/"[…}"
// placeholder, and the walk stops once `out` reaches maxParams -- so a deeply
// nested or huge body can neither blow the stack nor flood the output.
void flattenJson(const QJsonValue &v, const QString &prefix, QJsonArray &out,
                 int depth, int maxDepth, int maxParams) {
    if (out.size() >= maxParams) return;
    if (v.isObject()) {
        const QJsonObject o = v.toObject();
        if (o.isEmpty())       { out.append(nv(prefix, QStringLiteral("{}")));  return; }
        if (depth >= maxDepth) { out.append(nv(prefix, QStringLiteral("{…}"))); return; }
        for (auto it = o.begin(); it != o.end() && out.size() < maxParams; ++it) {
            const QString child = prefix.isEmpty() ? it.key()
                                                   : prefix + QLatin1Char('.') + it.key();
            flattenJson(it.value(), child, out, depth + 1, maxDepth, maxParams);
        }
    } else if (v.isArray()) {
        const QJsonArray a = v.toArray();
        if (a.isEmpty())       { out.append(nv(prefix, QStringLiteral("[]")));  return; }
        if (depth >= maxDepth) { out.append(nv(prefix, QStringLiteral("[…]"))); return; }
        for (int i = 0; i < a.size() && out.size() < maxParams; ++i) {
            const QString child = prefix + QLatin1Char('[') + QString::number(i) + QLatin1Char(']');
            flattenJson(a.at(i), child, out, depth + 1, maxDepth, maxParams);
        }
    } else {
        out.append(nv(prefix, jsonScalar(v)));
    }
}

// Extract a `key="value"` / `key=value` parameter from a header value like
// `form-data; name="file"; filename="a.txt"` (case-insensitive key).
QString headerParam(const QString &headerVal, const QString &key) {
    const QRegularExpression re(
        QRegularExpression::escape(key) + QStringLiteral("\\s*=\\s*(?:\"([^\"]*)\"|([^;]+))"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch m = re.match(headerVal);
    if (!m.hasMatch()) return QString();
    return m.captured(1).isNull() ? m.captured(2).trimmed() : m.captured(1);
}

// The boundary token from a multipart Content-Type (`; boundary=..` quoted or not).
QByteArray multipartBoundary(const QString &contentType) {
    return headerParam(contentType, QStringLiteral("boundary")).toUtf8();
}

// Parse a multipart/form-data body into one param per part: a text field ->
// name=value (body preview-capped), a file field (has filename=) ->
// name="[file: <filename>, <N> bytes]" so an upload is visible without echoing
// the bytes. Operates on RAW bytes so a binary part is never transcode-mangled.
// Bounded at maxParams; a malformed body yields whatever parts parsed.
QJsonArray parseMultipart(const QByteArray &body, const QByteArray &boundary, int maxParams) {
    QJsonArray out;
    if (boundary.isEmpty()) return out;
    const QByteArray delim = "--" + boundary;
    int pos = body.indexOf(delim);
    if (pos < 0) return out;
    pos += delim.size();
    while (out.size() < maxParams) {
        if (body.mid(pos, 2) == "--") break;                 // closing delimiter --boundary--
        int hstart = pos;
        if (body.mid(hstart, 2) == "\r\n")      hstart += 2;  // CRLF after the delimiter
        else if (body.mid(hstart, 1) == "\n")   hstart += 1;
        const int next = body.indexOf(delim, hstart);
        if (next < 0) break;
        QByteArray part = body.mid(hstart, next - hstart);
        if (part.endsWith("\r\n"))    part.chop(2);          // CRLF before the next delimiter
        else if (part.endsWith("\n")) part.chop(1);
        int hb = part.indexOf("\r\n\r\n"); int hblen = 4;
        if (hb < 0) { hb = part.indexOf("\n\n"); hblen = 2; }
        const QByteArray phead = hb < 0 ? part : part.left(hb);
        const QByteArray pbody = hb < 0 ? QByteArray() : part.mid(hb + hblen);
        QString cd;
        for (const QByteArray &rawLine : phead.split('\n')) {
            QByteArray h = rawLine;
            if (h.endsWith('\r')) h.chop(1);
            if (QString::fromUtf8(h).startsWith(QLatin1String("Content-Disposition"), Qt::CaseInsensitive))
                cd = QString::fromUtf8(h);
        }
        const QString name = headerParam(cd, QStringLiteral("name"));
        const QString filename = headerParam(cd, QStringLiteral("filename"));
        if (!filename.isEmpty())
            out.append(nv(name, QStringLiteral("[file: %1, %2 bytes]").arg(filename).arg(pbody.size())));
        else
            out.append(nv(name, QString::fromUtf8(pbody.left(kBodyPreview))));
        pos = next + delim.size();
    }
    return out;
}

// Flatten an XML body into dotted element-path params: leaf element text ->
// path=value (e.g. order.item.qty), and each attribute -> path@attr=value.
// Text is reset at every element boundary, so a data-XML leaf reports its value
// and a container element (whitespace-only text) reports none. Bounded at
// maxParams; a malformed document yields whatever parsed before the error.
void flattenXml(const QByteArray &body, QJsonArray &out, int maxParams) {
    QXmlStreamReader xml(body);
    QStringList path;
    QString text;
    while (!xml.atEnd() && out.size() < maxParams) {
        xml.readNext();
        if (xml.isStartElement()) {
            path << xml.name().toString();
            const QString here = path.join(QLatin1Char('.'));
            for (const QXmlStreamAttribute &a : xml.attributes()) {
                if (out.size() >= maxParams) break;
                out.append(nv(here + QLatin1Char('@') + a.name().toString(), a.value().toString()));
            }
            text.clear();
        } else if (xml.isCharacters() && !xml.isWhitespace()) {
            text += xml.text().toString();
        } else if (xml.isEndElement()) {
            const QString t = text.trimmed();
            if (!t.isEmpty() && out.size() < maxParams) out.append(nv(path.join(QLatin1Char('.')), t));
            if (!path.isEmpty()) path.removeLast();
            text.clear();
        }
    }
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
    QJsonArray queryParams = parsePairs(query);
    attachDecodeChains(queryParams);          // reveal URL/base64/hex/jwt-encoded values
    out["queryParams"] = queryParams;

    // HTTP/2 pseudo-header projection of the request line + authority. Lets the
    // Inspector show the h2 view (:method/:path/:authority/:scheme) of a request
    // regardless of the wire protocol. :scheme defaults to https (the MITM'd
    // case) since a raw HTTP/1 request line carries no scheme.
    out["pseudoHeaders"] = QJsonArray{
        nv(QStringLiteral(":method"),    sl.size() > 0 ? sl[0] : QString()),
        nv(QStringLiteral(":path"),      target),
        nv(QStringLiteral(":authority"), headerValue(p.headers, QStringLiteral("Host"))),
        nv(QStringLiteral(":scheme"),    QStringLiteral("https")),
    };

    out["headers"] = headersJson(p.headers);

    // Cookies from the Cookie header. RFC 6265 cookie values are opaque octets --
    // '+' is literal (do NOT form-decode it to a space, which corrupts base64).
    QJsonArray cookies = parsePairs(headerValue(p.headers, "Cookie"), ';', /*formDecode=*/false);
    attachDecodeChains(cookies);              // session tokens are often base64/jwt
    out["cookies"] = cookies;

    const QString ct = headerValue(p.headers, "Content-Type");
    out["contentType"] = ct;
    out["bodySize"] = p.body.size();

    // Body params: form-urlencoded pairs, or JSON top-level keys.
    QJsonArray bodyParams;
    QString bodyKind;
    if (ct.contains("application/x-www-form-urlencoded", Qt::CaseInsensitive)) {
        bodyKind = "form";
        bodyParams = parsePairs(QString::fromUtf8(p.body));
    } else if (ct.contains("multipart/form-data", Qt::CaseInsensitive)) {
        bodyKind = "multipart";
        bodyParams = parseMultipart(p.body, multipartBoundary(ct), /*maxParams=*/2000);
    } else if (ct.contains("application/json", Qt::CaseInsensitive)
               || p.body.trimmed().startsWith("{") || p.body.trimmed().startsWith("[")) {
        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(p.body, &pe);
        if (pe.error == QJsonParseError::NoError && (doc.isObject() || doc.isArray())) {
            bodyKind = "json";
            // Recursively flatten to Burp-style dotted/bracketed leaves so a
            // nested API body (objects/arrays) is fully visible in the params
            // view, not collapsed to a bare {…}/[…] placeholder. Handles a
            // top-level array too. Depth- and count-bounded.
            const QJsonValue root = doc.isObject() ? QJsonValue(doc.object())
                                                   : QJsonValue(doc.array());
            flattenJson(root, QString(), bodyParams, 0, /*maxDepth=*/64, /*maxParams=*/2000);
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
    } else if (ct.contains("xml", Qt::CaseInsensitive) || p.body.trimmed().startsWith("<")) {
        // application/xml, text/xml, application/soap+xml, or a sniffed '<' body.
        // Flatten to element-path params; a sniffed-but-unparseable '<' body that
        // yields nothing is just an opaque body (bodyKind "other"), mirroring the
        // JSON sniff's fall-through so a stray '<' never masquerades as XML.
        QJsonArray xmlParams;
        flattenXml(p.body, xmlParams, /*maxParams=*/2000);
        if (!xmlParams.isEmpty()) { bodyKind = "xml"; bodyParams = xmlParams; }
        else if (ct.contains("xml", Qt::CaseInsensitive)) bodyKind = "xml";
        else bodyKind = "other";
    } else if (!p.body.isEmpty()) {
        bodyKind = "other";
    }
    out["bodyKind"] = bodyKind;
    attachDecodeChains(bodyParams);           // form/json body values may be encoded too
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

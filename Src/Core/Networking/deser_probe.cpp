#include "deser_probe.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::DeserProbe {

namespace {

constexpr int kMaxSends = 90;
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *engine; QRegularExpression re; };

// Each regex matches a deserialization-SPECIFIC parse error -- a fragment the
// deserializer itself emits when it fails to read a stream -- NOT a generic 500
// and NOT a bare API name (e.g. "unserialize()" / "ClassNotFoundException")
// that also appears in type warnings, JNDI/startup traces, docs, or WAF text.
const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        { "Java",   QRegularExpression("java\\.io\\.(StreamCorruptedException|OptionalDataException|"
                                       "InvalidClassException|WriteAbortedException|EOFException)|"
                                       "invalid stream header|cannot be cast to java\\.io\\.Serializable", ci) },
        { "PHP",    QRegularExpression("Error at offset \\d+ of \\d+ bytes|__PHP_Incomplete_Class|"
                                       "Premature end of data|unserialize\\(\\):\\s*Error", ci) },
        { "Python", QRegularExpression("(_pickle|cPickle|pickle)\\.UnpicklingError|UnpicklingError|"
                                       "pickle data was truncated|unpickling stack underflow|"
                                       "insecure string pickle", ci) },
        { "Ruby",   QRegularExpression("marshal data too short|incompatible marshal file format|"
                                       "dump format error|ArgumentError[^\\n]*marshal", ci) },
        { ".NET",   QRegularExpression("System\\.Runtime\\.Serialization\\.SerializationException|"
                                       "End of Stream encountered|does not contain a valid BinaryHeader|"
                                       "input stream is not a valid binary format", ci) },
    };
    return s;
}

// Match a deserialization error in `body`; returns {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.engine), m.captured(0) };
    }
    return {};
}

QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r') || req.method.contains('\n')) return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/deser\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// A POST (or the caller's write method) carrying the serialized stub as the raw
// request body -- the application/x-java-serialized-object class of sink.
QByteArray buildBodyRequest(const Request &req, const QByteArray &body, const QString &ct) {
    QString method = req.method;
    if (method.isEmpty() || method.compare("GET", Qt::CaseInsensitive) == 0)
        method = QStringLiteral("POST");
    if (method.contains('\r') || method.contains('\n')) return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    QByteArray out;
    out  = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/deser\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Content-Type: " + ct.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

// Cookie names that classically carry a base64 serialized blob.
QStringList knownCookieNames() {
    return { "rememberMe", "remember_me", "remember-me", "remember_token",
             "_session", "session", "rack.session", "_rails_session",
             "auth", "sso", "user" };
}

// A GET carrying the serialized stub in a named cookie (the Shiro rememberMe /
// Ruby Marshal-session class of sink).
QByteArray buildCookieRequest(const Request &req, const QString &cookieName,
                              const QString &value) {
    if (req.method.contains('\r') || req.method.contains('\n')) return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (cookieName.contains('\r') || cookieName.contains('\n')) return {};
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    QString safeVal = value;
    safeVal.remove('\r'); safeVal.remove('\n'); safeVal.remove(';');  // cookie-value-safe
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/deser\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Cookie: " + cookieName.toUtf8() + "=" + safeVal.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Cookie", Qt::CaseInsensitive) == 0) continue;  // we set it
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QString queryWith(const QString &existing, const QString &param, const QString &value) {
    const QByteArray enc = QUrl::toPercentEncoding(value);
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + QString::fromUtf8(enc);
    return parts.join('&');
}

} // namespace

QStringList defaultParams() {
    // Names that carry serialized blobs in the wild -- incl. the .NET WebForms,
    // Apache Shiro remember-me, and JSF ViewState classics. (Many ride in
    // cookies/bodies, not the query -- see the scope note in the header; those
    // are flagged passively, not yet actively confirmed here.)
    return { "data", "state", "payload", "obj", "object", "ser", "token",
             "session", "input", "cache", "view", "o",
             "__VIEWSTATE", "__EVENTVALIDATION", "viewstate", "rememberMe",
             "remember_me", "javax.faces.ViewState", "jsf", "auth", "pref",
             "profile" };
}

QString kindForFormat(const QString &format) {
    if (format == "Java")   return QStringLiteral("deser-java");
    if (format == "PHP")    return QStringLiteral("deser-php");
    if (format == "Python") return QStringLiteral("deser-pickle");
    if (format == "Ruby")   return QStringLiteral("deser-ruby");
    if (format == ".NET")   return QStringLiteral("deser-dotnet");
    return QStringLiteral("deser-unknown");
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Raw-body injection: send each format's well-formed/malformed serialized
    // object as the REQUEST BODY (the application/x-java-serialized-object class
    // of sink). Same well-formed-vs-malformed differential as the query path.
    if (req.location.compare("body", Qt::CaseInsensitive) == 0) {
        HttpClient bclient;
        const quint16 bport = static_cast<quint16>(req.port);
        struct BodyProbe { const char *format; const char *wf; const char *mf;
                           const char *ct; bool b64; };
        static const QList<BodyProbe> bprobes = {
            { "Java",   "rO0ABXQAA2FiYw==", "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=",
              "application/x-java-serialized-object", true },
            { "PHP",    "O:8:\"stdClass\":1:{s:1:\"a\";i:1;}",
              "O:18:\"NullockDeserCanary\":9:{s:1:\"x\";i:1;}",
              "application/x-www-form-urlencoded", false },
            { "Python", "gAJLAS4=", "gASVBQAAAAAAAACMAQ", "application/python-pickle", true },
            { "Ruby",   "BAhpBg==", "BAhbBg==", "application/octet-stream", true },
        };
        result.testedParams = QStringList{ QStringLiteral("(request body)") };
        auto raw = [](const char *s, bool b64) {
            return b64 ? QByteArray::fromBase64(QByteArray(s)) : QByteArray(s);
        };
        auto sendBody = [&](const QByteArray &b, const QString &ct) {
            ++result.requestsSent;
            return bclient.send(req.host, bport, req.tls, buildBodyRequest(req, b, ct));
        };
        for (const BodyProbe &p : bprobes) {
            if (result.requestsSent >= kMaxSends) break;
            const QString ct = req.contentType.isEmpty()
                ? QString::fromUtf8(p.ct) : req.contentType;
            const auto wf = sendBody(raw(p.wf, p.b64), ct);
            if (!wf.ok) continue;
            result.baselineStatus = wf.parsed.statusCode;
            if (!matchError(wf.parsed.body).first.isEmpty()) continue;  // shape-WAF / strict / not a deser
            const auto mf = sendBody(raw(p.mf, p.b64), ct);
            if (!mf.ok) continue;
            const auto err = matchError(mf.parsed.body);
            if (err.first.isEmpty()) continue;
            result.hits.append({ QStringLiteral("(body)"), err.first,
                                 QString::fromUtf8(p.mf), err.second });
            result.vulnerable = true;
            break;
        }
        return result;
    }

    // Cookie injection: serialized blobs classically ride in auth/session
    // cookies (Shiro/Spring rememberMe, Ruby Marshal _session). Inject each
    // binary format's base64 well-formed/malformed object into a candidate
    // cookie; same differential. (PHP's text form doesn't fit a cookie value.)
    if (req.location.compare("cookie", Qt::CaseInsensitive) == 0) {
        HttpClient cclient;
        const quint16 cport = static_cast<quint16>(req.port);
        struct Ck { const char *format; const char *wf; const char *mf; };
        static const QList<Ck> cprobes = {
            { "Java",   "rO0ABXQAA2FiYw==", "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=" },
            { "Python", "gAJLAS4=", "gASVBQAAAAAAAACMAQ" },
            { "Ruby",   "BAhpBg==", "BAhbBg==" },
        };
        QStringList cookies;
        if (!req.param.isEmpty()) cookies << req.param;
        else cookies = knownCookieNames();
        while (cookies.size() > 8) cookies.removeLast();
        result.testedParams = cookies;
        auto sendCookie = [&](const QString &name, const QString &val) {
            ++result.requestsSent;
            return cclient.send(req.host, cport, req.tls, buildCookieRequest(req, name, val));
        };
        for (const QString &ck : cookies) {
            if (result.requestsSent >= kMaxSends) break;
            for (const Ck &p : cprobes) {
                if (result.requestsSent >= kMaxSends) break;
                const auto wf = sendCookie(ck, QString::fromUtf8(p.wf));
                if (!wf.ok) continue;
                result.baselineStatus = wf.parsed.statusCode;
                if (!matchError(wf.parsed.body).first.isEmpty()) continue;  // shape-WAF / not a deser
                const auto mf = sendCookie(ck, QString::fromUtf8(p.mf));
                if (!mf.ok) continue;
                const auto err = matchError(mf.parsed.body);
                if (err.first.isEmpty()) continue;
                result.hits.append({ "cookie:" + ck, err.first,
                                     QString::fromUtf8(p.mf), err.second });
                result.vulnerable = true;
                return result;     // one confirmed cookie sink is enough
            }
        }
        return result;
    }

    // Build the param set: the named param, else the query keys MERGED with the
    // curated carriers (so a URL that already has one query param doesn't shut
    // out the known names), prioritizing query keys, then capped.
    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        for (const QString &d : defaultParams())
            if (!params.contains(d)) params << d;
    }
    while (params.size() > 10) params.removeLast();
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

    // Sound discriminator: a real deserializer ACCEPTS a well-formed benign
    // serialized object (deserializes it -> no parse error) but ERRORS on a
    // malformed one. A shape-keyed WAF/blocklist errors on BOTH (it never
    // deserializes -- it sniffs the magic), so the well-formed control errors
    // too and we don't flag. An echo/store sink errors on NEITHER. The
    // well-formed object is inert (a String / the integer 1); the malformed one
    // references only a non-existent canary class and fails before any gadget.
    struct Probe { const char *format; const char *wellFormed; const char *malformed; };
    static const QList<Probe> probes = {
        { "Java",   "rO0ABXQAA2FiYw==",
                    "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=" },        // magic + obj header, truncated
        { "PHP",    "O:8:\"stdClass\":1:{s:1:\"a\";i:1;}",           // benign stdClass (no magic methods)
                    "O:18:\"NullockDeserCanary\":9:{s:1:\"x\";i:1;}" }, // declared 9 props, 1 given
        { "Python", "gAJLAS4=",
                    "gASVBQAAAAAAAACMAQ" },                          // truncated pickle
        { "Ruby",   "BAhpBg==",
                    "BAhbBg==" },                                    // Marshal array len 1, no elements -> EOF before any class
    };

    QSet<QString> confirmedParams;
    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        if (confirmedParams.contains(param)) continue;
        for (const Probe &p : probes) {
            if (result.requestsSent >= kMaxSends) break;
            // 1) Well-formed control: a real deserializer accepts it cleanly.
            const auto wf = send(queryWith(req.query, param, QString::fromUtf8(p.wellFormed)));
            if (!wf.ok) continue;
            // If even valid serialized data errors, the sink isn't a plain
            // deserializer (shape-WAF / strict type / not deserializing) --
            // can't soundly attribute a malformed error to deserialization.
            if (!matchError(wf.parsed.body).first.isEmpty()) continue;
            // 2) Malformed of the same format: a real deserializer errors.
            const auto mf = send(queryWith(req.query, param, QString::fromUtf8(p.malformed)));
            if (!mf.ok) continue;
            const auto err = matchError(mf.parsed.body);
            if (err.first.isEmpty()) continue;
            result.hits.append({ param, err.first,
                                 QString::fromUtf8(p.malformed), err.second });
            result.vulnerable = true;
            confirmedParams.insert(param);
            break;
        }
    }

    return result;
}

} // namespace Nullock::Core::DeserProbe

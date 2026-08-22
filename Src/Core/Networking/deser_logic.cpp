// Pure (no-network) logic for the insecure-deserialization probe: the
// deserialization-specific error signatures, the four request builders' CR/LF
// guards, the query-rewrite helper, and the curated carrier name lists. Split
// out of deser_probe.cpp so Tests/deser_probe links Qt6::Core alone.

#include "deser_probe.hpp"

#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::DeserProbe {

namespace {

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

// Reject a CR or LF in any request-line / header field that we write raw.
bool crlf(const QString &s) { return s.contains('\r') || s.contains('\n'); }

} // namespace

QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.engine), m.captured(0) };
    }
    return {};
}

QByteArray buildRequest(const Request &req, const QString &query) {
    if (crlf(req.method) || crlf(req.host) || crlf(req.basePath) || crlf(query)) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/deser\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // Drop carried framing/encoding headers that fight the ones this BODY-LESS GET
        // forces (Accept-Encoding: identity above, Connection: close below):
        //  - Content-Length / Transfer-Encoding advertise a body that is never sent, so
        //    the server waits for it (the probe stalls) or the socket desyncs.
        //  - a carried Accept-Encoding combines (RFC 9112 7.4) and lets the server
        //    compress, so the raw-byte gadget scan runs on compressed bytes.
        //  - a carried Connection: keep-alive contradicts the forced close.
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QByteArray buildBodyRequest(const Request &req, const QByteArray &body, const QString &ct) {
    QString method = req.method;
    if (method.isEmpty() || method.compare("GET", Qt::CaseInsensitive) == 0)
        method = QStringLiteral("POST");
    if (crlf(method) || crlf(req.host) || crlf(req.basePath) || crlf(req.query) || crlf(ct)) return {};
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
        // A carried Transfer-Encoding would survive ALONGSIDE the Content-Length this
        // builder computes below -- a CL.TE ambiguous request the scanner sends itself.
        // Accept-Encoding / Connection likewise fight the forced identity + close.
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

QStringList knownCookieNames() {
    return { "rememberMe", "remember_me", "remember-me", "remember_token",
             "_session", "session", "rack.session", "_rails_session",
             "auth", "sso", "user" };
}

QByteArray buildCookieRequest(const Request &req, const QString &cookieName,
                              const QString &value) {
    if (crlf(req.method) || crlf(req.host) || crlf(req.basePath) || crlf(cookieName) || crlf(req.query)) return {};
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
        // Body-less GET: same carried framing/encoding drops as the sibling builders.
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QStringList knownFieldNames() {
    return { "__VIEWSTATE", "viewstate", "data", "state", "payload",
             "obj", "object", "ser", "input", "json" };
}

QByteArray buildFieldRequest(const Request &req, const QString &field, const QString &value) {
    QString method = req.method;
    if (method.isEmpty() || method.compare("GET", Qt::CaseInsensitive) == 0)
        method = QStringLiteral("POST");
    if (crlf(method) || crlf(req.host) || crlf(req.basePath) || crlf(req.query)) return {};
    const QString target = req.query.isEmpty() ? req.basePath : req.basePath + "?" + req.query;
    const QByteArray body = QUrl::toPercentEncoding(field) + "=" + QUrl::toPercentEncoding(value);
    QByteArray out;
    out  = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/deser\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Content-Type: application/x-www-form-urlencoded\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // A carried Transfer-Encoding would survive ALONGSIDE the Content-Length this
        // builder computes below -- a CL.TE ambiguous request the scanner sends itself.
        // Accept-Encoding / Connection likewise fight the forced identity + close.
        if (h.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Connection", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
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

QStringList defaultParams() {
    // Framework-specific serialized-blob carriers FIRST so they survive the
    // auto-detect param cap (.NET WebForms __VIEWSTATE/__EVENTVALIDATION, JSF
    // ViewState, Apache Shiro remember-me), then the generic names. (Many also
    // ride in cookies/bodies -- see the cookie/field carrier lists.)
    return { "__VIEWSTATE", "__EVENTVALIDATION", "viewstate", "javax.faces.ViewState",
             "jsf", "rememberMe", "remember_me",
             "data", "state", "payload", "obj", "object", "ser", "token",
             "session", "input", "cache", "view", "o", "auth", "pref", "profile" };
}

QString kindForFormat(const QString &format) {
    if (format == "Java")   return QStringLiteral("deser-java");
    if (format == "PHP")    return QStringLiteral("deser-php");
    if (format == "Python") return QStringLiteral("deser-pickle");
    if (format == "Ruby")   return QStringLiteral("deser-ruby");
    if (format == ".NET")   return QStringLiteral("deser-dotnet");
    return QStringLiteral("deser-unknown");
}

bool confirmsDeser(bool wfOk, bool wfErr, bool mfOk, bool mfErr,
                   bool wf2Ok, bool wf2Err) {
    return wfOk && !wfErr    // well-formed control clean (not a shape-WAF)
        && mfOk && mfErr     // malformed of the same format errors
        && wf2Ok && !wf2Err; // re-confirmed control still clean (no flap)
}

} // namespace Nullock::Core::DeserProbe

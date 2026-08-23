// Pure (no-network) logic for the IDOR/BOLA probe: id-parameter / id-segment
// recognition, numeric detection, neighbor generation with zero-padding
// preservation, id substitution, the request builder's CR/LF guards, and the
// fail-closed control + accessibility decisions. Split out of idor_tester.cpp
// so Tests/idor_tester links Qt6::Core alone (no HttpClient / Network / GUI).

#include "idor_tester.hpp"

#include <QRegularExpression>
#include <QtGlobal>   // qMax, qAbs

namespace Nullock::Core::IdorTester {

bool looksLikeIdParam(const QString &name) {
    // Param names that typically carry an object identifier worth probing.
    // Deliberately excludes pagination/cursor names (page, no, offset) and
    // vague ones (key, ref, node) -- those mutate fine but aren't object ids.
    // The overall match is case-insensitive, but the ".*Id" alternative must stay
    // CASE-SENSITIVE -- it exists to catch camelCase object ids (orderId/userId), a
    // capital 'I'. Under CaseInsensitiveOption a bare ".*Id" degrades to ".*id",
    // matching any word merely ending in the letters i,d (grid, valid, hybrid,
    // solid, rapid, fluid) and firing IDOR replays on benign params. A local
    // (?-i:...) group pins that one alternative to a literal capital-I suffix while
    // the rest (id, .*_id, uid, ...) stays case-insensitive.
    static const QRegularExpression rx(
        R"(^(id|.*_id|(?-i:.*Id)|uid|guid|pid|oid|account|order|doc|file|record|item|object|entity|user|customer|invoice|ticket|message|msg|post|comment)$)",
        QRegularExpression::CaseInsensitiveOption);
    return rx.match(name).hasMatch();
}

bool looksLikeNonIdSegment(const QString &seg, const QString &prev) {
    // A numeric path segment that is really an API version (/v1/2/...) or a
    // path component under a version/api root -- not an object id. We key off
    // the preceding segment, so a legit 4-digit id like /orders/2024 is tested.
    Q_UNUSED(seg);
    static const QRegularExpression verRx("^v\\d+$");
    return verRx.match(prev).hasMatch() || prev == "api" || prev == "rest"
        || prev == "graphql";
}

bool isNumeric(const QString &s) {
    if (s.isEmpty() || s.size() > 18) return false;   // fits in qint64
    for (QChar c : s) if (!c.isDigit()) return false;
    return true;
}

QString pathOnly(const QString &basePath) {
    const int q = basePath.indexOf('?');
    return q < 0 ? basePath : basePath.left(q);
}
QString queryOnly(const QString &basePath) {
    const int q = basePath.indexOf('?');
    return q < 0 ? QString() : basePath.mid(q + 1);
}

QString formatId(qint64 n, const QString &original) {
    // Preserve a fixed-width / zero-padded id space: /doc/00042 -> 00043, not
    // 43 (which would 404 on a width-strict route and miss the neighbor).
    if (n >= 0 && original.size() > 1 && original.startsWith('0'))
        return QString("%1").arg(n, original.size(), 10, QChar('0'));
    return QString::number(n);
}

QStringList neighbors(const QString &original, qint64 v, int count) {
    const qint64 deltas[] = { 1, -1, 2, -2, 5, 10, -5, 100 };
    QStringList out;
    for (qint64 d : deltas) {
        if (out.size() >= count) break;
        const qint64 n = v + d;
        if (n < 0) continue;
        out << formatId(n, original);
    }
    return out;
}

QString withMutatedId(const QString &basePath, const IdLocation &loc,
                      const QString &newId) {
    QString path = pathOnly(basePath);
    QString query = queryOnly(basePath);

    if (loc.kind == IdLocation::PathSegment) {
        QStringList segs = path.split('/');
        if (loc.segIndex >= 0 && loc.segIndex < segs.size())
            segs[loc.segIndex] = newId;
        path = segs.join('/');
    } else {
        const QStringList pairs = query.split('&', Qt::SkipEmptyParts);
        QStringList rebuilt;
        for (const QString &p : pairs) {
            const int eq = p.indexOf('=');
            const QString k = eq > 0 ? p.left(eq) : p;
            if (k == loc.paramName)
                rebuilt << (k + "=" + newId);
            else
                rebuilt << p;
        }
        query = rebuilt.join('&');
    }
    return query.isEmpty() ? path : path + "?" + query;
}

QByteArray buildRequest(const Request &req, const QString &path) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // method/host/path flow raw from the HAR-import / deep-audit path; a CR/LF
    // in any would smuggle a second request line or header -- refuse to build.
    if (crlf(req.method) || crlf(req.host) || crlf(path)) return QByteArray();

    QByteArray out;
    out  = req.method.toUtf8() + " " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/idor-tester\r\n";
    out += "Accept: */*\r\n";
    // Identity encoding so our length-based comparison sees real object
    // sizes, not variable gzip output (compression ratio differs per body).
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding too: we set our own "identity" above so the
        // length-based discriminator sees real object sizes. A carried
        // "gzip, deflate, br" would combine (RFC 7230 3.2.2) to let the server gzip,
        // and the client does NOT inflate -- so the comparison would run on
        // compression-ratio noise, defeating the very invariant identity protects.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

bool controlUsable(int controlLen) {
    return controlLen >= 0;   // fail closed: a failed discriminator -> skip
}

bool isAccessible(int status, bool differsFromNotFound, bool differsFromBaseline) {
    return status >= 200 && status < 300 && differsFromNotFound && differsFromBaseline;
}

int idorTolerance(int baseJitter, int ctrlJitter) {
    return qMax(baseJitter, ctrlJitter) + 16;
}

bool idorDiffersFromNotFound(int len, int ctrlLen, int tol) {
    return qAbs(len - ctrlLen) > tol;
}

} // namespace Nullock::Core::IdorTester

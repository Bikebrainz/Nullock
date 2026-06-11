#include "idor_tester.hpp"
#include "networking.hpp"

#include <QRegularExpression>
#include <QUrl>

namespace Nullock::Core::IdorTester {

namespace {

// Param names that typically carry an object identifier worth probing.
// Deliberately excludes pagination/cursor names (page, no, offset) and
// vague ones (key, ref, node) -- those mutate fine but aren't object ids,
// so probing them just yields different pages of YOUR OWN authorized data.
bool looksLikeIdParam(const QString &name) {
    static const QRegularExpression rx(
        R"(^(id|.*_id|.*Id|uid|guid|pid|oid|account|order|doc|file|record|item|object|entity|user|customer|invoice|ticket|message|msg|post|comment)$)",
        QRegularExpression::CaseInsensitiveOption);
    return rx.match(name).hasMatch();
}

// A numeric path segment that is really an API version (/v1/2/...) or a
// date/path component under a version root (/api/2024/...) -- not an
// object id. `prev` is the preceding path segment (lowercased). We key
// off the preceding segment rather than the value, so a legitimate
// 4-digit object id like /orders/2024 is still tested.
bool looksLikeNonIdSegment(const QString &seg, const QString &prev) {
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

// Rebuild basePath with `loc`'s id replaced by `newId`.
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
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// Candidate neighbor ids for a numeric id, nearest first.
QStringList neighbors(qint64 v, int count) {
    const qint64 deltas[] = { 1, -1, 2, -2, 5, 10, -5, 100 };
    QStringList out;
    for (qint64 d : deltas) {
        if (out.size() >= count) break;
        const qint64 n = v + d;
        if (n < 0) continue;
        out << QString::number(n);
    }
    return out;
}

} // namespace

Result test(const Request &req, const QString &explicitIdParam, int mutationsPerId) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (mutationsPerId < 1) mutationsPerId = 1;
    if (mutationsPerId > 12) mutationsPerId = 12;

    // ---- discover numeric id locations -------------------------------
    QList<IdLocation> locs;
    const QString path = pathOnly(req.basePath);
    const QStringList segs = path.split('/');
    for (int i = 0; i < segs.size(); ++i) {
        if (!isNumeric(segs[i])) continue;
        if (!explicitIdParam.isEmpty()) continue;   // explicit mode = params only
        const QString prev = i > 0 ? segs[i - 1].toLower() : QString();
        if (looksLikeNonIdSegment(segs[i], prev)) continue;   // version / year
        IdLocation l;
        l.kind = IdLocation::PathSegment;
        l.segIndex = i;
        l.originalValue = segs[i];
        l.descriptor = QString("path[%1]").arg(i);
        locs.append(l);
    }
    const QStringList pairs = queryOnly(req.basePath).split('&', Qt::SkipEmptyParts);
    for (const QString &p : pairs) {
        const int eq = p.indexOf('=');
        if (eq <= 0) continue;
        const QString k = p.left(eq), v = p.mid(eq + 1);
        if (!isNumeric(v)) continue;
        const bool want = explicitIdParam.isEmpty() ? looksLikeIdParam(k)
                                                     : (k == explicitIdParam);
        if (!want) continue;
        IdLocation l;
        l.kind = IdLocation::QueryParam;
        l.paramName = k;
        l.originalValue = v;
        l.descriptor = QString("param '%1'").arg(k);
        locs.append(l);
    }
    result.idLocationsFound = locs.size();
    if (locs.isEmpty()) return result;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto fetch = [&](const QString &p) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, p));
    };

    // Baseline (your own object), fetched twice to gauge body stability:
    // pages that embed a per-request CSRF token / timestamp make every
    // response byte-different, so we can't use exact body equality -- we
    // calibrate a length tolerance from the observed jitter and compare on
    // response *size* instead, which is robust to dynamic tokens.
    const auto base1 = fetch(req.basePath);
    if (!base1.ok) { result.error = "baseline failed: " + base1.errorMessage; return result; }
    if (base1.parsed.statusCode < 200 || base1.parsed.statusCode >= 300) {
        result.error = QString("baseline returned status %1 -- provide a valid "
                               "authenticated request to test").arg(base1.parsed.statusCode);
        return result;
    }
    const auto base2 = fetch(req.basePath);
    const QByteArray baseBody = base1.parsed.body;
    const int baseLen = baseBody.size();
    const int baseJitter = base2.ok ? qAbs(base2.parsed.body.size() - baseLen) : 0;

    for (const IdLocation &loc : locs) {
        bool ok = false;
        const qint64 v = loc.originalValue.toLongLong(&ok);
        if (!ok) continue;

        // Discriminator: two wildly out-of-range ids teach us what
        // "no such object / forbidden" looks like AND how much its length
        // jitters (dynamic tokens again).
        const auto ctrlA = fetch(withMutatedId(req.basePath, loc, QString::number(v + 1000000007LL)));
        const auto ctrlB = fetch(withMutatedId(req.basePath, loc, QString::number(v + 999999937LL)));
        const int ctrlLen    = ctrlA.ok ? ctrlA.parsed.body.size() : -1;
        const int ctrlJitter = (ctrlA.ok && ctrlB.ok)
                               ? qAbs(ctrlB.parsed.body.size() - ctrlLen) : 0;
        const int tol = qMax(baseJitter, ctrlJitter) + 16;

        Finding finding;
        finding.loc = loc;
        for (const QString &nid : neighbors(v, mutationsPerId)) {
            const auto r = fetch(withMutatedId(req.basePath, loc, nid));
            if (!r.ok) continue;
            const int st  = r.parsed.statusCode;
            const QByteArray body = r.parsed.body;
            const int len = body.size();
            // Accessible object = a 2xx response that is (a) not the
            // not-found template -- its length is meaningfully different
            // from the control -- and (b) not literally your own identical
            // object (an endpoint that ignores the id / serves a static
            // page returns body == baseBody for every neighbor).
            const bool twoxx       = st >= 200 && st < 300;
            const bool notNotFound = (ctrlLen < 0) || qAbs(len - ctrlLen) > tol;
            const bool notMine     = body != baseBody;
            if (twoxx && notNotFound && notMine)
                finding.accessible.append({ nid, st, len });
        }
        if (!finding.accessible.isEmpty())
            result.findings.append(finding);
    }

    return result;
}

} // namespace Nullock::Core::IdorTester

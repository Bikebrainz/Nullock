#include "idor_tester.hpp"
#include "networking.hpp"

namespace Nullock::Core::IdorTester {

// (Pure helpers -- looksLikeIdParam, looksLikeNonIdSegment, isNumeric,
// pathOnly, queryOnly, formatId, neighbors, withMutatedId, buildRequest,
// controlUsable, isAccessible -- live in idor_logic.cpp so the regression test
// can exercise them without the network stack.)

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
        const auto ctrlA = fetch(withMutatedId(req.basePath, loc, formatId(v + 1000000007LL, loc.originalValue)));
        const auto ctrlB = fetch(withMutatedId(req.basePath, loc, formatId(v + 999999937LL, loc.originalValue)));
        const int ctrlLen    = ctrlA.ok ? ctrlA.parsed.body.size() : -1;
        // FAIL CLOSED: if the discriminator request failed we cannot tell a
        // real object from a not-found page, so every 2xx would otherwise be
        // flagged. Skip the location rather than flag everything.
        if (!controlUsable(ctrlLen)) continue;
        const int ctrlJitter = (ctrlA.ok && ctrlB.ok)
                               ? qAbs(ctrlB.parsed.body.size() - ctrlLen) : 0;
        const int tol = idorTolerance(baseJitter, ctrlJitter);  // pure, unit-tested

        Finding finding;
        finding.loc = loc;
        for (const QString &nid : neighbors(loc.originalValue, v, mutationsPerId)) {
            const auto r = fetch(withMutatedId(req.basePath, loc, nid));
            if (!r.ok) continue;
            const int st  = r.parsed.statusCode;
            const QByteArray body = r.parsed.body;
            const int len = body.size();
            // Accessible (enumeration lead) = a 2xx response that is (a) not the
            // not-found template -- its length is meaningfully different from
            // the control -- and (b) not literally your own identical object
            // (an endpoint that ignores the id / serves a static page returns
            // body == baseBody for every neighbor).
            const bool notNotFound = idorDiffersFromNotFound(len, ctrlLen, tol);  // pure, unit-tested
            const bool notMine     = body != baseBody;
            if (isAccessible(st, notNotFound, notMine))
                finding.accessible.append({ nid, st, len });
        }
        if (!finding.accessible.isEmpty())
            result.findings.append(finding);
    }

    return result;
}

} // namespace Nullock::Core::IdorTester

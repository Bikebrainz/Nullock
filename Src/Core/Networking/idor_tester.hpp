#pragma once

// IDOR / BOLA auto-detection. Burp has no native scanner for this -- the
// #1 API vulnerability class (OWASP API #1: Broken Object Level
// Authorization) is left to manual work or extensions. We automate the
// discovery half:
//
//   Given a request that carries a numeric object id (in a path segment
//   like /api/orders/1043 or a param like ?user_id=7), replay it with
//   the SAME session but neighboring ids. If a neighbor returns a valid,
//   *distinct* object (not your own, not the not-found template), the id
//   space is enumerable under your session -- a horizontal IDOR LEAD.
//
// IMPORTANT: a single session can only prove objects are ENUMERABLE, not
// that the access is UNAUTHORIZED -- a public catalog (/product/124) is
// enumerable by design. So a hit here is a lead graded low, not a confirmed
// break; confirmation needs a multi-identity replay (see /api/authz-test),
// which fetches the same object under a second (lower-privilege) identity and
// flags only when access diverges.
//
// Discriminator: we first fetch a wildly-out-of-range id to learn what
// "this object doesn't exist / you can't see it" looks like. A neighbor
// only counts as accessible if its response differs from BOTH your own
// object and that not-found template -- which kills the false positives
// from endpoints that 200 everything or echo a static page. If that
// discriminator request FAILS we cannot tell a real object from a 404, so
// we fail closed and skip the location rather than flag everything.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::IdorTester {

struct IdLocation {
    enum Kind { PathSegment, QueryParam };
    Kind    kind = PathSegment;
    int     segIndex = -1;       // for PathSegment: index into split path
    QString paramName;           // for QueryParam
    QString originalValue;       // the numeric id we found
    QString descriptor;          // human label, e.g. "path[3]" / "param 'id'"
};

struct AccessibleObject {
    QString mutatedId;
    int     status = 0;
    int     length = 0;
};

struct Finding {
    IdLocation loc;
    QList<AccessibleObject> accessible;   // neighboring ids that returned distinct objects
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;                         // path, may carry a query
    QList<QPair<QString, QString>> headers;   // session cookies / auth ride here
};

struct Result {
    QList<Finding> findings;
    int     idLocationsFound = 0;
    int     requestsSent = 0;
    QString error;
};

// Find numeric id locations in the request, mutate each to neighbors, and
// report neighbors that return distinct valid objects (enumeration leads). If
// explicitIdParam is set, only that param/segment is tested. mutationsPerId
// bounds the neighbor count fired per location.
Result test(const Request &req, const QString &explicitIdParam = QString(),
            int mutationsPerId = 6);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// id discovery, mutation, padding, fail-closed control gate, and CR/LF guards
// against Qt6::Core alone.

bool looksLikeIdParam(const QString &name);
bool looksLikeNonIdSegment(const QString &seg, const QString &prev);
bool isNumeric(const QString &s);

QString pathOnly(const QString &basePath);
QString queryOnly(const QString &basePath);

// Format a mutated id, preserving the original's zero-padding width so a
// fixed-width id space (/doc/00042) yields valid padded neighbors, not "43".
QString formatId(qint64 n, const QString &original);

// Candidate neighbor ids for `original` (value v), nearest first, padded to
// match `original`'s width.
QStringList neighbors(const QString &original, qint64 v, int count);

// Rebuild basePath with `loc`'s id replaced by `newId`.
QString withMutatedId(const QString &basePath, const IdLocation &loc, const QString &newId);

// Build the raw request. Returns empty if method/host/path or a carried header
// carries a CR/LF (request-line / header injection guard).
QByteArray buildRequest(const Request &req, const QString &path);

// Fail-closed control gate: was the not-found discriminator usable? If the
// control request failed (len < 0) we cannot distinguish a real object from a
// 404, so the location must be skipped rather than flagging every 2xx.
bool controlUsable(int controlLen);

// A neighbor is an enumeration lead when it is 2xx, distinguishable from the
// not-found template, and not byte-identical to your own baseline object.
bool isAccessible(int status, bool differsFromNotFound, bool differsFromBaseline);

// The length-tolerance calibration + the not-found discriminator (both pure).
// These derive the `differsFromNotFound` bool that isAccessible consumes; they
// were inline in test() and untested, so the threshold that separates "a real
// distinct object" from "just the not-found template" had no regression lock.
//
//  - idorTolerance: how many bytes a neighbor must differ from the not-found
//    control before it counts as distinct. Calibrated as the LARGER of the
//    baseline's and the control's own request-to-request length jitter (dynamic
//    CSRF tokens / timestamps make identical objects differ a little), plus a
//    16-byte floor so a low-jitter endpoint still needs a real difference.
//  - idorDiffersFromNotFound: STRICT '>' so a neighbor exactly `tol` bytes from
//    the control is treated as the not-found template (not a lead) -- fail safe.
int  idorTolerance(int baseJitter, int ctrlJitter);
bool idorDiffersFromNotFound(int len, int ctrlLen, int tol);

} // namespace Nullock::Core::IdorTester

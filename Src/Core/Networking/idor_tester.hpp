#pragma once

// IDOR / BOLA auto-detection. Burp has no native scanner for this -- the
// #1 API vulnerability class (OWASP API #1: Broken Object Level
// Authorization) is left to manual work or extensions. We automate the
// common case:
//
//   Given a request that carries a numeric object id (in a path segment
//   like /api/orders/1043 or a param like ?user_id=7), replay it with
//   the SAME session but neighboring ids. If a neighbor returns a valid,
//   *distinct* object (not your own, not the not-found template), you
//   just read someone else's record -- a horizontal IDOR lead.
//
// Discriminator: we first fetch a wildly-out-of-range id to learn what
// "this object doesn't exist / you can't see it" looks like. A neighbor
// only counts as accessible if its response differs from BOTH your own
// object and that not-found template -- which kills the false positives
// from endpoints that 200 everything or echo a static page.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

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
// report neighbors that return distinct valid objects. If explicitIdParam
// is set, only that param/segment is tested. mutationsPerId bounds the
// neighbor count fired per location.
Result test(const Request &req, const QString &explicitIdParam = QString(),
            int mutationsPerId = 6);

} // namespace Nullock::Core::IdorTester

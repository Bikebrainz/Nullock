#pragma once

// HTTP/3 readiness detection. A server that supports HTTP/3 (QUIC) advertises
// it to HTTP/1.1 and HTTP/2 clients through the Alt-Svc response header
// (RFC 7838), e.g.:
//
//   Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400, h2=":443"
//
// The h3* protocol-ids name the HTTP/3 versions on offer and the authority /
// max-age each is valid for. Knowing a target speaks HTTP/3 matters for an
// engagement: the QUIC path is a distinct attack surface (separate stack,
// often a different edge, sometimes different routing/normalisation than the
// TCP path), and it is increasingly the default once advertised.
//
// This is a passive, read-only discovery probe -- one ordinary GET, then parse
// Alt-Svc. It does NOT speak QUIC (a full HTTP/3 client transport is a separate
// roadmap item that needs a QUIC dependency); it reports advertised readiness.
//
// Note: HTTP/3 can also be advertised via DNS HTTPS/SVCB resource records
// (alpn=h3). Qt's resolver does not expose those record types, so this probe
// covers the Alt-Svc mechanism only; SVCB is a future extension.

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::Http3Detect {

struct AltProtocol {
    QString id;          // protocol-id, e.g. "h3", "h3-29", "h2"
    QString authority;   // the quoted authority, e.g. ":443" or "alt.example:443"
    int     maxAge = -1; // ma= seconds, -1 if absent
    bool    isHttp3 = false;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString path;                               // defaults to "/"
    QString query;                              // optional encoded query
    QList<QPair<QString, QString>> headers;     // carried headers (cookies, auth)
};

struct Result {
    bool        advertisesHttp3 = false;
    QStringList http3Versions;        // the h3* ids, in advertised order
    QList<AltProtocol> protocols;     // every Alt-Svc entry parsed
    QString     altSvcRaw;            // the raw Alt-Svc header(s), joined
    int         baselineStatus = 0;
    QString     error;
};

// Issue one GET and parse Alt-Svc. Sets Result::error (leaving advertisesHttp3
// false) when the request fails. A successful request that simply carries no
// Alt-Svc is a normal negative (advertisesHttp3=false, empty error).
Result detect(const Request &req);

} // namespace Nullock::Core::Http3Detect

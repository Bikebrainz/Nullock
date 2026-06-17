#pragma once

// HTTP method enumeration (read-only). Reads the OPTIONS `Allow` header to see
// which methods the server advertises and flags the dangerous ones -- write
// methods (PUT/DELETE/PATCH), WebDAV (PROPFIND/MKCOL/COPY/MOVE/LOCK), and TRACE.
// TRACE is additionally confirmed with a non-mutating echo probe (Cross-Site
// Tracing). Deliberately does NOT actively PUT/DELETE -- that would modify
// server state; advertised write methods are reported from OPTIONS, and the
// operator can confirm intrusively if authorized.

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::MethodAudit {

struct Finding { QString kind; QString severity; QString detail; };

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QString query;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    int         optionsStatus = 0;
    QStringList allowed;          // methods from the Allow header
    bool        traceEnabled = false;
    QList<Finding> findings;
    QString     error;
};

// Send OPTIONS (+ a TRACE echo probe) and report dangerous advertised methods.
Result audit(const Request &req);

} // namespace Nullock::Core::MethodAudit

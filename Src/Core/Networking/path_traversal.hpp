#pragma once

// Path traversal / local file inclusion (CWE-22: Improper Limitation of a
// Pathname to a Restricted Directory). When a parameter feeds a filesystem
// path, "../" sequences (and their many encodings) escape the intended
// directory and read arbitrary files -- /etc/passwd, app config, source,
// secrets. We confirm by *content signature*: inject a battery of traversal
// encodings aimed at well-known files and flag only when the response carries
// that file's fingerprint (and the baseline did not). No reflection guessing.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::PathTraversal {

struct Hit {
    QString param;       // parameter the payload went into
    QString technique;   // "dotdot", "encoded", "double-encoded", "nested", ...
    QString target;      // "/etc/passwd" | "windows/win.ini"
    QString payload;     // the raw value injected
    QString evidence;    // the signature line that proved it
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;
    QString param;                              // param to test; empty => auto
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    QStringList testedParams;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject traversal payloads into the target parameter(s) and flag any whose
// response contains a known file's content signature. If `param` is empty,
// existing query params are tried (capped), else a small default set.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::PathTraversal

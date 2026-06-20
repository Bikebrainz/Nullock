#pragma once

// Path traversal / local file inclusion (CWE-22: Improper Limitation of a
// Pathname to a Restricted Directory). When a parameter feeds a filesystem
// path, "../" sequences (and their many encodings) escape the intended
// directory and read arbitrary files -- /etc/passwd, app config, source,
// secrets. We confirm by *content signature*: inject a battery of traversal
// encodings aimed at well-known files and flag only when the response carries
// that file's fingerprint (and the baseline did not). A SHAPED/INERT control --
// the same encoding+depth pointing at a guaranteed-nonexistent name -- must NOT
// carry the signature, ruling out a value-keyed error/docs/help template that
// renders the fingerprint for any odd path (no real file read). No reflection
// guessing.
//
// Scope: query-string params only (POST/form-body file selectors are a
// follow-up). The traversal set is ../-family; bare-absolute, NUL-byte, and
// overlong-UTF-8 encodings are a follow-up.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QRegularExpression>
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
    QStringList droppedParams;                  // candidates skipped past the cap
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject traversal payloads into the target parameter(s) and flag any whose
// response contains a known file's content signature (confirmed against a
// shaped/inert control). If `param` is empty, existing query params are tried
// (capped, overflow in droppedParams), else a default set.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// First match of a file-content signature in the body (bounded), or "".
QString matchSig(const QRegularExpression &sig, const QByteArray &body);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::PathTraversal

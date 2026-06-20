#pragma once

// OS command injection (CWE-78: Improper Neutralization of Special Elements
// used in an OS Command). When user input reaches a shell -- system(),
// popen(), backticks, a templated `sh -c` -- an attacker chains their own
// command and it's RCE. We confirm it the unambiguous way: chain a command
// that prints <pre>$(echo $((a*b)))<suf> with random sentinels and random
// operands. The bare product appears between the sentinels ONLY if a COMMAND
// actually executed (the $() command substitution ran `echo`) -- not merely if
// $(()) arithmetic was expanded -- so a restricted arithmetic-only evaluator
// cannot be mistaken for RCE.
//
// Scope: confirmation is IN-BAND (the executed output must reflect in the HTTP
// response) and POSIX-shell only (cmd.exe `set /a` coverage is a follow-up);
// payloads ride the QUERY STRING (POST-body params are a follow-up). A clean
// result does not rule out blind/OOB command injection -- pair with the
// OAST blast tool for that.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::CmdInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString technique;   // "semicolon", "pipe", "subshell", "backtick", ...
    QString payload;     // the injected value (decoded)
    QString evidence;    // "command executed: $(echo $((a*b))) -> <product>"
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
    quint32 seedA = 0;                          // operands; 0 => randomize
    quint32 seedB = 0;
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

// Inject command-chaining payloads into the target parameter(s) and flag any
// whose response proves shell execution (the command-substitution product
// between our sentinels). If `param` is empty, existing query params are tried
// (capped, overflow in droppedParams), else a small default set.
Result test(const Request &req);

QStringList defaultParams();

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// The command-substitution proof token "<pre>$(echo $((a*b)))<suf>".
QString commandProof(const QString &pre, const QString &suf, quint64 a, quint64 b);
// All sentinel-bracketed regions (pre...suf, <= 64 chars) in the body.
QStringList renderedRegions(const QString &body, const QString &pre, const QString &suf);
// Build the raw request, CR/LF-guarding method/host/path (returns {} if tainted)
// and dropping any CR/LF-bearing header.
QByteArray buildRequest(const Request &req, const QString &query);

} // namespace Nullock::Core::CmdInjection

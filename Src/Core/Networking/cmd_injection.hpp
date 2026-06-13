#pragma once

// OS command injection (CWE-78: Improper Neutralization of Special Elements
// used in an OS Command). When user input reaches a shell -- system(),
// popen(), backticks, a templated `sh -c` -- an attacker chains their own
// command and it's RCE. We confirm it without timing or guesswork: inject a
// command separator plus `echo <pre>$((a*b))<suf>` with random sentinels and
// random operands; the shell evaluates the arithmetic ONLY if it actually
// ran the command, so a response carrying <pre><product><suf> -- the computed
// value bracketed by our sentinels, not the literal expression -- is proof.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CmdInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString technique;   // "semicolon", "pipe", "subshell", "backtick", ...
    QString payload;     // the injected value (decoded)
    QString evidence;    // "executed $((a*b)) -> <product>"
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
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject command-chaining payloads into the target parameter(s) and flag any
// whose response proves shell execution (the evaluated arithmetic between our
// sentinels). If `param` is empty, existing query params are tried (capped),
// else a small default set.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::CmdInjection

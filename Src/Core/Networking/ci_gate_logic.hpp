#pragma once

// CI security gate (an "above Burp" primitive Burp only ships in Enterprise):
// given the current findings and a fail-on severity threshold, decide whether a
// CI pipeline should PASS or FAIL, and hand back a process exit code. A CI job
// runs Nullock headless, drives its scans over the API, then reads GET
// /api/gate?fail-on=high and exits with the returned code.
//
// PURE: severities in, a verdict out. No I/O -- links against Qt6::Core alone.
//
// SAFETY / robustness: an unknown or empty threshold defaults to "high" (a sane
// CI default, never "never fail"), and "none"/"off" is honoured as an explicit
// "never fail" so a pipeline can run the scan for reporting without gating.
// Blank finding severities coalesce to "info" (matching the reporting endpoints)
// so a malformed finding can't sneak past or trip the gate unexpectedly.

#include <QList>
#include <QMap>
#include <QString>

namespace Nullock::Core::CiGate {

// A threshold rank no real finding can reach -- used for "none"/"off".
constexpr int kNeverFail = 1000;

// Exit codes (trivy/grype-style): 0 clean, 1 gate tripped, 2 bad usage (the
// caller's concern -- a malformed URL never reaches this module), 3 the scan
// could not run at all.
constexpr int kExitPass        = 0;
constexpr int kExitFail        = 1;
constexpr int kExitBadUrl      = 2;   // set by the caller; listed here so the
                                      // whole contract lives in one place
constexpr int kExitUnreachable = 3;

// Rank a severity name. Higher = worse. Blank/unknown -> 0 (info).
int severityRank(const QString &sev);

// Canonicalise a severity name to one of critical/high/medium/low/info.
QString canonicalSeverity(const QString &sev);

// Parse a fail-on threshold. "none"/"off"/"never" -> kNeverFail (never trips).
// critical/high/medium/low/info -> that rank. Unknown/empty -> the "high" rank.
int thresholdRank(const QString &failOn);

// The canonical threshold NAME for a fail-on string (for echoing back). "none"
// stays "none"; unknown/empty -> "high".
QString thresholdName(const QString &failOn);

struct GateResult {
    bool             pass = true;
    int              exitCode = kExitPass;
    QString          threshold;          // canonical threshold name
    int              thresholdRank = 0;
    int              offendingCount = 0; // findings at/above the threshold
    int              total = 0;
    QMap<QString,int> bySeverity;        // full breakdown (canonical keys)
    bool             reachable = true;   // false => the scan never reached the target
    QString          error;              // transport error, only when !reachable
};

// Evaluate the gate over a list of finding severities.
GateResult evaluate(const QList<QString> &severities, const QString &failOn);

// Verdict for a run whose scan NEVER REACHED THE TARGET.
//
// This exists because "clean" and "never scanned" are byte-identical to
// evaluate(): every tester derives its finding count from a hit/found container,
// so a refused connection, a typo'd hostname, a down staging env or an
// egress-blocked runner all yield an EMPTY severity list -- and an empty list is
// a pass at every threshold, including the strictest. The gate then reported
// "findings: 0 ... RESULT: PASS (exit 0)" having probed nothing. A gate that
// cannot fail closed on its OWN failure is worse than no gate, so the caller
// must preflight the target and route that case here.
//
// "none"/"off" is still honoured: the operator explicitly asked NOT to gate, so
// the exit code stays kExitPass for them. `reachable` is false either way, so
// every caller can still report WHY nothing was scanned.
GateResult unreachable(const QString &failOn, const QString &error);

} // namespace Nullock::Core::CiGate

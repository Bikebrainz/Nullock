#pragma once

// Server-side prototype pollution (CWE-1321: Improperly Controlled
// Modification of Object Prototype Attributes). A Node/JavaScript back-end
// that deep-merges attacker-controlled JSON into an object without rejecting
// the special keys __proto__ / constructor / prototype lets an attacker write
// onto Object.prototype -- a process-global change that every other object
// then inherits. Depending on the gadget reachable in the running code this
// escalates to privilege bypass, reflected XSS, or RCE.
//
// We confirm it the way PortSwigger's research does, using the most BENIGN
// gadget available: Express reads its `json spaces` setting through the
// prototype chain when serialising res.json(). Polluting
// Object.prototype["json spaces"] therefore reformats every subsequent JSON
// response -- a harmless, formatting-only side effect with NO data impact.
//
// Detection is a four-step causal proof, not a single guess:
//   1. baseline  -- the JSON observation endpoint must currently be COMPACT;
//   2. pollute   -- POST {"__proto__":{"json spaces":7}} to the merge endpoint;
//   3. observe   -- the SAME endpoint now indents top-level keys by EXACTLY 7
//                   spaces (a distinctive, non-default value we chose, so the
//                   reformat is causally ours and not a coincidence);
//   4. cleanup   -- POST {"__proto__":{"json spaces":0}} and confirm it goes
//                   compact again, both reverting our change and proving the
//                   formatting tracked the pollution we controlled.
// Only when all four hold do we report. This mutates one harmless server-side
// setting (response indentation), so the probe is scope-gated and opt-in.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::ProtoPollution {

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    // GET endpoint that returns a JSON object -- the observation point whose
    // formatting we watch. Defaults to "/" if empty.
    QString jsonPath;
    QString jsonQuery;          // optional existing query (encoded), may be empty
    // POST endpoint that deep-merges the JSON request body. Defaults to
    // jsonPath when empty (many apps merge body on the same route).
    QString pollutePath;
    QList<QPair<QString, QString>> headers;   // carried headers (cookies, auth)
};

struct Result {
    bool    vulnerable = false;          // all four proof steps held
    bool    observedJson = false;        // the observation endpoint returned JSON
    bool    baselineCompact = false;     // baseline had no 7-space indentation
    bool    indentedAfterPollute = false;
    bool    revertedAfterCleanup = false;
    QString gadget;                      // "json spaces" (the gadget we used)
    QString polluteKey;                  // "__proto__" | "constructor.prototype" -- the key that worked
    int     polluteStatus = 0;           // status of the last pollute POST (for the 4xx hint)
    QString evidence;                    // short human-readable note
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Run the json-spaces causal proof, trying both the __proto__ and
// constructor.prototype write keys (a merge that blocks __proto__ may still be
// pollutable via the constructor walk). Sets Result::error (and leaves
// vulnerable=false) when the observation endpoint isn't usable JSON, returns a
// compressed body (on baseline OR re-observe), is already indented (gadget
// inconclusive), or a request fails -- and, importantly, when pollution
// succeeded but the revert could not be confirmed after retries, so callers can
// treat ok=false as "target may be left mutated" rather than silently trusting
// a clean result.
Result test(const Request &req);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// build / detection logic against Qt6::Core alone.

QString randTok();
QString withBuster(const QString &query);
bool    looksJsonObject(const QByteArray &body);
// Is the TOP-LEVEL object indented by EXACTLY n spaces ({ newline n-spaces ")?
bool    indentedByN(const QByteArray &body, int n);
// A non-identity Content-Encoding whose body we cannot read as text.
bool    encodingUnreadable(const QString &contentEncoding);
QByteArray buildGet(const Request &req, const QString &path, const QString &query);
QByteArray buildPollute(const Request &req, const QString &path, const QByteArray &body);

} // namespace Nullock::Core::ProtoPollution

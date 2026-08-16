#pragma once

// Pure session-rule logic, split out of the SessionRules QObject so it can be
// unit-tested against Qt6::Core alone (SessionRules pulls proxy_server.hpp). These
// are the soundness/safety-critical primitives: extraction parsing, {{var}}
// substitution, and the sanitizers that stop a target-controlled extracted value
// from injecting headers/cookies/JSON into the scanner's OWN outgoing request.

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QPair>
#include <QRegularExpression>
#include <QString>

namespace Nullock::Core::SessionRulesLogic {

// Glob ("*"=any, "?"=one) to an anchored, case-insensitive regex.
QRegularExpression globToRx(const QString &glob);

// First header value by case-insensitive name.
QString findHeader(const QList<QPair<QString, QString>> &headers, const QString &name);

// The value of cookie `name` from a (Set-)Cookie header. ONLY the FIRST segment
// is the name=value cookie pair; the rest are attributes (Path/Domain/Expires/
// ...) and must never be returned as a cookie value.
QString findCookieValue(const QString &raw, const QString &name);

// Dot-path lookup into a JSON body. A numeric leaf keeps its exact integer text
// (no scientific-notation/precision loss from a bare toDouble). "" on miss.
QString jsonPathGet(const QByteArray &body, const QString &path);

// {{var}} substitution; unknown vars stay literal; single-pass (a substituted
// value is NOT re-scanned -- response-derived data must not pull in other vars).
QString substitute(const QString &templ, const QHash<QString, QString> &vars);

// The first capture group that actually PARTICIPATED (non-null), else the whole
// match -- so an alternation/optional group 1 that didn't match doesn't drop a
// value present in a later group.
QString firstCapture(const QRegularExpressionMatch &m);

// Strip CR/LF (and other control chars) from a value bound for a request HEADER
// -- a target-controlled value with CRLF would otherwise split the header line /
// smuggle a request onto the wire (CWE-93/CWE-113).
QString sanitizeHeaderValue(const QString &v);

// Header sanitize + drop ';' -- a Cookie value with ';' would forge extra cookie
// pairs in the outgoing Cookie header.
QString sanitizeCookieValue(const QString &v);

// JSON-string-escape the inner text of a value (no surrounding quotes) so a
// {{var}} substituted into a JSON body string can't break/forge the JSON.
QString jsonEscapeInner(const QString &v);

// The path component with any "?query" stripped -- a pathGlob is matched against
// the path, not the query (else an exact glob never matches a query-bearing req).
QString stripQuery(const QString &path);

// --- Tool scoping (Burp's "Tools scope" on a session-handling rule) ----------
// Which Nullock tools a session rule applies to, as a bitmask on SessionRule.tools.
// Historically rules ran only in the proxy pipeline; scoping lets a rule also (or
// instead) run when Repeater / Intruder / the scanner send a request.
enum SessionTool {
    ToolProxy    = 1,
    ToolRepeater = 2,
    ToolIntruder = 4,
    ToolScanner  = 8,
};
inline constexpr int kAllSessionTools = ToolProxy | ToolRepeater | ToolIntruder | ToolScanner;

// Does a rule with this tools bitmask apply to `tool`? An UNSET (0) bitmask means
// "all tools", so a rule authored before scoping existed still applies everywhere
// (backward-compatible); otherwise the tool's bit must be set.
bool ruleAppliesToTool(int toolsMask, int tool);

} // namespace Nullock::Core::SessionRulesLogic

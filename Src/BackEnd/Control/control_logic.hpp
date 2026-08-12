#pragma once

#include <QJsonArray>
#include <QString>

// Pure pre-dispatch security-gate logic for ControlServer::handle(), split out
// of control_server.cpp so a unit test can link it against Qt6::Core alone (the
// rest of control_server.cpp pulls Network/Sql/Qml + the whole scanner suite).
//
// These three predicates ARE the control server's attacker-facing security
// boundary: the server exposes PRIVATE state (proxy history, captured creds) and
// is defended by same-origin policy + a DNS-rebinding Host check + a CSRF
// Origin/token check. Isolating + unit-testing them locks the boundary against
// regressions.
namespace Nullock::Control::ControlLogic {

// DNS-rebinding Host allowlist. Returns true if the request should pass the Host
// check. An EMPTY Host is allowed by design: the rebinding threat is a browser
// confused-deputy, and a browser ALWAYS sends Host (set from the URL authority),
// so a rebinded page carries `Host: evil.com` and is rejected; a non-browser
// client that omits Host is not a confused deputy and gains nothing it couldn't
// get by hitting the port directly. A non-empty Host must be a loopback form
// (with or without our port), compared case-insensitively.
bool isHostAllowed(const QString &hostHdr, quint16 port);

// Known-HTTP-verb allowlist (closes the any-method -> mutating-endpoint vector).
bool isMethodAllowed(const QString &method);

// Safe/read method (GET/HEAD/OPTIONS) -- needs no CSRF check.
bool isReadMethod(const QString &method);

// CSRF decision. A read method is always authorized (no state change). A WRITE
// (non-read) method is authorized iff the Origin EXACTLY matches our http
// loopback origin OR the X-Nullock-UI token is set ("1"/"true") -- a token a
// cross-origin browser page cannot add without a CORS preflight we never grant.
bool isRequestAuthorized(const QString &method, const QString &origin,
                         const QString &nullockHdr, quint16 port);

// --- Bearer-token API auth (for off-loopback / remote-drive) --------------
// When the operator binds the control server off-loopback (CI, a shared scan
// host), same-origin policy and the CSRF Origin check are meaningless -- any
// page the attacker loads from the server IS same-origin. A bearer token is
// then the real boundary: an API client (curl/CI) presents it, and a hostile
// browser page cannot add an Authorization header cross-origin without a CORS
// preflight the server never grants.

// Extract the token from an Authorization header VALUE ("Bearer <token>").
// Case-insensitive scheme, tolerant of surrounding whitespace. Returns the
// token, or an empty string if the value isn't a well-formed Bearer credential.
QString bearerToken(const QString &authHeaderValue);

// Constant-time equality over the UTF-8 bytes of a and b: runs in time
// proportional to the longer input regardless of where they first differ, so a
// network attacker cannot recover the configured token byte-by-byte via timing.
bool constantTimeEquals(const QString &a, const QString &b);

// Full token decision: true iff configuredToken is NON-EMPTY and the
// Authorization header carries a Bearer token that constant-time-equals it. An
// empty configuredToken (auth disabled) returns FALSE -- callers must not treat
// "no token configured" as authorized; that case is gated separately by whether
// the bind is loopback.
bool isTokenAuthorized(const QString &authHeaderValue, const QString &configuredToken);

// --- Markdown report-export escaping -------------------------------------
// Finding fields (kind/host/summary/url/evidence) can contain ATTACKER-controlled
// bytes (e.g. an OAST callback's path/User-Agent, or a reflected payload echoed
// into a scanner finding's evidence). The JSON/SARIF/HTML report sinks are
// already escaped by their encoders, but the Markdown export embeds these fields
// raw, so a backtick/newline/[..](..) could forge report structure (links,
// images, broken code spans, injected list items). These two helpers neutralize
// that at the sink, covering ALL findings regardless of source.

// Safe to drop inside a Markdown INLINE CODE SPAN (`...`). Backticks can't be
// backslash-escaped inside a span, so they are removed; CR/LF/tab/other control
// chars (which would break the span / line) collapse to a single space.
QString mdCodeSpanSafe(const QString &s);

// Safe to drop into Markdown INLINE PLAIN TEXT. CR/LF/control chars collapse to a
// space (so content can never start a new line / list item / heading), and the
// inline metacharacters (\ ` * _ [ ] ( ) < > | ! #) are backslash-escaped so a
// payload can't inject a link/image/emphasis/HTML.
QString mdTextSafe(const QString &s);

// Safe to drop into an XML ATTRIBUTE VALUE (the nmap-XML / report exports embed
// ATTACKER-controlled scan data -- host, service name, banner -- as attribute
// values). Control chars (incl. CR/LF/tab) collapse to a space so they cannot
// break attribute framing or be rejected by a downstream XML parser, and the
// five predefined entities (& < > " ') are escaped so a payload can't close the
// attribute / inject markup. Returns a QString; callers serializing to a byte
// stream apply .toUtf8().
QString xmlAttrEscape(const QString &s);

// Render a findings array (the /api/report/json finding shape:
// kind/host/url/summary/severity/cwe/owasp/cvssScore/fixSummary/confidence)
// as a well-formed Burp-style XML issue report. Every attribute and element
// value is xmlAttrEscape'd, so hostile scan data (a host/url/summary
// containing </issue>, <, &, quotes, or control bytes) cannot break the
// document framing or inject markup. Pure + deterministic (the timestamp is
// passed in, not read), so it is unit-tested directly.
QString findingsJsonToXml(const QJsonArray &findings, const QString &project,
                          const QString &generatedIso);

// --- Finding severity mapping (report export) ----------------------------
// Rank a severity string (critical>high>medium>low>info>unknown=0) so the worst
// of several probe severities can be selected deterministically.
int severityRank(const QString &sev);
// SARIF result level for a finding severity: "error" for critical/high (so a CI
// gate failing on level=="error" catches the MOST severe issues -- a critical
// must NOT map to "warning"), "note" for low/info, "warning" for medium/unknown.
QString sarifLevelForSeverity(const QString &sev);

// --- Outbound request-builder CR/LF guard --------------------------------
// A request-line / header component (path, query, param name) built from a
// parsed URL or operator JSON and concatenated RAW into outbound HTTP request
// bytes must not carry CR, LF, or NUL. QUrl::path() DECODES percent-encoded
// bytes (incl. %0d%0a -> raw CR/LF on Qt 6.7), so a crafted url could splice a
// forged header / smuggled second request into every probe a handler builds.
// Returns true if s contains any such byte, so the caller can reject it --
// mirroring the reject-on-CRLF convention the Core/Networking buildGet builders
// already follow.
bool hasRequestSmugglingChars(const QString &s);

// --- /api/search ReDoS pattern pre-screen --------------------------------
// /api/search compiles a USER-SUPPLIED regex and runs it over captured proxy
// history. PCRE2 (Qt's backend) caps any single match via its internal
// match_limit (~tens of ms), so a hostile pattern can't hang forever, but it
// CAN burn that budget on every one of up to ~1000 bodies -> a multi-second
// main-thread freeze (the endpoint is cross-origin reachable via a simple GET).
// A wall-clock budget at the call site bounds the aggregate; this predicate is
// the cheap FAST-PATH that rejects the two obvious catastrophic shapes up front:
//   (1) a nested unbounded quantifier -- the textbook (a+)+ / (a*)* / (a{2,})+;
//   (2) alternation with two IDENTICAL adjacent branches -- (a|a)+, (\d|\d)+,
//       ([ab]|[ab])+, (a|a|a)+ -- which bypass shape (1). DISJOINT alternations
//       like (foo|bar)+ or (a|b)+ are linear and are NOT flagged.
// Returns true if the pattern matches a known-catastrophic shape (caller 400s).
// Heuristic by nature (alternation-overlap detection is undecidable to do
// precisely without over-rejecting), so it is a fast-path, NOT the whole defence.
bool looksLikeCatastrophicRegex(const QString &pattern);

// --- /api/search scan ordering + completeness ----------------------------
// ProxyModel appends, so row 0 is the OLDEST capture and row (n-1) is the
// NEWEST. A time-bounded body scan must therefore start at the newest row so
// that on a busy engagement (the in-memory window holds up to 10'000 rows) the
// results a tester actually cares about -- the request they just sent -- are
// the ones covered before the wall-clock budget runs out. This maps the i-th
// scan iteration (0-based) to a model row, newest-first: i=0 -> n-1, i=1 -> n-2.
// Precondition 0 <= i < n; out-of-range i clamps into [0, n-1] rather than
// returning a negative index a caller might feed straight to model->index().
int searchRowForIteration(int n, int i);

// A body scan is COMPLETE only if it examined every row. `scanned` is the count
// of rows actually inspected before the loop stopped (wall-clock budget or hit
// limit); when it is short of `total` the endpoint MUST report truncated:true,
// because a search tool that silently omits recent traffic and answers a
// confident "0" is worse than one that admits it did not finish. This is the
// single source of that truth -- the old fixed 500-row cap set truncated only
// on the wall-clock path, so a >500-capture history returned a silent lie.
bool searchTruncated(int scanned, int total);

// --- Filesystem path confinement -----------------------------------------
// Join an attacker-influenced relative path `rel` onto a trusted base `dir`,
// confining the result to `dir`. Strips leading '/' and '\\' (so an "absolute"
// request cannot escape) and REJECTS (returns an empty string) any `rel` that
// contains the substring ".." -- the only up-traversal primitive. Returns
// dir + "/" + rel when safe; the caller MUST treat the empty return as
// "not found"/skip. `rel` must already be URL-DECODED (QUrl::path() decodes
// %2e%2e -> ".." before this runs, so encoded traversal is caught). This is the
// SINGLE confinement guard every attacker-path file op in the control server
// routes through -- the static file server AND the project-template loader.
QString safeJoin(const QString &dir, const QString &rel);

} // namespace Nullock::Control::ControlLogic

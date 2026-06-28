#pragma once

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

} // namespace Nullock::Control::ControlLogic

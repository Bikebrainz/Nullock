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

} // namespace Nullock::Control::ControlLogic

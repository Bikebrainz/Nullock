#pragma once

// Request / Response Inspector (Burp-parity workflow) -- a structured, at-a-
// glance view of a raw HTTP message: the request line / status, headers,
// cookies, query + body parameters, content-type, and any JWTs found in a
// header or cookie (decoded header + payload). Burp puts this behind its
// Inspector panel; Nullock exposes it over the API so any client can render it.
//
// PURE: raw bytes in, a QJsonObject out. Qt6::Core only, no network. Default-
// safe: a malformed message yields a best-effort partial object, never a crash.
// Bounded: only the first kMaxInput bytes are parsed so a huge body can't stall.

#include <QByteArray>
#include <QJsonObject>

namespace Nullock::Core::Inspector {

// Cap on how much of a message we parse.
constexpr int kMaxInput = 2 * 1024 * 1024;   // 2 MiB
// Cap on the body preview returned (the full body isn't echoed back).
constexpr int kBodyPreview = 8 * 1024;

// Parse a raw HTTP/1.x REQUEST. Shape:
//   { method, target, path, version, query, queryParams:[{name,value}],
//     headers:[{name,value}], cookies:[{name,value}], contentType,
//     bodyKind: "form"|"json"|"other"|"", bodyParams:[{name,value}],
//     bodySize, jwts:[{source, where, alg, typ, header, payload}] }
QJsonObject inspectRequest(const QByteArray &raw);

// Parse a raw HTTP/1.x RESPONSE. Shape:
//   { version, status, reason, headers:[{name,value}], setCookies:[{...}],
//     contentType, bodySize, bodyPreview, jwts:[...] }
QJsonObject inspectResponse(const QByteArray &raw);

} // namespace Nullock::Core::Inspector

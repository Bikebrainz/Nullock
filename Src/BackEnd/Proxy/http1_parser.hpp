#pragma once

// HTTP/1.x parsing helpers extracted from proxy_server.cpp so they
// can be reached from the fuzz harness + future test suites without
// dragging in the whole Connection class. Definitions live in
// proxy_server.cpp -- this header is just the public surface.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Proxy {

// Split a CRLF-delimited header block into (name, value) pairs.
// Skips the first line (assumed to be the request/status line).
QList<QPair<QString, QString>> parseHeaders(const QByteArray &headerBlock);

// RFC 7230 §3.3.3 / RFC 9112 §6.3: refuse messages that mix
// Content-Length and Transfer-Encoding, or carry duplicate /
// conflicting Content-Length values. Returns true if the framing
// is unambiguous and safe to relay.
bool isFramingSafe(const QList<QPair<QString, QString>> &headers);

} // namespace Nullock::Proxy

#pragma once

// Pure translation logic for the SERVER side of h2 (Phase 3: terminating a
// browser's HTTP/2 and bridging it to the upstream). Split out of the socket
// code so it links against Qt6::Core alone and is fully unit-testable: turning a
// browser stream's h2 request headers into request fields, and an h1-shaped
// response back into h2 response headers. No nghttp2, no sockets, no
// proxy_server.hpp -- it works on neutral name/value lists.

#include "h2_client_logic.hpp"   // reuse HeaderNV + isHopByHopHeader

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Proxy::H2ServerLogic {

using Nullock::Proxy::H2ClientLogic::HeaderNV;

// The request fields pulled out of a browser stream's h2 headers.
struct H2ReqFields {
    QString method;      // from :method
    QString scheme;      // from :scheme (https for our MITM)
    QString authority;   // from :authority (the Host)
    QString path;        // from :path
    QList<QPair<QString, QString>> headers;   // regular (non-pseudo) headers
    bool    valid = false;   // true once :method and :path are both present
};

// Split a browser stream's received h2 headers into pseudo-headers (:method,
// :scheme, :authority, :path) + regular headers. Pseudo-headers are consumed;
// regular headers are kept as-is (nghttp2 already lowercased their names).
H2ReqFields parseRequestHeaders(const QList<QPair<QString, QString>> &h2headers);

// Build the h2 response header list from an h1-shaped status + headers: ":status"
// first (required), then the response headers with the h2-forbidden connection-
// control headers (connection / transfer-encoding / keep-alive / upgrade /
// proxy-connection) stripped and every name lowercased. A header with an empty
// name is skipped.
QList<HeaderNV> responseHeaders(int status,
                                const QList<QPair<QString, QString>> &headers);

} // namespace Nullock::Proxy::H2ServerLogic

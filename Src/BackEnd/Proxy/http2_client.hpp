#pragma once

#include "proxy_server.hpp"

#include <QByteArray>
#include <QObject>
#include <QString>

class QSslSocket;

namespace Nullock::Proxy {

// Synchronous one-shot HTTP/2 client. Speaks h2 over an already-established
// TLS connection whose ALPN was negotiated to "h2". Translates the response
// back into our HttpResponse so the rest of the proxy machinery can treat
// it identically to an HTTP/1.1 reply.
//
// Backed by libnghttp2 (vcpkg). We do all the wire/framing through nghttp2
// and only feed bytes in and out via the QSslSocket; this keeps us out of
// the HPACK + frame-encoding business entirely.
class H2Client {
public:
    struct Result {
        bool                                ok = false;
        QString                             errorMessage;
        Nullock::Proxy::HttpResponse        response;
    };

    // Send one request and read the full response. The socket must already
    // be encrypted with ALPN == "h2". Connection is left in a usable state
    // but we don't currently re-use it — caller closes after.
    Result sendRequest(QSslSocket *sock, const Nullock::Proxy::HttpRequest &req);
};

} // namespace Nullock::Proxy

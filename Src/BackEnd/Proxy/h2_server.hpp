#pragma once

#include "proxy_server.hpp"

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

#include <functional>

class QSslSocket;

namespace Nullock::Proxy {

// H2Terminator (Phase 3): terminates a BROWSER's HTTP/2 inside a MITM tunnel.
// The browser socket must already be TLS-encrypted with ALPN negotiated to "h2".
// It runs a server-role nghttp2 session, assembles each browser request stream,
// hands it to the proxy-provided `upstream` callback to fulfill, and submits the
// response back on that stream. Requests are processed sequentially (one upstream
// round-trip at a time) -- the browser leg is real multiplexed h2; true
// concurrent upstream fan-out is a later refinement.
//
// This is OFF by default (gated behind --h2-termination) because advertising h2
// to the browser without a working terminator would break every h2 client.
class H2Terminator {
public:
    // The result of trying to fulfill one browser request upstream.
    //   Ok           -> `out` holds the response; send it back on the stream.
    //   RejectStream -> fail just THIS stream (RST); the tunnel stays up.
    //   TunnelDead   -> the upstream connection itself died; tear the whole
    //                   browser tunnel down so it reconnects with a fresh session
    //                   (a per-stream RST would storm every future request).
    enum class UpstreamOutcome { Ok, RejectStream, TunnelDead };

    // Fulfill one browser request. `h2headers` are the received h2 headers
    // (pseudo + regular), `body` the request body. On Ok, fill `out`. The proxy
    // does the history/rules/extension/intercept work + the actual upstream send.
    using UpstreamFn = std::function<UpstreamOutcome(
        const QList<QPair<QString, QString>> &h2headers,
        const QByteArray &body,
        Nullock::Proxy::HttpResponse &out)>;

    // Drive the termination loop until the browser closes or a fatal occurs.
    // connName is host:port for the event log.
    void run(QSslSocket *browser, const QString &connName, const UpstreamFn &upstream);
};

} // namespace Nullock::Proxy

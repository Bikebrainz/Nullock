#pragma once

#include "proxy_server.hpp"

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>

#include <memory>

class QSslSocket;

namespace Nullock::Proxy {

// Synchronous HTTP/2 client. Speaks h2 over an already-established TLS
// connection whose ALPN was negotiated to "h2". Translates each response back
// into our HttpResponse so the rest of the proxy machinery can treat it
// identically to an HTTP/1.1 reply.
//
// Backed by libnghttp2 (vcpkg). We do all the wire/framing through nghttp2 and
// only feed bytes in and out via the QSslSocket; this keeps us out of the
// HPACK + frame-encoding business entirely.
//
// A single call opens N concurrent streams over ONE nghttp2 session and one
// pump loop, so requests are genuinely multiplexed on the wire (interleaved
// HEADERS/DATA) rather than serialized. Local exhaustion caps bound the stream
// count and the per-stream response body regardless of what the peer advertises.
class H2Client {
public:
    struct Result {
        bool                                ok = false;
        QString                             errorMessage;
        Nullock::Proxy::HttpResponse        response;
        // True only for a genuine connection-level failure (can't create/keep an
        // h2 session), NOT a per-stream error / truncation / timeout. Lets the
        // proxy decide whether an origin is really h2-incompatible before it
        // permanently bypasses MITM for that host.
        bool                                connectionFailed = false;
    };

    // ctor + dtor are out-of-line so the unique_ptr<Session> (incomplete here)
    // deleter is only instantiated in the .cpp where Session is complete.
    H2Client();
    ~H2Client();
    H2Client(const H2Client &) = delete;
    H2Client &operator=(const H2Client &) = delete;

    // Send one request and read the full response. The socket must already be
    // encrypted with ALPN == "h2". Thin wrapper over sendConcurrent (one-shot;
    // creates + tears down its own session).
    Result sendRequest(QSslSocket *sock, const Nullock::Proxy::HttpRequest &req);

    // Send N requests concurrently over one h2 session and return one Result
    // per request, in the SAME order as `reqs`. All streams are submitted up
    // front (subject to the local concurrency cap) and driven by a single pump
    // loop, so the origin can interleave their responses. A connection-level
    // failure fails every outstanding request; a per-stream error (RST, body
    // over budget) fails only that one. Creates + tears down its own session.
    QList<Result> sendConcurrent(QSslSocket *sock,
                                 const QList<Nullock::Proxy::HttpRequest> &reqs);

    // Persistent-session send (Phase 2). REUSES one nghttp2 session across calls
    // bound to `sock`, so sequential requests on a kept-alive tunnel share the
    // upstream h2 connection (no per-request TCP+TLS+h2 handshake). The session
    // is opened lazily on the first call and torn down by the destructor (or when
    // `sock` changes). Once a connection-level failure occurs the session is
    // marked dead: this and every later send() returns ok=false and the caller
    // should stop reusing this H2Client.
    Result send(QSslSocket *sock, const Nullock::Proxy::HttpRequest &req);

    // False until send() has opened a session, and false again once it died.
    bool alive() const;

private:
    struct Session;                       // persistent per-tunnel session (pImpl)
    std::unique_ptr<Session> m_sess;
};

} // namespace Nullock::Proxy

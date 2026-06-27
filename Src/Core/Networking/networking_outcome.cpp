// Pure transport-outcome classifier for HttpClient::send, split out of
// networking.cpp so a unit test can link it against Qt6::Network alone (no
// Proxy / HttpClient / socket I/O) and assert every SocketOutcome -- including
// Timeout, which is impractical to exercise live at the 15s read timeout.
// Mirrors the established sibling pattern (smuggling_logic.cpp, port_logic.cpp).

#include "socket_outcome.hpp"

namespace Nullock::Core {

SocketOutcome classifySocketOutcome(QAbstractSocket::SocketError err,
                                    QAbstractSocket::SocketState state) {
    switch (err) {
    // The peer dropped an ESTABLISHED connection mid-exchange. A hold-then-RST
    // WAF/middlebox that buffers then resets a quarantined probe surfaces here.
    case QAbstractSocket::RemoteHostClosedError:
        return SocketOutcome::Reset;

    // The connection never came up at all.
    case QAbstractSocket::ConnectionRefusedError:
    case QAbstractSocket::HostNotFoundError:
    case QAbstractSocket::SocketAccessError:
    case QAbstractSocket::ProxyConnectionRefusedError:
    case QAbstractSocket::ProxyNotFoundError:
    case QAbstractSocket::SslHandshakeFailedError:
        return SocketOutcome::ConnectError;

    // The read expired with no bytes -- the genuine desync shape, but ONLY if
    // the connection is still up. Some stacks surface a peer RST as a timeout-
    // flavoured error, so the state check below disambiguates: a socket that is
    // no longer connected timed out because it was reset, not because it was
    // held open and silent.
    case QAbstractSocket::SocketTimeoutError:
        return state == QAbstractSocket::ConnectedState
                   ? SocketOutcome::Timeout
                   : SocketOutcome::Reset;

    default:
        break;
    }

    // No decisive error code. Fall back to STATE: a still-connected socket that
    // failed to yield a response block went silent on us (Timeout); otherwise
    // the connection went away (Reset).
    return state == QAbstractSocket::ConnectedState ? SocketOutcome::Timeout
                                                    : SocketOutcome::Reset;
}

} // namespace Nullock::Core

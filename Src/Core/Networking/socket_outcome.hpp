#pragma once

#include <QAbstractSocket>

namespace Nullock::Core {

// How a one-shot HTTP send's TRANSPORT leg ended when we could NOT obtain a
// complete, parseable response. Lets a caller tell apart failure shapes that
// look identical on a stopwatch but mean different things:
//
//   Timeout      -- the socket stayed OPEN and went silent; our read of the
//                   response expired (waitForReadyRead timed out) with the
//                   connection still up. This is the genuine request-smuggling
//                   desync shape: a vulnerable back-end blocks on its OWN read
//                   of body bytes the front-end never forwarded.
//   Reset        -- the peer DROPPED an established connection (RST / close).
//                   A hold-then-RST WAF/middlebox that BUFFERS a malformed
//                   probe, quarantines it for several seconds, then RSTs or
//                   500s lands here. It produces the same DELAY as a desync but
//                   must NOT be graded as one (the smuggling probe's stated
//                   conservative stance: a genuine block keeps the socket open
//                   and silent; a quarantine ends in an error).
//   ConnectError -- the connection never established (refused / DNS / TLS).
//   Ok           -- no transport anomaly to report: either the send succeeded,
//                   or it failed for a non-transport reason (e.g. a malformed
//                   status line) where the bytes did arrive.
enum class SocketOutcome { Ok, Timeout, Reset, ConnectError };

// Map a failed socket's error()/state() to a SocketOutcome. Pure -- no I/O, no
// socket ownership -- so it is unit-testable against synthetic enum values
// (Tests/networking) covering all four outcomes including Timeout, which is
// impractical to exercise live at the 15s read timeout.
SocketOutcome classifySocketOutcome(QAbstractSocket::SocketError err,
                                    QAbstractSocket::SocketState state);

} // namespace Nullock::Core

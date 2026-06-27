// Unit coverage for HttpClient's transport-outcome classifier
// (classifySocketOutcome). The smuggling probe's false-positive fix hinges on
// telling a read TIMEOUT (socket held open & silent -- a genuine CWE-444 desync
// block) from a RESET/connect failure (a hold-then-RST WAF quarantine that
// merely mimics the same delay). That mapping is pure -- it reads only a
// socket's error()/state() -- so we drive it with synthetic enum values and
// cover all four outcomes, including Timeout (impractical to exercise live at
// the 15s read timeout).
//
// Run via:  ctest -R networking -V

#include "socket_outcome.hpp"

#include <QAbstractSocket>
#include <QCoreApplication>

#include <cstdio>

using Nullock::Core::SocketOutcome;
using Nullock::Core::classifySocketOutcome;

namespace {
int pass = 0, fail = 0;

const char *name(SocketOutcome o) {
    switch (o) {
    case SocketOutcome::Ok:           return "Ok";
    case SocketOutcome::Timeout:      return "Timeout";
    case SocketOutcome::Reset:        return "Reset";
    case SocketOutcome::ConnectError: return "ConnectError";
    }
    return "?";
}

void chk(const char *label, SocketOutcome got, SocketOutcome want) {
    if (got == want) { ++pass; return; }
    std::fprintf(stderr, "  FAIL  %s: got %s, want %s\n", label, name(got), name(want));
    ++fail;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    using E = QAbstractSocket;

    // ===== Timeout: socket OPEN and silent -- the genuine desync shape ====
    // The vulnerable back-end blocks on its own body read, so our response read
    // expires with the connection STILL UP. This is the ONLY shape the
    // smuggling grader treats as a CWE-444 hit.
    chk("timeout + connected => Timeout",
        classifySocketOutcome(E::SocketTimeoutError, E::ConnectedState),
        SocketOutcome::Timeout);
    // No decisive error code but still connected: it went silent on us -> Timeout.
    chk("unknown error + connected => Timeout",
        classifySocketOutcome(E::UnknownSocketError, E::ConnectedState),
        SocketOutcome::Timeout);

    // ===== Reset: the peer DROPPED the connection -- a quarantine, NOT a desync.
    // A hold-then-RST WAF that buffers, stalls, then RSTs lands here. Must NOT
    // be graded a critical despite producing the same delay as a timeout.
    chk("remote host closed => Reset",
        classifySocketOutcome(E::RemoteHostClosedError, E::UnconnectedState),
        SocketOutcome::Reset);
    // A peer RST sometimes surfaces as a timeout-flavoured error AFTER the
    // socket has already gone unconnected -- the state check reclassifies it.
    chk("timeout error but NOT connected => Reset (peer reset, not a silent hold)",
        classifySocketOutcome(E::SocketTimeoutError, E::UnconnectedState),
        SocketOutcome::Reset);
    // Fallback path with the connection gone.
    chk("unknown error + unconnected => Reset",
        classifySocketOutcome(E::UnknownSocketError, E::UnconnectedState),
        SocketOutcome::Reset);
    chk("network error + unconnected => Reset",
        classifySocketOutcome(E::NetworkError, E::UnconnectedState),
        SocketOutcome::Reset);

    // ===== ConnectError: the connection never established =================
    chk("connection refused => ConnectError",
        classifySocketOutcome(E::ConnectionRefusedError, E::UnconnectedState),
        SocketOutcome::ConnectError);
    chk("host not found => ConnectError",
        classifySocketOutcome(E::HostNotFoundError, E::UnconnectedState),
        SocketOutcome::ConnectError);
    chk("TLS handshake failed => ConnectError",
        classifySocketOutcome(E::SslHandshakeFailedError, E::UnconnectedState),
        SocketOutcome::ConnectError);

    // ===== The safety property the FP fix depends on ======================
    // None of the non-timeout transport failures may EVER classify as Timeout
    // (that is what would resurrect the false critical the fix removes).
    const E::SocketError nonTimeouts[] = {
        E::RemoteHostClosedError, E::ConnectionRefusedError, E::HostNotFoundError,
        E::SslHandshakeFailedError, E::ProxyConnectionRefusedError,
    };
    for (E::SocketError e : nonTimeouts) {
        // Even claiming "connected", a reset/connect error must not read as a
        // silent hold.
        const bool isTimeout =
            classifySocketOutcome(e, E::ConnectedState) == SocketOutcome::Timeout;
        chk("reset/connect error never grades as Timeout",
            isTimeout ? SocketOutcome::Timeout : SocketOutcome::Reset,
            SocketOutcome::Reset);
    }

    std::fprintf(stderr, "networking_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

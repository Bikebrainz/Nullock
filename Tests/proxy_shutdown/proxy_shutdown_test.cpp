// Does ProxyServer::shutdownAndJoin() actually stop and JOIN the per-connection
// worker threads, and does it do so PROMPTLY when a worker is parked inside a
// blocking read?
//
// Before this existed, onNewConnection() spawned a detached QThread per accepted
// socket, kept no handle to it, and ~ProxyServer() was `= default`. At teardown
// main()'s stack locals unwound -- intercept, extensions, model, scanner, all
// declared AFTER `proxy` and therefore destroyed BEFORE it -- while workers were
// still reaching them through m_server. ProxyServer had (and this is the first)
// zero test coverage of any kind.
//
// WHAT IS ACTUALLY LOCKED HERE -- measured, not assumed:
//
//   PROMPT  waitForReadyRead is uninterruptible, so a worker parked in a 15 s
//           kReadTimeoutMs read could not see a shutdown. waitReadable() slices
//           it at kWaitSliceMs and polls isShuttingDown(). MUTATION: un-slice
//           waitReadable back to a single waitForReadyRead(totalMs) -> the join
//           below takes 14606 ms, this one case fails, the other 9 pass.
//
// WHAT IS *NOT* LOCKED, stated plainly because the mutation run proved it:
//
//   The wait() in joinWorkers(). Deleting the QThreads WITHOUT joining them
//   first was expected to trip Qt's "Destroyed while thread is still running"
//   abort. It does not: the shutdown flag wakes the worker within one slice, so
//   by the time qDeleteAll runs the thread has already finished and deleting it
//   is harmless. That mutant passes all 10 cases. Making it fail would need the
//   worker to still be mid-run at the delete, which is a timing window, and a
//   test built on it would be flaky rather than discriminating. So the wait() is
//   correct-by-construction here, not test-enforced -- do not remove it on the
//   strength of this suite staying green.
//
//   The connect-path slice, on THIS developer machine. The case exists and
//   derives its own precondition, but 192.0.2.1 fails fast here rather than
//   blackholing, so it self-skips and prints why. It will exercise the path on
//   a host that drops TEST-NET-1. waitConnected/waitEncrypted therefore rest on
//   being the same helper shape as the mutation-proven read-path slice, not on
//   their own green run here. The skip is loud on purpose -- an always-silent
//   skip is indistinguishable from a case that never mattered.
//
//   The use-after-free itself. That needs main()'s real unwind ordering with
//   live traffic, which no unit test reproduces.
//
// Run via:  ctest -R proxy_shutdown -V

#include "proxy_server.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostAddress>
#include <QTcpSocket>
#include <QTimer>

#include <cstdio>

using Nullock::Proxy::ProxyServer;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Spin the main event loop for ms so QTcpServer::newConnection is delivered
// (onNewConnection is a queued slot; without a loop turn nothing is accepted).
void pump(int ms) {
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    ProxyServer proxy;
    // Port 0 -> OS-assigned ephemeral port. Derived, not hard-coded: a fixed
    // port would collide with the other live-socket suites in the gauntlet.
    chk("fixture: proxy listens on an ephemeral port",
        proxy.start(QHostAddress::LocalHost, 0) && proxy.listeningPort() != 0);
    chk("fixture: a fresh server is not shutting down", !proxy.isShuttingDown());

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, proxy.listeningPort());
    chk("fixture: client connected to the proxy", client.waitForConnected(5000));

    // A PARTIAL request head -- no terminating CRLFCRLF -- so the worker parks
    // inside readHeaderBlock()'s wait and stays there for the full read budget.
    client.write("GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    chk("fixture: partial request written", client.waitForBytesWritten(5000));
    pump(400);   // let the accept + thread spawn happen

    QElapsedTimer clock;
    clock.start();
    proxy.shutdownAndJoin();
    const qint64 joinMs = clock.elapsed();

    // kReadTimeoutMs is 15'000 and kWaitSliceMs is 250. An un-sliced wait puts
    // this at ~15 s; the sliced one lands well under a second. 5 s sits between
    // them with room for a loaded CI runner on either side.
    chk("PROMPT: a worker parked in a blocking read is joined without waiting out "
        "the full read timeout",
        joinMs < 5000);
    if (joinMs >= 5000)
        std::fprintf(stderr, "        (join took %lld ms)\n", static_cast<long long>(joinMs));

    chk("shutdownAndJoin() marks the server as shutting down", proxy.isShuttingDown());
    chk("shutdownAndJoin() stops listening", !proxy.isRunning());

    // The worker ran to completion, so its stack Connection was destroyed, so
    // the client socket it owned was closed. This is external proof the thread
    // FINISHED -- it is not proof that joinWorkers() waited for it (see the
    // mutation note at the top of this file).
    chk("the worker's Connection was destroyed (client sees the close)",
        client.state() != QAbstractSocket::ConnectedState || client.waitForDisconnected(5000));

    // Idempotent, and cheap the second time -- nothing left to wait for.
    QElapsedTimer again;
    again.start();
    proxy.shutdownAndJoin();
    chk("idempotent: a second shutdownAndJoin() returns immediately",
        again.elapsed() < 1000);

    // A connection accepted after teardown began would never be joined, so it
    // must be refused rather than spawned.
    QTcpSocket late;
    late.connectToHost(QHostAddress::LocalHost, proxy.listeningPort());
    chk("post-shutdown: the listener is closed, so a new client cannot connect",
        !late.waitForConnected(1500));

    // ===== the CONNECT path, not just the READ path =====================
    // Slicing waitForReadyRead alone leaves waitForConnected/waitForEncrypted
    // uninterruptible, so one unreachable upstream could still push the join
    // past its budget -- at which point joinWorkers() gives up and LEAKS the
    // worker, exactly the outcome this change exists to prevent.
    //
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation and
    // never routed. But whether it BLACKHOLES (connect hangs) or is refused
    // immediately depends on the network this runs on, so DERIVE it instead of
    // assuming -- the same mistake a hard-coded "a closed port reports closed"
    // assertion made in port_scan_live.
    {
        QTcpSocket probe;
        probe.connectToHost(QStringLiteral("192.0.2.1"), 80);
        const bool connected = probe.waitForConnected(1200);
        const bool hangs = !connected
            && (probe.state() == QAbstractSocket::ConnectingState
                || probe.state() == QAbstractSocket::HostLookupState);
        probe.abort();

        if (!hangs) {
            std::fprintf(stderr, "  SKIP  connect-path slice: 192.0.2.1 does not "
                                 "blackhole on this host (state=%d), so a worker "
                                 "cannot be parked in waitForConnected here\n",
                         static_cast<int>(probe.state()));
        } else {
            ProxyServer p2;
            chk("fixture: second proxy listens", p2.start(QHostAddress::LocalHost, 0));
            QTcpSocket c2;
            c2.connectToHost(QHostAddress::LocalHost, p2.listeningPort());
            chk("fixture: second client connected", c2.waitForConnected(5000));
            // COMPLETE request this time -- the worker gets past the header read
            // and parks in upstream.connectToHost/waitForConnected instead.
            c2.write("GET http://192.0.2.1/ HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n");
            c2.waitForBytesWritten(5000);
            pump(600);

            QElapsedTimer c2clock;
            c2clock.start();
            p2.shutdownAndJoin();
            const qint64 c2ms = c2clock.elapsed();
            chk("PROMPT: a worker parked in an upstream CONNECT is joined without "
                "waiting out the full connect timeout",
                c2ms < 5000);
            if (c2ms >= 5000)
                std::fprintf(stderr, "        (connect-path join took %lld ms)\n",
                             static_cast<long long>(c2ms));
        }
    }

    std::fprintf(stderr, "proxy_shutdown_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

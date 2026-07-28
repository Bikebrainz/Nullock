// LIVE end-to-end coverage for PortScanner::run() against a loopback listener.
//
// Why this exists: 22bc53d changed how run() retires its probe threads --
// connect(finished -> deleteLater) on UNPARENTED QThread::create objects never
// fired (run() executes on a QtConcurrent pool thread, which turns no event
// loop), so the threads leaked. They are now joined with an UNCONDITIONAL
// t->wait() and destroyed with qDeleteAll. That change shipped with NO coverage:
// probe_smoke has no port-scan case and Tests/port_scanner exercises only the
// pure classifyBanner. A join that deadlocks, or a delete that races a thread
// which had not yet been observed as running, is exactly the kind of defect the
// pure test cannot see -- so this drives the real scanner and requires it to
// finish.
//
// SCOPE, up front: this is a regression guard on scanner BEHAVIOUR, not proof
// that the join is present. Mutation-tested -- deleting the t->wait() loop keeps
// this suite green, because the probes finish before the launcher reaches the
// join and there is no running thread left to destroy. See the breadth case
// below for the full reasoning. The leak itself is not behaviourally
// observable.
//
// It links port_scanner.cpp DIRECTLY (with its own AUTOMOC) rather than the
// Networking lib: that lib's shared mocs_compilation.o references every QObject
// in it, including Repeater, whose ProxyModel symbols only resolve when App also
// links FrontEndGUI. port_scanner.cpp itself pulls nothing but Qt, so compiling
// it in keeps this target at Qt6::Core/Network/Concurrent.
//
// Run via:  ctest -R port_scan_live -V

#include "port_scanner.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>

#include <cstdio>

using Nullock::Core::PortResult;
using Nullock::Core::PortScanner;
using Nullock::Core::ScanRequest;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Bind an ephemeral loopback port, then drop the listener. The port is now
// almost certainly free, which makes "closed" deterministic -- far more reliable
// than guessing a high port number and hoping nothing answers.
quint16 reserveThenReleasePort() {
    QTcpServer probe;
    if (!probe.listen(QHostAddress::LocalHost, 0)) return 0;
    const quint16 p = probe.serverPort();
    probe.close();
    return p;
}

// Pump the main-thread event loop (the listener accepts there) until the scan
// reports it is finished. run() clears m_running only AFTER its join loop and
// qDeleteAll, so "stopped running" IS the assertion that the join completed.
bool waitForScan(PortScanner &s, int budgetMs) {
    QElapsedTimer t; t.start();
    while (s.running() && t.elapsed() < budgetMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
    return !s.running();
}

const PortResult *findPort(const QList<PortResult> &rs, quint16 port) {
    for (const auto &r : rs) if (r.port == port) return &r;
    return nullptr;
}

// What a PLAIN connect() sees on a non-listening port. Some hosts refuse
// (RST -> "closed"), others silently drop (timeout -> "filtered") depending on
// the local firewall; that is a property of the environment, not of the scanner.
// Deriving the expected label from a direct probe keeps the assertion strict --
// the scanner must AGREE with a bare socket -- without hard-coding one platform's
// behaviour. (Asserting "closed" outright failed here: this host drops.)
QString directProbeStatus(quint16 port, int timeoutMs) {
    QTcpSocket s;
    s.connectToHost(QHostAddress::LocalHost, port);
    if (s.waitForConnected(timeoutMs)) return QStringLiteral("open");
    return s.error() == QAbstractSocket::ConnectionRefusedError
               ? QStringLiteral("closed")
               : QStringLiteral("filtered");
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // A real listener that greets like SSH, so the banner grab and
    // classifyBanner both run for real rather than on a synthetic byte string.
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) {
        std::fprintf(stderr, "  FAIL  could not bind a loopback listener\n");
        return 1;
    }
    const quint16 openPort = server.serverPort();
    QObject::connect(&server, &QTcpServer::newConnection, &server, [&server] {
        while (QTcpSocket *c = server.nextPendingConnection()) {
            c->write("SSH-2.0-NullockTest\r\n");
            c->flush();          // child of the server; reaped with it
        }
    });

    const quint16 closedA = reserveThenReleasePort();
    const quint16 closedB = reserveThenReleasePort();
    chk("fixture: got an open port",   openPort != 0);
    chk("fixture: got two closed ports", closedA != 0 && closedB != 0
                                         && closedA != openPort && closedB != openPort);

    // ===== a normal scan runs to completion =============================
    {
        PortScanner scanner;
        ScanRequest req;
        req.host       = QStringLiteral("127.0.0.1");
        req.ports      = { openPort, closedA, closedB };
        req.timeoutMs  = 1500;
        req.grabBanner = true;
        chk("scan: start() accepted", scanner.start(req));

        // THE JOIN ASSERTION. If t->wait() deadlocked or qDeleteAll destroyed a
        // thread that was still running, this never clears (or the process dies).
        chk("scan: run() finished -- probe threads joined and destroyed",
            waitForScan(scanner, 30'000));

        chk("scan: total is one entry per host x port", scanner.total() == 3);
        chk("scan: every probe reported done", scanner.done() == 3);

        const QList<PortResult> rs = scanner.results();
        chk("scan: one result per port", rs.size() == 3);

        const PortResult *open = findPort(rs, openPort);
        chk("scan: the listening port was found", open != nullptr);
        chk("scan: the listening port is 'open'", open && open->status == "open");
        // End-to-end proof that the grabbed bytes reach classifyBanner: a real
        // socket, a real greeting, a real label -- the integration the pure
        // classifyBanner tests cannot cover.
        chk("scan: the SSH greeting was captured",
            open && open->banner.startsWith("SSH-2.0-NullockTest"));
        chk("scan: the greeting classified as ssh", open && open->service == "ssh");

        const PortResult *a = findPort(rs, closedA);
        const PortResult *b = findPort(rs, closedB);
        chk("scan: closed port A reported", a != nullptr);
        chk("scan: closed port B reported", b != nullptr);
        chk("scan: closed port A is not open", a && a->status != "open");
        chk("scan: closed port B is not open", b && b->status != "open");
        // The scanner's verdict must AGREE with a bare connect() on the same port.
        // This host drops rather than refuses, so hard-coding "closed" was wrong;
        // deriving it keeps the check strict (a mislabel still fails) and portable.
        const QString expected = directProbeStatus(closedA, 1500);
        std::fprintf(stderr, "  info  non-listening loopback port probes as '%s'\n",
                     qUtf8Printable(expected));
        chk("scan: the closed-port verdict matches a direct connect",
            a && a->status == expected);
        chk("scan: a non-listening port is never graded open", expected != "open");
        // Anti-FP: an unanswered port must not inherit the listener's label.
        chk("scan: a closed port carries no banner", a && a->banner.isEmpty());
        chk("scan: a closed port carries no service label", a && a->service.isEmpty());

        chk("scan: no error recorded", scanner.lastError().isEmpty());
        chk("scan: running() is false once finished", !scanner.running());
    }

    // ===== the stop-flag path still joins ===============================
    // stop() breaks the launcher out of its task loop, but threads already
    // launched keep running and MUST still be joined before run() returns --
    // the same join, reached by the other exit. A scan that is stopped must
    // terminate, not hang.
    {
        PortScanner scanner;
        ScanRequest req;
        req.host      = QStringLiteral("127.0.0.1");
        req.timeoutMs = 1500;
        for (quint16 p = 1; p <= 60; ++p) req.ports.append(quint16(closedA + p));
        chk("stop: start() accepted", scanner.start(req));
        scanner.stop();
        chk("stop: a stopped scan still finishes (threads joined)",
            waitForScan(scanner, 30'000));
        chk("stop: running() cleared", !scanner.running());
        // stop() is a request, not a guarantee about how much ran: probes already
        // in flight complete. Assert only the invariant -- never more than asked.
        chk("stop: done() never exceeds total()", scanner.done() <= scanner.total());
    }

    // ===== breadth: many ports, high parallelism ========================
    // Drives the semaphore-bounded launcher across 40 probes so the thread
    // lifecycle runs at scale rather than over three ports.
    //
    // WHAT THIS DOES NOT PROVE, stated because it is easy to assume otherwise:
    // it does NOT show the join is required. Mutation-tested by deleting the
    // t->wait() loop and leaving qDeleteAll -- this suite stayed GREEN, twice.
    // The probes finish before the launcher reaches the join (ordinary
    // never-bound loopback ports refuse instantly, so each probe returns in
    // microseconds), leaving no running thread to destroy. Making the join
    // genuinely load-bearing needs probes that are still blocked at that
    // point, which means a black-hole address and a platform-dependent
    // timeout -- flakier than the bug it would guard.
    //
    // So: this file is a REGRESSION GUARD on scanner behaviour (a deadlocked
    // join, a wedged semaphore, a scan that never clears running(), or a
    // mis-classified port all fail here). The leak that 22bc53d fixed is not
    // behaviourally observable and remains covered by reasoning, not by a test.
    {
        PortScanner scanner;
        ScanRequest req;
        req.host       = QStringLiteral("127.0.0.1");
        req.timeoutMs  = 1500;
        req.parallel   = 64;
        req.grabBanner = false;
        for (quint16 p = 1; p <= 40; ++p) req.ports.append(quint16(closedB + p));
        chk("breadth: start() accepted", scanner.start(req));
        chk("breadth: a 40-probe scan finishes", waitForScan(scanner, 30'000));
        chk("breadth: every probe accounted for", scanner.done() == scanner.total());
        chk("breadth: all 40 results collected", scanner.results().size() == 40);
        chk("breadth: none of the unbound ports graded open", [&] {
            for (const auto &r : scanner.results()) if (r.status == "open") return false;
            return true;
        }());
    }

    // ===== a second scan on a fresh scanner still works =================
    // Proves the join left nothing wedged (an undeleted thread or a stuck
    // semaphore would surface as a scan that never starts or never ends).
    {
        PortScanner scanner;
        ScanRequest req;
        req.host       = QStringLiteral("127.0.0.1");
        req.ports      = { openPort };
        req.timeoutMs  = 1500;
        req.grabBanner = true;
        chk("rescan: start() accepted", scanner.start(req));
        chk("rescan: finished", waitForScan(scanner, 30'000));
        const QList<PortResult> rs = scanner.results();
        chk("rescan: still finds the listener open",
            rs.size() == 1 && rs[0].status == "open" && rs[0].service == "ssh");
    }

    std::fprintf(stderr, "port_scan_live_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

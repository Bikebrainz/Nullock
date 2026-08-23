#include "port_scanner.hpp"

#include <QElapsedTimer>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QSemaphore>
#include <QtConcurrent/QtConcurrent>
#include <QTcpSocket>
#include <QThread>

namespace Nullock::Core {

// classifyBanner() (pure) lives in port_logic.cpp so it can be unit-tested
// against Qt6::Core alone -- this TU is the QObject scanner (threads/sockets).

namespace {

PortResult probeOne(const QString &host, quint16 port,
                    int timeoutMs, bool grabBanner,
                    bool *hostNotFound = nullptr) {
    PortResult r;
    r.host = host;
    r.port = port;

    QTcpSocket s;
    QElapsedTimer t; t.start();
    s.connectToHost(host, port);
    if (!s.waitForConnected(timeoutMs)) {
        // Distinguishing closed vs filtered cleanly needs SYN scans; with
        // TCP-connect we read the socket error. The mapping (and the
        // host-not-found short-circuit signal) is the pure, unit-tested
        // portStatusForError.
        r.status = portStatusForError(s.error(), hostNotFound);
        r.latencyMs = static_cast<int>(t.elapsed());
        return r;
    }
    r.status = "open";
    r.latencyMs = static_cast<int>(t.elapsed());

    if (grabBanner) {
        // Give the service a moment to greet us. Many services (ssh, ftp,
        // smtp, mysql) push a banner unsolicited. For HTTP we have to
        // prompt with a request first.
        s.waitForReadyRead(800);
        QByteArray b = s.readAll();
        if (b.isEmpty()) {
            // Try a minimal HTTP request -- works on both 80/443 (mismatched
            // ports here are dropped). Cheap and won't break non-http hosts.
            s.write("GET / HTTP/1.0\r\nHost: " + host.toUtf8() + "\r\n\r\n");
            s.waitForBytesWritten(300);
            s.waitForReadyRead(600);
            b = s.readAll();
        }
        if (b.size() > 256) b = b.left(256);
        r.banner = QString::fromUtf8(b).trimmed();
        // Classify on the RAW grabbed bytes -- r.banner is a lossy UTF-8 display
        // string (a TLS record / binary banner would be corrupted by the
        // round-trip before classifyBanner's 0x16 0x03 check runs).
        r.service = classifyBanner(port, b);
    } else {
        r.service = classifyBanner(port, QByteArray());
    }
    s.disconnectFromHost();
    return r;
}

} // namespace

PortScanner::PortScanner(QObject *parent) : QObject(parent) {}

PortScanner::~PortScanner() {
    // Stop-join. run() launches child probe threads that lock m_mutex and append
    // to m_results; if this object is destroyed while the launcher (or a probe)
    // is mid-flight, those accesses are a use-after-free. Signal stop, then block
    // until the launcher future returns -- run() itself t->wait()s every child
    // probe before returning, so joining the outer future drains them all. The
    // launch loop checks m_stopFlag each iteration, so only already-launched
    // probes (bounded by the probe timeout) are waited out, not the whole scan.
    m_stopFlag.storeRelease(1);
    if (m_worker.isRunning()) m_worker.waitForFinished();
}

QString PortScanner::host() const {
    QMutexLocker lk(&m_mutex);
    return m_host;
}

QList<PortResult> PortScanner::results() const {
    QMutexLocker lk(&m_mutex);
    return m_results;
}

QString PortScanner::lastError() const {
    QMutexLocker lk(&m_mutex);
    return m_lastError;
}

bool PortScanner::start(const ScanRequest &req) {
    if (m_running.loadAcquire() != 0) return false;
    if (req.ports.isEmpty()) return false;

    // Build the unified host list. Single-host mode (req.host) and
    // multi-host mode (req.hosts) coexist; we just merge both.
    QStringList hosts = req.hosts;
    if (!req.host.isEmpty()) hosts.prepend(req.host);
    if (hosts.isEmpty()) return false;

    ScanRequest expanded = req;
    expanded.hosts = hosts;
    expanded.host.clear();  // canonicalize to multi-host form

    {
        QMutexLocker lk(&m_mutex);
        m_host = hosts.size() == 1 ? hosts.first()
                                   : QString("%1 hosts").arg(hosts.size());
        m_results.clear();
        m_lastError.clear();
        m_deadHosts.clear();
    }
    m_stopFlag.storeRelease(0);
    m_done.storeRelease(0);
    m_total.storeRelease(req.ports.size() * hosts.size());
    m_running.storeRelease(1);
    emit runningChanged();
    emit progressChanged();
    emit resultsChanged();

    m_worker = QtConcurrent::run([this, expanded] { run(expanded); });
    return true;
}

void PortScanner::stop() { m_stopFlag.storeRelease(1); }

void PortScanner::clear() {
    if (m_running.loadAcquire() != 0) return;
    {
        QMutexLocker lk(&m_mutex);
        m_results.clear();
        m_lastError.clear();
        m_host.clear();
        m_deadHosts.clear();
    }
    m_done.storeRelease(0);
    m_total.storeRelease(0);
    emit resultsChanged();
    emit progressChanged();
}

bool PortScanner::setResults(const QString &host,
                             const QList<PortResult> &results) {
    if (m_running.loadAcquire() != 0) return false;
    {
        QMutexLocker lk(&m_mutex);
        m_results = results;
        m_host    = host;
    }
    m_done.storeRelease(results.size());
    m_total.storeRelease(results.size());
    emit resultsChanged();
    emit progressChanged();
    return true;
}

void PortScanner::run(const ScanRequest req) {
    // Bound parallelism via a semaphore + one transient worker thread
    // per probe. QTcpSocket can't be moved between threads while a
    // connection is live, so each probe creates its socket on its
    // own thread.
    QSemaphore slotsSem(req.parallel > 0 ? req.parallel : 1);
    QList<QThread *> threads;
    threads.reserve(req.ports.size() * req.hosts.size());

    // Build the flat (host, port) task list. With randomize on, shuffle
    // so we don't hammer one host with every port in a tight burst --
    // useful when the user wants the scan to look less obvious (or to
    // play nicely with rate-limited targets).
    struct Task { QString host; quint16 port; };
    QList<Task> tasks;
    tasks.reserve(req.ports.size() * req.hosts.size());
    for (const QString &host : req.hosts) {
        for (quint16 port : req.ports) tasks.append({ host, port });
    }
    if (req.randomize) {
        auto *rng = QRandomGenerator::global();
        for (int i = tasks.size() - 1; i > 0; --i) {
            const int j = static_cast<int>(rng->bounded(i + 1));
            std::swap(tasks[i], tasks[j]);
        }
    }

    for (const Task &task : tasks) {
        if (m_stopFlag.loadAcquire() != 0) break;
        // If an earlier probe proved this host's name doesn't resolve, don't
        // bother probing the rest of its ports -- they'd all fail DNS the same
        // way. Count it done so progress still completes. (Up to ~parallel
        // probes for the host may already be in flight before the first
        // HostNotFound lands; we skip only what hasn't launched yet.)
        {
            QMutexLocker lk(&m_mutex);
            if (m_deadHosts.contains(task.host)) {
                lk.unlock();
                m_done.fetchAndAddOrdered(1);
                emit progressChanged();
                continue;
            }
        }
        slotsSem.acquire();
        if (req.throttleMs > 0) {
            // Pause between probe launches (in addition to the parallel
            // cap). Throttle here in the launcher rather than inside the
            // worker so the rate is honoured even with parallel=1.
            QThread::msleep(static_cast<unsigned long>(req.throttleMs));
        }
        const QString host = task.host;
        const quint16 port = task.port;

        QThread *t = QThread::create([this, host, port,
                                      timeoutMs=req.timeoutMs,
                                      grabBanner=req.grabBanner, &slotsSem] {
            bool hostNotFound = false;
            const PortResult r = probeOne(host, port, timeoutMs, grabBanner,
                                          &hostNotFound);
            {
                QMutexLocker lk(&m_mutex);
                m_results.append(r);
                if (hostNotFound) {
                    m_deadHosts.insert(host);
                    if (m_lastError.isEmpty())
                        m_lastError =
                            QStringLiteral("host not found (DNS): %1").arg(host);
                }
            }
            m_done.fetchAndAddOrdered(1);
            emit progressChanged();
            // Only flag a results-changed every 8 probes so we don't
            // hammer the snapshot poll for a big scan. Final sync
            // happens after the join loop.
            if ((m_done.loadAcquire() & 0x7) == 0)
                emit resultsChanged();
            slotsSem.release();
        });
        threads.append(t);
        t->start();
    }

    // Join and destroy every probe thread HERE. QThread::create() returns an
    // UNPARENTED object, so retiring it with connect(finished -> deleteLater) made
    // deleteLater the only path to destruction -- and run() itself executes inside a
    // QtConcurrent::run() pool thread (see start()), which never turns an event loop,
    // so that DeferredDelete was never dispatched. The local `threads` list then went
    // out of scope and the objects were lost: one leaked QThread per host x port, per
    // scan, for the life of the process.
    //
    // wait() is now UNCONDITIONAL. The old `if (t->isRunning())` guard could skip the
    // join in the window between start() returning and the OS thread being observed
    // as running; that merely skipped a join before, but would be a use-after-free now
    // that we delete. wait() on an already-finished thread returns immediately, so
    // the unconditional form is both safe and strictly more correct.
    for (QThread *t : threads) {
        t->wait();
    }
    qDeleteAll(threads);
    threads.clear();

    m_running.storeRelease(0);
    emit runningChanged();
    emit resultsChanged();
}

} // namespace Nullock::Core

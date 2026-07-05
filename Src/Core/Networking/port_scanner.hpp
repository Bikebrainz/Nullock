#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QFuture>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QSet>
#include <QString>

namespace Nullock::Core {

// Banner/port -> service label (pure; defined in port_logic.cpp). Exposed for
// the unit test and called by the scanner on the RAW grabbed bytes.
QString classifyBanner(quint16 port, const QByteArray &banner);

// One target port + result of probing it.
struct PortResult {
    QString  host;
    quint16  port    = 0;
    QString  status;       // "open" | "closed" | "filtered" | "unreachable"
    int      latencyMs = 0;
    QString  banner;       // first ~256 bytes of whatever the service said
    QString  service;      // best-guess label (http / ssh / tls / ...)
};

// Configuration for one scan run.
struct ScanRequest {
    QString        host;          // legacy single-host (kept for compat)
    QStringList    hosts;         // multi-host (cidr expansion lives in caller)
    QList<quint16> ports;
    int            timeoutMs = 1500;
    int            parallel  = 64;     // how many concurrent probes
    bool           grabBanner = true;  // pull first response bytes
    int            throttleMs = 0;     // delay between probe launches
                                        // (0 = fire as fast as semaphore allows)
    bool           randomize  = false; // shuffle host*port order so we don't
                                        // hit one host in a tight burst
};

// TCP-connect port scanner. Spawns a worker QThread per probe (cheap on
// modern Windows; ~64 in flight tops out at well under 1% CPU). No raw
// sockets so we don't need npcap and don't need admin -- the cost is
// "filtered" looks the same as "closed" to the kernel.
class PortScanner : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY runningChanged)
    Q_PROPERTY(int  done    READ done    NOTIFY progressChanged)
    Q_PROPERTY(int  total   READ total   NOTIFY progressChanged)
public:
    explicit PortScanner(QObject *parent = nullptr);
    ~PortScanner() override;   // stop-join: the probe worker must not outlive us

    bool running() const { return m_running.loadAcquire() != 0; }
    int  done() const    { return m_done.loadAcquire(); }
    int  total() const   { return m_total.loadAcquire(); }
    QString host() const;

    QList<PortResult> results() const;
    QString lastError() const;

public slots:
    // Start a scan. If one is already in progress, returns false and
    // does nothing (use stop() first).
    Q_INVOKABLE bool start(const ScanRequest &req);
    Q_INVOKABLE void stop();
    Q_INVOKABLE void clear();

    // Push pre-built results (e.g. imported from an nmap XML file).
    // Only callable when no scan is in progress so we don't race the
    // worker threads' appenders.
    bool setResults(const QString &host, const QList<PortResult> &results);

signals:
    void runningChanged();
    void progressChanged();
    void resultsChanged();

private:
    void run(const ScanRequest req);

    mutable QMutex     m_mutex;
    QList<PortResult>  m_results;
    QString            m_host;
    QString            m_lastError;
    QSet<QString>      m_deadHosts;   // hosts that failed DNS -- skip their
                                      // remaining ports (guarded by m_mutex)
    QAtomicInt         m_running{0};
    QAtomicInt         m_stopFlag{0};
    QAtomicInt         m_done{0};
    QAtomicInt         m_total{0};
    QFuture<void>      m_worker;   // handle to the probe-launcher, joined in ~PortScanner()
};

} // namespace Nullock::Core

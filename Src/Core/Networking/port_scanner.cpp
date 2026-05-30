#include "port_scanner.hpp"

#include <QElapsedTimer>
#include <QMutexLocker>
#include <QSemaphore>
#include <QtConcurrent/QtConcurrent>
#include <QTcpSocket>
#include <QThread>

namespace Nullock::Core {

namespace {

// Tiny banner classifier. Looks at the first bytes the service spits
// out (TCP-connect banner grab) and labels what we think it is.
QString classifyBanner(quint16 port, const QByteArray &banner) {
    // Known wire prefixes first -- they're more reliable than port-only.
    if (banner.startsWith("SSH-"))            return "ssh";
    if (banner.startsWith("220 ") && banner.contains("FTP"))    return "ftp";
    if (banner.startsWith("220 ") && banner.contains("SMTP"))   return "smtp";
    if (banner.startsWith("220-")) return "ftp";
    if (banner.startsWith("HTTP/"))           return "http";
    if (banner.startsWith("* OK") && banner.contains("IMAP"))   return "imap";
    if (banner.startsWith("+OK"))             return "pop3";
    if (banner.startsWith("RFB"))             return "vnc";
    if (banner.length() >= 5 && (banner[0] == 0x16) && (banner[1] == 0x03))
        return "tls";
    if (banner.contains("MySQL"))             return "mysql";
    if (banner.contains("Microsoft Windows")) return "winrm/smb";
    if (banner.contains("PostgreSQL"))        return "postgresql";
    if (banner.contains("Redis"))             return "redis";

    // Fallback to a port-based guess. Conservative -- only for the
    // common ones that don't auto-banner.
    switch (port) {
        case 21:   return "ftp";
        case 22:   return "ssh";
        case 23:   return "telnet";
        case 25:
        case 587:
        case 465:  return "smtp";
        case 53:   return "dns";
        case 80:
        case 8080:
        case 8000:
        case 8888: return "http";
        case 110:  return "pop3";
        case 111:  return "rpcbind";
        case 135:  return "msrpc";
        case 139:
        case 445:  return "smb";
        case 143:  return "imap";
        case 161:  return "snmp";
        case 389:  return "ldap";
        case 443:
        case 8443: return "https";
        case 636:  return "ldaps";
        case 993:  return "imaps";
        case 995:  return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 1723: return "pptp";
        case 2049: return "nfs";
        case 2375: return "docker";
        case 2376: return "docker-tls";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 5984: return "couchdb";
        case 5985: return "winrm";
        case 6379: return "redis";
        case 6443: return "k8s-api";
        case 7474: return "neo4j";
        case 8086: return "influxdb";
        case 9000: return "minio/php-fpm";
        case 9092: return "kafka";
        case 9200: return "elasticsearch";
        case 9300: return "elasticsearch-cluster";
        case 11211:return "memcached";
        case 15672:return "rabbitmq-mgmt";
        case 27017:return "mongodb";
    }
    return banner.isEmpty() ? QString() : QString("unknown");
}

PortResult probeOne(const QString &host, quint16 port,
                    int timeoutMs, bool grabBanner) {
    PortResult r;
    r.port = port;

    QTcpSocket s;
    QElapsedTimer t; t.start();
    s.connectToHost(host, port);
    if (!s.waitForConnected(timeoutMs)) {
        // Distinguishing closed vs filtered cleanly needs SYN scans;
        // with TCP-connect we can only see the socket-level error.
        // ConnectionRefusedError -> closed; everything else -> filtered.
        r.status = (s.error() == QAbstractSocket::ConnectionRefusedError)
                       ? "closed" : "filtered";
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
    }
    r.service = classifyBanner(port, r.banner.toUtf8());
    s.disconnectFromHost();
    return r;
}

} // namespace

PortScanner::PortScanner(QObject *parent) : QObject(parent) {}

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
    if (req.host.isEmpty() || req.ports.isEmpty()) return false;

    {
        QMutexLocker lk(&m_mutex);
        m_host = req.host;
        m_results.clear();
        m_lastError.clear();
    }
    m_stopFlag.storeRelease(0);
    m_done.storeRelease(0);
    m_total.storeRelease(req.ports.size());
    m_running.storeRelease(1);
    emit runningChanged();
    emit progressChanged();
    emit resultsChanged();

    (void)QtConcurrent::run([this, req] { run(req); });
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
    }
    m_done.storeRelease(0);
    m_total.storeRelease(0);
    emit resultsChanged();
    emit progressChanged();
}

void PortScanner::run(const ScanRequest req) {
    // Bound parallelism via a semaphore + one transient worker thread
    // per probe. QTcpSocket can't be moved between threads while a
    // connection is live, so each probe creates its socket on its
    // own thread.
    QSemaphore slotsSem(req.parallel > 0 ? req.parallel : 1);
    QList<QThread *> threads;
    threads.reserve(req.ports.size());

    for (quint16 port : req.ports) {
        if (m_stopFlag.loadAcquire() != 0) break;
        slotsSem.acquire();

        QThread *t = QThread::create([this, host=req.host, port,
                                      timeoutMs=req.timeoutMs,
                                      grabBanner=req.grabBanner, &slotsSem] {
            const PortResult r = probeOne(host, port, timeoutMs, grabBanner);
            {
                QMutexLocker lk(&m_mutex);
                m_results.append(r);
            }
            m_done.fetchAndAddOrdered(1);
            emit progressChanged();
            // Only flag a results-changed every 8 probes so we don't
            // hammer the snapshot poll for a 1000-port scan. Final
            // sync happens after the join loop.
            if ((m_done.loadAcquire() & 0x7) == 0)
                emit resultsChanged();
            slotsSem.release();
        });
        QObject::connect(t, &QThread::finished, t, &QObject::deleteLater);
        threads.append(t);
        t->start();
    }

    for (QThread *t : threads) {
        if (t->isRunning()) t->wait();
    }

    m_running.storeRelease(0);
    emit runningChanged();
    emit resultsChanged();
}

} // namespace Nullock::Core

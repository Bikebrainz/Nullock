#pragma once

#include <QAtomicInt>
#include <QDnsLookup>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

// One DNS record. `priority` is only meaningful for MX records.
struct DnsRecord {
    QString type;    // "A" | "AAAA" | "MX" | "TXT" | "NS" | "CNAME"
    QString value;
    int     priority = 0;
};

// One discovered subdomain. `source` is "wordlist" or "crt.sh" so the UI
// can show where it came from; `resolvedIps` is empty when the name
// didn't resolve (still useful for CT hits -- the subdomain existed at
// least once historically).
struct Subdomain {
    QString     name;
    QString     source;
    QStringList resolvedIps;
};

// Recon engine: DNS lookups, certificate-transparency subdomain enum,
// wordlist subdomain enum. Async via QDnsLookup so we don't block the
// main thread, with HTTPS calls (crt.sh) running on a worker.
class ReconEngine : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY runningChanged)
public:
    explicit ReconEngine(QObject *parent = nullptr);

    bool running() const { return m_active.loadAcquire() > 0; }
    QString target() const;
    QString lastError() const;

    QList<DnsRecord> dnsRecords() const;
    QList<Subdomain> subdomains() const;

public slots:
    // Kick off A/AAAA/MX/TXT/NS lookups for a domain. Results stream in
    // as each lookup finishes (typically <500ms total).
    Q_INVOKABLE void runDns(const QString &domain);

    // Query crt.sh certificate transparency logs for subdomains issued
    // certificates for this domain. Runs on a worker thread.
    Q_INVOKABLE void runCertTransparency(const QString &domain);

    // For each name in `subdomains`, prepend it to `domain` and resolve.
    // Report those that resolve as Subdomains with source="wordlist".
    Q_INVOKABLE void runSubdomainWordlist(const QString &domain,
                                          const QStringList &subdomains);

    // Reverse-DNS (PTR) lookup of an IP literal (IPv4 or IPv6). The PTR answer
    // (hostname) lands in dnsRecords() as a record of type "PTR"; an invalid IP
    // sets lastError() instead.
    Q_INVOKABLE void runReverseDns(const QString &ip);

    Q_INVOKABLE void clear();
    Q_INVOKABLE void stop();  // best-effort; in-flight lookups complete

signals:
    void runningChanged();
    void dnsRecordsChanged();
    void subdomainsChanged();

private slots:
    void onDnsFinished();

private:
    void               addLookup(QDnsLookup::Type type, const QString &name);
    void               addSubdomain(const Subdomain &sd);
    // Resolve a fully-qualified name over BOTH A and AAAA (so an IPv6-only host
    // isn't missed), reporting any matching answers as a Subdomain from `source`.
    // When filterWildcard is set (the wordlist brute), a candidate that resolves
    // ONLY to the calibrated wildcard set (m_wildcardIps) is dropped as synthesis.
    void               resolveName(const QString &name, const QString &source,
                                   bool filterWildcard = false);
    // Calibrate the wildcard-DNS answer set from a certainly-absent random name,
    // THEN run the candidate sweep (the sweep must see m_wildcardIps first).
    void               probeWildcardThenSweep(const QString &domain, const QStringList &capped);
    void               runWordlistSweep(const QString &domain, const QStringList &capped);
    void               finishOne();

    mutable QMutex     m_mutex;
    QString            m_target;
    QString            m_lastError;
    QList<DnsRecord>   m_dnsRecords;
    QList<Subdomain>   m_subdomains;
    QStringList        m_wildcardIps;     // calibrated "*.domain" answer set (A+AAAA);
                                          // a candidate resolving only to these is synthesis
    QAtomicInt         m_active{0};       // total in-flight ops
    QAtomicInt         m_stopFlag{0};
    QList<QDnsLookup *> m_pendingLookups;
};

} // namespace Nullock::Core

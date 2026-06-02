#include "recon_engine.hpp"

#include "networking.hpp"

#include <QDnsDomainNameRecord>
#include <QDnsHostAddressRecord>
#include <QDnsMailExchangeRecord>
#include <QDnsServiceRecord>
#include <QDnsTextRecord>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>
#include <QSet>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core {

namespace {

// Strip wildcards / extra labels / lowercase. crt.sh sometimes returns
// names with a leading "*." or "\n"-separated multiple values. Returns
// a canonical (lowercased, trimmed) host.
QString cleanName(QString s) {
    s = s.trimmed().toLower();
    if (s.startsWith("*.")) s.remove(0, 2);
    return s;
}

} // namespace

ReconEngine::ReconEngine(QObject *parent) : QObject(parent) {}

QString ReconEngine::target() const {
    QMutexLocker lk(&m_mutex);
    return m_target;
}

QString ReconEngine::lastError() const {
    QMutexLocker lk(&m_mutex);
    return m_lastError;
}

QList<DnsRecord> ReconEngine::dnsRecords() const {
    QMutexLocker lk(&m_mutex);
    return m_dnsRecords;
}

QList<Subdomain> ReconEngine::subdomains() const {
    QMutexLocker lk(&m_mutex);
    return m_subdomains;
}

void ReconEngine::clear() {
    if (m_active.loadAcquire() > 0) return;
    {
        QMutexLocker lk(&m_mutex);
        m_dnsRecords.clear();
        m_subdomains.clear();
        m_lastError.clear();
        m_target.clear();
    }
    emit dnsRecordsChanged();
    emit subdomainsChanged();
}

void ReconEngine::stop() {
    m_stopFlag.storeRelease(1);
}

void ReconEngine::addLookup(QDnsLookup::Type type, const QString &name) {
    auto *lookup = new QDnsLookup(type, name, this);
    connect(lookup, &QDnsLookup::finished, this, &ReconEngine::onDnsFinished);
    m_pendingLookups.append(lookup);
    m_active.fetchAndAddOrdered(1);
    lookup->lookup();
}

void ReconEngine::finishOne() {
    const int now = m_active.fetchAndSubOrdered(1) - 1;
    if (now <= 0) emit runningChanged();
}

void ReconEngine::runDns(const QString &domain) {
    if (domain.isEmpty()) return;
    const bool wasIdle = (m_active.loadAcquire() == 0);
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain;
        m_lastError.clear();
    }
    if (wasIdle) emit runningChanged();

    addLookup(QDnsLookup::A,     domain);
    addLookup(QDnsLookup::AAAA,  domain);
    addLookup(QDnsLookup::MX,    domain);
    addLookup(QDnsLookup::TXT,   domain);
    addLookup(QDnsLookup::NS,    domain);
    addLookup(QDnsLookup::CNAME, domain);
}

void ReconEngine::onDnsFinished() {
    auto *lookup = qobject_cast<QDnsLookup *>(sender());
    if (!lookup) { finishOne(); return; }

    QList<DnsRecord> got;
    if (lookup->error() == QDnsLookup::NoError) {
        switch (lookup->type()) {
            case QDnsLookup::A:
                for (const auto &r : lookup->hostAddressRecords())
                    got.append({ "A", r.value().toString(), 0 });
                break;
            case QDnsLookup::AAAA:
                for (const auto &r : lookup->hostAddressRecords())
                    got.append({ "AAAA", r.value().toString(), 0 });
                break;
            case QDnsLookup::MX:
                for (const auto &r : lookup->mailExchangeRecords())
                    got.append({ "MX", r.exchange(), r.preference() });
                break;
            case QDnsLookup::TXT:
                for (const auto &r : lookup->textRecords()) {
                    QStringList parts;
                    for (const auto &v : r.values()) parts.append(QString::fromUtf8(v));
                    got.append({ "TXT", parts.join(' '), 0 });
                }
                break;
            case QDnsLookup::NS:
                for (const auto &r : lookup->nameServerRecords())
                    got.append({ "NS", r.value(), 0 });
                break;
            case QDnsLookup::CNAME:
                for (const auto &r : lookup->canonicalNameRecords())
                    got.append({ "CNAME", r.value(), 0 });
                break;
            default: break;
        }
    } else if (lookup->error() != QDnsLookup::NotFoundError
               && lookup->error() != QDnsLookup::OperationCancelledError) {
        QMutexLocker lk(&m_mutex);
        m_lastError = lookup->errorString();
    }

    if (!got.isEmpty()) {
        {
            QMutexLocker lk(&m_mutex);
            m_dnsRecords.append(got);
        }
        emit dnsRecordsChanged();
    }

    m_pendingLookups.removeOne(lookup);
    lookup->deleteLater();
    finishOne();
}

void ReconEngine::addSubdomain(const Subdomain &sd) {
    QMutexLocker lk(&m_mutex);
    // dedup on name (keep first source wins).
    for (const auto &existing : m_subdomains) {
        if (existing.name == sd.name) return;
    }
    m_subdomains.append(sd);
}

void ReconEngine::runCertTransparency(const QString &domain) {
    if (domain.isEmpty()) return;
    const bool wasIdle = (m_active.loadAcquire() == 0);
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain;
    }
    m_active.fetchAndAddOrdered(1);
    if (wasIdle) emit runningChanged();

    // crt.sh hosts a JSON endpoint that returns every cert mentioning the
    // given domain. Run on a worker thread because HttpClient blocks.
    (void)QtConcurrent::run([this, domain]() {
        Nullock::Core::HttpClient client;
        // crt.sh wants the bare domain with a % wildcard prefix to catch
        // subdomains too.
        const QString path = "/?q=%25." + domain + "&output=json";
        const QByteArray req =
            "GET " + path.toUtf8() + " HTTP/1.1\r\n"
            "Host: crt.sh\r\n"
            "User-Agent: Nullock-Recon\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n";
        const auto res = client.send("crt.sh", 443, /*useTls=*/true, req);
        if (!res.ok) {
            QMutexLocker lk(&m_mutex);
            // crt.sh sits behind Cloudflare which rejects Qt's TLS
            // fingerprint (same JA3-fingerprinting issue we hit
            // elsewhere). Surface a useful message instead of the
            // raw socket error.
            m_lastError = "crt.sh unreachable (likely TLS fingerprint "
                          "rejection by Cloudflare). DNS + wordlist still "
                          "work. Detail: " + res.errorMessage;
            finishOne();
            return;
        }
        // crt.sh sometimes returns NDJSON-ish output or pure JSON. Try
        // parsing as JSON first.
        const QJsonDocument doc = QJsonDocument::fromJson(res.parsed.body);
        if (!doc.isArray()) {
            QMutexLocker lk(&m_mutex);
            m_lastError = "crt.sh: unexpected response shape";
            finishOne();
            return;
        }
        QSet<QString> seen;
        int added = 0;
        for (const QJsonValue &v : doc.array()) {
            if (m_stopFlag.loadAcquire() != 0) break;
            const QJsonObject o = v.toObject();
            // name_value can be multi-line (multi-SAN cert).
            const QStringList names =
                o.value("name_value").toString().split('\n', Qt::SkipEmptyParts);
            for (const QString &raw : names) {
                const QString name = cleanName(raw);
                if (name.isEmpty()) continue;
                if (!name.endsWith("." + domain) && name != domain) continue;
                if (seen.contains(name)) continue;
                seen.insert(name);
                addSubdomain({ name, "crt.sh", {} });
                ++added;
            }
        }
        if (added > 0) emit subdomainsChanged();
        finishOne();
    });
}

void ReconEngine::runSubdomainWordlist(const QString &domain,
                                       const QStringList &subdomains) {
    if (domain.isEmpty() || subdomains.isEmpty()) return;
    const bool wasIdle = (m_active.loadAcquire() == 0);
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain;
    }
    if (wasIdle) emit runningChanged();

    // One QDnsLookup per candidate. We bound it lazily by trusting Qt
    // to multiplex over its own DNS workers; even at 100 names the
    // total network cost is well under a second.
    for (const QString &sub : subdomains) {
        if (m_stopFlag.loadAcquire() != 0) break;
        const QString name = (sub + "." + domain).toLower();

        auto *lookup = new QDnsLookup(QDnsLookup::A, name, this);
        m_active.fetchAndAddOrdered(1);
        connect(lookup, &QDnsLookup::finished, this, [this, lookup, name]() {
            if (lookup->error() == QDnsLookup::NoError) {
                // Some OS resolvers do "search domain" suffix expansion --
                // ask for "ftp" and you may get back records for
                // "ftp.<your-local-search-domain>". QDnsLookup inherits
                // that. Reject any answer whose canonical name doesn't
                // match the FQDN we asked for.
                QStringList ips;
                for (const auto &r : lookup->hostAddressRecords()) {
                    if (r.name().compare(name, Qt::CaseInsensitive) != 0
                        && !r.name().endsWith("." + name, Qt::CaseInsensitive)) {
                        continue;   // a different host's record snuck in
                    }
                    ips.append(r.value().toString());
                }
                if (!ips.isEmpty()) {
                    addSubdomain({ name, "wordlist", ips });
                    emit subdomainsChanged();
                }
            }
            lookup->deleteLater();
            finishOne();
        });
        lookup->lookup();
    }
}

} // namespace Nullock::Core

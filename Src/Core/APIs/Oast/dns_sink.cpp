#include "dns_sink.hpp"

#include "dns_logic.hpp"

#include <QDateTime>
#include <QUdpSocket>

namespace Nullock::Core {

DnsSink::DnsSink(QObject *parent) : QObject(parent) {}
DnsSink::~DnsSink() { stop(); }

quint16 DnsSink::start(quint16 port, const QString &baseHost,
                       const QString &answerIp) {
    stop();
    m_baseHost = baseHost.isEmpty() ? QStringLiteral("127.0.0.1") : baseHost;
    m_answerIp = QHostAddress(answerIp.isEmpty() ? QStringLiteral("127.0.0.1")
                                                 : answerIp);
    if (m_answerIp.isNull()) m_answerIp = QHostAddress(QStringLiteral("127.0.0.1"));
    m_socket = new QUdpSocket(this);
    if (!m_socket->bind(QHostAddress::Any, port)) {
        m_socket->deleteLater();
        m_socket = nullptr;
        return 0;
    }
    connect(m_socket, &QUdpSocket::readyRead, this, &DnsSink::onDatagram);
    return m_socket->localPort();
}

void DnsSink::stop() {
    if (m_socket) {
        m_socket->close();
        m_socket->deleteLater();
        m_socket = nullptr;
    }
}

bool    DnsSink::running() const { return m_socket && m_socket->state() != QAbstractSocket::UnconnectedState; }
quint16 DnsSink::port()    const { return m_socket ? m_socket->localPort() : 0; }

// Build a minimal valid response (single A record echoing the question) for a
// DNS query datagram. okOut is false if the packet isn't a parseable
// single-question query. The QNAME parsing lives in the pure, unit-tested
// DnsLogic::parseDnsQuery so this path and onDatagram() agree byte-for-byte.
QByteArray DnsSink::buildResponse(const QByteArray &query, bool &okOut) const {
    okOut = false;
    const DnsLogic::ParsedQuery pq = DnsLogic::parseDnsQuery(query);
    if (!pq.valid) return {};
    const int questionEnd = pq.questionEnd;

    // Response = header (ID copied, QR=1, AA=1, RD copied, RA=0, RCODE=0)
    // + original question + one A answer pointing at m_answerIp.
    QByteArray resp;
    resp.append(query[0]).append(query[1]);     // ID
    resp.append(char(0x84)).append(char(0x00)); // flags: QR=1, AA=1
    resp.append(char(0x00)).append(char(0x01)); // QDCOUNT = 1
    resp.append(char(0x00)).append(char(0x01)); // ANCOUNT = 1
    resp.append(char(0x00)).append(char(0x00)); // NSCOUNT = 0
    resp.append(char(0x00)).append(char(0x00)); // ARCOUNT = 0
    resp.append(query.mid(12, questionEnd - 12)); // original question

    // Answer: name pointer to offset 12, type A, class IN, TTL 30, RDLEN 4.
    resp.append(char(0xC0)).append(char(0x0C));
    resp.append(char(0x00)).append(char(0x01)); // TYPE A
    resp.append(char(0x00)).append(char(0x01)); // CLASS IN
    resp.append(char(0x00)).append(char(0x00))
        .append(char(0x00)).append(char(0x1E)); // TTL = 30
    resp.append(char(0x00)).append(char(0x04)); // RDLENGTH = 4
    const quint32 ip = m_answerIp.toIPv4Address();
    resp.append(char((ip >> 24) & 0xFF)).append(char((ip >> 16) & 0xFF))
        .append(char((ip >> 8) & 0xFF)).append(char(ip & 0xFF));

    okOut = true;
    return resp;
}

void DnsSink::onDatagram() {
    while (m_socket && m_socket->hasPendingDatagrams()) {
        QByteArray buf;
        buf.resize(int(m_socket->pendingDatagramSize()));
        QHostAddress sender;
        quint16 senderPort = 0;
        m_socket->readDatagram(buf.data(), buf.size(), &sender, &senderPort);

        // Parse the QNAME once (memory-safe, length-capped, label-sanitized) --
        // the same pure parser buildResponse() uses, so the answer decision and
        // the logged name can never disagree.
        const DnsLogic::ParsedQuery pq = DnsLogic::parseDnsQuery(buf);

        // Answer best-effort so the resolver doesn't retry and double-log.
        // buildResponse only frames a reply for a well-formed query (respOk ==
        // pq.valid), so responses / malformed datagrams are not reflected.
        bool respOk = false;
        const QByteArray resp = buildResponse(buf, respOk);
        if (respOk && m_socket)
            m_socket->writeDatagram(resp, sender, senderPort);

        // Confirm a callback ONLY from a well-formed query -- never auto-confirm
        // off a malformed datagram (keeps the hit path no more permissive than
        // the responder).
        if (!pq.valid) continue;
        const QString token = DnsLogic::extractToken(pq.qname);
        if (token.isEmpty()) continue;   // not one of ours

        OastHit hit;
        hit.id         = m_nextHitId++;
        hit.atMs       = QDateTime::currentMSecsSinceEpoch();
        hit.token      = token;
        hit.sourceIp   = sender.toString();
        hit.method     = QStringLiteral("DNS");
        hit.hostHeader = pq.qname;   // sanitized + length-capped
        hit.path       = QString();
        hit.userAgent  = QStringLiteral("(dns-resolver)");
        ++m_hitCount;
        emit hitReceived(hit);
    }
}

} // namespace Nullock::Core

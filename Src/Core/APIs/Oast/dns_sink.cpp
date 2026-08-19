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

// Build a minimal valid response for a DNS query datagram, answering the RECORD
// TYPE that was asked: an A answer for A/ANY, an AAAA answer for AAAA, and a
// protocol-correct NODATA (NOERROR, ANCOUNT=0) for any other QTYPE -- rather than
// the old behaviour of handing back a mistyped A record for every question.
// Either way the query is logged as a callback (the token lives in the QNAME,
// independent of QTYPE), so OOB detection is unaffected by the answer type.
// okOut is false if the packet isn't a parseable single-question query. The QNAME
// parse lives in the pure, unit-tested DnsLogic::parseDnsQuery so this path and
// onDatagram() agree byte-for-byte.
QByteArray DnsSink::buildResponse(const QByteArray &query, bool &okOut) const {
    okOut = false;
    const DnsLogic::ParsedQuery pq = DnsLogic::parseDnsQuery(query);
    if (!pq.valid) return {};
    const int questionEnd = pq.questionEnd;

    // Frame the answer RDATA for the queried type. answer.isEmpty() -> NODATA.
    QByteArray answer;
    const quint16 qt = pq.qtype;
    if (qt == 1 || qt == 255) {                 // A (or ANY -> answer with A)
        answer.append(char(0x00)).append(char(0x01)); // TYPE A
        answer.append(char(0x00)).append(char(0x01)); // CLASS IN
        answer.append(char(0x00)).append(char(0x00))
              .append(char(0x00)).append(char(0x1E)); // TTL = 30
        answer.append(char(0x00)).append(char(0x04)); // RDLENGTH = 4
        const quint32 ip = m_answerIp.toIPv4Address();
        answer.append(char((ip >> 24) & 0xFF)).append(char((ip >> 16) & 0xFF))
              .append(char((ip >> 8) & 0xFF)).append(char(ip & 0xFF));
    } else if (qt == 28) {                       // AAAA
        answer.append(char(0x00)).append(char(0x1C)); // TYPE AAAA
        answer.append(char(0x00)).append(char(0x01)); // CLASS IN
        answer.append(char(0x00)).append(char(0x00))
              .append(char(0x00)).append(char(0x1E)); // TTL = 30
        answer.append(char(0x00)).append(char(0x10)); // RDLENGTH = 16
        // m_answerIp as a 16-byte v6 address (an IPv4 answerIp becomes its
        // v4-mapped ::ffff:a.b.c.d form) so the record points back at this box.
        const Q_IPV6ADDR v6 = m_answerIp.toIPv6Address();
        for (int i = 0; i < 16; ++i) answer.append(char(v6[i]));
    }
    // else: unsupported QTYPE -> NODATA (empty answer, ANCOUNT stays 0).

    const bool haveAnswer = !answer.isEmpty();

    QByteArray resp;
    resp.append(query[0]).append(query[1]);     // ID
    resp.append(char(0x84)).append(char(0x00)); // flags: QR=1, AA=1, RCODE=0
    resp.append(char(0x00)).append(char(0x01)); // QDCOUNT = 1
    resp.append(char(0x00)).append(char(haveAnswer ? 0x01 : 0x00)); // ANCOUNT
    resp.append(char(0x00)).append(char(0x00)); // NSCOUNT = 0
    resp.append(char(0x00)).append(char(0x00)); // ARCOUNT = 0
    resp.append(query.mid(12, questionEnd - 12)); // original question

    if (haveAnswer) {
        resp.append(char(0xC0)).append(char(0x0C)); // name pointer to offset 12
        resp.append(answer);
    }

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
        hit.path       = DnsLogic::qtypeName(pq.qtype);   // record type queried (A/AAAA/TXT/...)
        hit.userAgent  = QStringLiteral("(dns-resolver)");
        {
            QMutexLocker lk(&m_mutex);
            ++m_hitCount;
            m_hits.append(hit);                 // retain so it's listable, not just counted
            while (m_hits.size() > kMaxHits) m_hits.removeFirst();
        }
        emit hitReceived(hit);
    }
}

QList<OastHit> DnsSink::hitsSince(qint64 sinceId) const {
    QMutexLocker lk(&m_mutex);
    QList<OastHit> out;
    for (const auto &h : m_hits)
        if (h.id > sinceId) out.append(h);      // strictly after the cursor
    return out;
}

} // namespace Nullock::Core

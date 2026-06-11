#include "dns_sink.hpp"

#include <QDateTime>
#include <QRegularExpression>
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

// First label of the queried name, if it's exactly 16 hex chars.
QString DnsSink::extractToken(const QString &qname) {
    const int dot = qname.indexOf('.');
    const QString head = (dot > 0 ? qname.left(dot) : qname).toLower();
    static const QRegularExpression hex16("^[0-9a-f]{16}$");
    return hex16.match(head).hasMatch() ? head : QString();
}

// Parse a DNS query datagram. Returns the full queried name (labels
// joined by '.') in qnameOut, and a minimal valid response in the return
// value (single A record echoing the question). okOut is false if the
// packet isn't a parseable single-question query.
QByteArray DnsSink::buildResponse(const QByteArray &query, bool &okOut) const {
    okOut = false;
    if (query.size() < 12) return {};
    const quint16 qdcount = (quint8(query[4]) << 8) | quint8(query[5]);
    if (qdcount < 1) return {};

    // Walk the QNAME labels starting at offset 12.
    int pos = 12;
    while (pos < query.size()) {
        const quint8 len = quint8(query[pos]);
        if (len == 0) { pos++; break; }       // root label terminates name
        if ((len & 0xC0) != 0) return {};       // compression in a query: bail
        pos += 1 + len;
        if (pos > query.size()) return {};
    }
    // QTYPE(2) + QCLASS(2) follow the name.
    const int questionEnd = pos + 4;
    if (questionEnd > query.size()) return {};

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

        // Decode the QNAME for logging + token extraction.
        QString qname;
        int pos = 12;
        bool nameOk = buf.size() >= 12;
        while (nameOk && pos < buf.size()) {
            const quint8 len = quint8(buf[pos]);
            if (len == 0) break;
            if ((len & 0xC0) != 0) { nameOk = false; break; }
            if (pos + 1 + len > buf.size()) { nameOk = false; break; }
            if (!qname.isEmpty()) qname += '.';
            qname += QString::fromLatin1(buf.constData() + pos + 1, len);
            pos += 1 + len;
        }

        // Always answer (best-effort) so the resolver doesn't retry and
        // double-log. Ignore failures.
        bool respOk = false;
        const QByteArray resp = buildResponse(buf, respOk);
        if (respOk && m_socket)
            m_socket->writeDatagram(resp, sender, senderPort);

        const QString token = extractToken(qname);
        if (token.isEmpty()) continue;   // not one of ours

        OastHit hit;
        hit.id         = m_nextHitId++;
        hit.atMs       = QDateTime::currentMSecsSinceEpoch();
        hit.token      = token;
        hit.sourceIp   = sender.toString();
        hit.method     = QStringLiteral("DNS");
        hit.hostHeader = qname;
        hit.path       = QString();
        hit.userAgent  = QStringLiteral("(dns-resolver)");
        ++m_hitCount;
        emit hitReceived(hit);
    }
}

} // namespace Nullock::Core

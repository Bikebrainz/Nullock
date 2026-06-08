#include "oast_server.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>

namespace Nullock::Core {

OastServer::OastServer(QObject *parent) : QObject(parent) {}
OastServer::~OastServer() { stop(); }

quint16 OastServer::start(quint16 port, const QString &baseHost) {
    stop();
    m_baseHost = baseHost.isEmpty() ? QStringLiteral("127.0.0.1") : baseHost;
    m_server = new QTcpServer(this);
    connect(m_server, &QTcpServer::newConnection, this, &OastServer::onNewConnection);
    // Bind any address so the server can be reached from the LAN. Caller
    // is responsible for choosing whether to expose externally.
    if (!m_server->listen(QHostAddress::Any, port)) {
        m_server->deleteLater();
        m_server = nullptr;
        return 0;
    }
    return m_server->serverPort();
}

void OastServer::stop() {
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
}

bool    OastServer::running() const   { return m_server && m_server->isListening(); }
quint16 OastServer::port()    const   { return m_server ? m_server->serverPort() : 0; }
QString OastServer::baseHost() const  { return m_baseHost; }

int OastServer::hitCount() const {
    QMutexLocker lk(&m_mutex);
    return m_hits.size();
}

QList<OastHit> OastServer::hitsSince(qint64 sinceId) const {
    QMutexLocker lk(&m_mutex);
    QList<OastHit> out;
    for (const auto &h : m_hits)
        if (h.id > sinceId) out.append(h);
    return out;
}

QJsonObject OastServer::mintToken() {
    // 64 bits of randomness as 16 hex chars. Long enough that an attacker
    // can't realistically guess valid tokens to spam our log; short enough
    // to fit into a DNS subdomain (max 63 chars total per label).
    quint64 a = QRandomGenerator::global()->generate64();
    QString tok = QString::number(a, 16).rightJustified(16, '0');
    const quint16 p = port();
    const QString hostPart = m_baseHost.contains('.') || m_baseHost.contains(':')
        ? QString("%1.%2").arg(tok, m_baseHost)
        : QString("%1.%2").arg(tok, m_baseHost);
    // Fallback URL form that puts the token in the path -- useful for
    // environments where the embedded host doesn't actually resolve via
    // DNS (a real Collaborator needs a wildcard DNS A record).
    const QString pathUrl = QString("http://%1:%2/oast/%3/cb")
                                .arg(m_baseHost).arg(p).arg(tok);
    const QString hostUrl = QString("http://%1:%2/").arg(hostPart).arg(p);
    QJsonObject o;
    o["token"]      = tok;
    o["pathUrl"]    = pathUrl;
    o["hostUrl"]    = hostUrl;
    o["port"]       = p;
    o["baseHost"]   = m_baseHost;
    return o;
}

QString OastServer::extractToken(const QString &hostHeader, const QString &path) {
    // Subdomain form: <token>.<base-host>:<port>
    const int dot = hostHeader.indexOf('.');
    if (dot > 0) {
        const QString head = hostHeader.left(dot).toLower();
        // 16 hex chars exactly.
        static const QRegularExpression hex16("^[0-9a-f]{16}$");
        if (hex16.match(head).hasMatch()) return head;
    }
    // Path form: /oast/<token>/...
    if (path.startsWith("/oast/")) {
        const int next = path.indexOf('/', 6);
        const QString seg = next > 0 ? path.mid(6, next - 6) : path.mid(6);
        static const QRegularExpression hex16p("^[0-9a-f]{16}$");
        if (hex16p.match(seg).hasMatch()) return seg;
    }
    return {};
}

void OastServer::onNewConnection() {
    while (m_server && m_server->hasPendingConnections()) {
        QTcpSocket *s = m_server->nextPendingConnection();
        connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
        // Read the first header block synchronously. OAST callbacks are
        // tiny -- the worst case is a vulnerable target POSTing a few KB.
        // We bound at 64 KB so a hostile peer can't park RAM here.
        handleClient(s);
    }
}

void OastServer::handleClient(QTcpSocket *socket) {
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(2000)) {
            socket->disconnectFromHost();
            return;
        }
        buf.append(socket->readAll());
        if (buf.size() > 64 * 1024) break;
    }
    const int sep = buf.indexOf("\r\n\r\n");
    if (sep < 0) { socket->disconnectFromHost(); return; }
    const QByteArray header = buf.left(sep);
    QByteArray rest = buf.mid(sep + 4);

    // Parse first line + headers.
    const int firstLineEnd = header.indexOf("\r\n");
    const QByteArray requestLine = firstLineEnd > 0 ? header.left(firstLineEnd) : header;
    const QList<QByteArray> parts = requestLine.split(' ');
    QString method, path;
    if (parts.size() >= 2) {
        method = QString::fromLatin1(parts[0]);
        path   = QString::fromLatin1(parts[1]);
    }
    QString hostHdr, ua;
    qint64 contentLength = 0;
    for (const QByteArray &line : header.split('\n')) {
        QByteArray l = line; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        const QString key = QString::fromLatin1(l.left(c));
        const QString val = QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
        if      (key.compare("Host", Qt::CaseInsensitive) == 0)         hostHdr = val;
        else if (key.compare("User-Agent", Qt::CaseInsensitive) == 0)   ua = val;
        else if (key.compare("Content-Length", Qt::CaseInsensitive) == 0)
            contentLength = val.toLongLong();
    }

    // Best-effort body read, capped for safety.
    if (contentLength > 0 && contentLength <= 4 * 1024 * 1024) {
        while (rest.size() < contentLength) {
            if (!socket->waitForReadyRead(2000)) break;
            rest.append(socket->readAll());
        }
        rest = rest.left(contentLength);
    }

    OastHit hit;
    {
        QMutexLocker lk(&m_mutex);
        hit.id   = m_nextHitId++;
    }
    hit.atMs       = QDateTime::currentMSecsSinceEpoch();
    hit.token      = extractToken(hostHdr, path);
    hit.sourceIp   = socket->peerAddress().toString();
    hit.method     = method;
    hit.hostHeader = hostHdr;
    hit.path       = path;
    hit.bodyBytes  = rest.size();
    hit.userAgent  = ua;
    hit.bodyPreview = QString::fromUtf8(rest.left(4096));

    {
        QMutexLocker lk(&m_mutex);
        m_hits.append(hit);
        while (m_hits.size() > kMaxHits) m_hits.removeFirst();
    }
    emit hitReceived(hit);

    // Always 200 OK -- some scanners look for a known body. Keep it tiny.
    QByteArray resp = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/plain\r\n"
                      "Content-Length: 30\r\n"
                      "Connection: close\r\n"
                      "\r\nnullock-oast: callback received\n";
    socket->write(resp);
    socket->flush();
    socket->disconnectFromHost();
}

} // namespace Nullock::Core

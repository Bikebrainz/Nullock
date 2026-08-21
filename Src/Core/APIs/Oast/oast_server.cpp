#include "oast_server.hpp"

#include "oast_logic.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

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
    if (m_pollTimer) m_pollTimer->stop();
    m_remoteMode = false;
}

bool OastServer::running() const {
    return m_remoteMode ? (m_pollTimer && m_pollTimer->isActive())
                        : (m_server && m_server->isListening());
}
quint16 OastServer::port() const {
    return m_remoteMode ? m_remotePort : (m_server ? m_server->serverPort() : 0);
}
QString OastServer::baseHost() const  { return m_baseHost; }

QJsonObject OastServer::remoteRequest(const QString &httpMethod,
                                      const QString &pathAndQuery, int timeoutMs) {
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req{ QUrl(m_remoteBase + pathAndQuery) };
    req.setRawHeader("X-Oast-Key", m_remoteKey.toUtf8());
    QNetworkReply *reply = (httpMethod == QLatin1String("POST"))
        ? m_nam->post(req, QByteArray())
        : m_nam->get(req);
    // Block on a nested loop with a wall-clock timeout so a dead remote can't hang
    // the mint call. Mint/healthz are infrequent + user-initiated, so this is fine.
    QEventLoop loop;
    QTimer to; to.setSingleShot(true);
    connect(&to, &QTimer::timeout, &loop, &QEventLoop::quit);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    to.start(timeoutMs);
    loop.exec();
    QJsonObject out;
    if (reply->isFinished() && reply->error() == QNetworkReply::NoError) {
        out = QJsonDocument::fromJson(reply->readAll()).object();
    } else {
        out["ok"]    = false;
        out["error"] = reply->isFinished() ? reply->errorString() : QStringLiteral("timeout");
        if (!reply->isFinished()) reply->abort();
    }
    reply->deleteLater();
    return out;
}

bool OastServer::startRemote(const QString &base, const QString &key, int pollMs) {
    stop();                       // no local listener in client mode
    m_remoteMode  = true;
    m_remoteBase  = base;
    while (m_remoteBase.endsWith(QLatin1Char('/'))) m_remoteBase.chop(1);
    m_remoteKey   = key;
    m_remoteSince = 0;
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    // /healthz is unauthenticated and returns { ok, baseHost, callbackPort }; use it
    // to learn the remote's identity AND prove reachability before we commit.
    const QJsonObject hz = remoteRequest(QStringLiteral("GET"), QStringLiteral("/healthz"));
    if (hz.value("ok").toBool() != true) {
        m_remoteMode = false;     // unreachable -> caller can fall back to local
        return false;
    }
    m_baseHost   = hz.value("baseHost").toString(m_baseHost);
    m_remotePort = static_cast<quint16>(hz.value("callbackPort").toInt());
    if (!m_pollTimer) {
        m_pollTimer = new QTimer(this);
        connect(m_pollTimer, &QTimer::timeout, this, &OastServer::pollRemote);
    }
    m_pollTimer->start(pollMs);
    return true;
}

void OastServer::pollRemote() {
    if (!m_remoteMode || !m_nam) return;
    QNetworkRequest req{ QUrl(m_remoteBase + QStringLiteral("/poll?since=")
                             + QString::number(m_remoteSince)) };
    req.setRawHeader("X-Oast-Key", m_remoteKey.toUtf8());
    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) return;   // transient; try next tick
        const QJsonObject o = QJsonDocument::fromJson(reply->readAll()).object();
        for (const QJsonValue &v : o.value("hits").toArray()) {
            const QJsonObject ho = v.toObject();
            const qint64 remoteId = static_cast<qint64>(ho.value("id").toDouble());
            if (remoteId > m_remoteSince) m_remoteSince = remoteId;
            // Re-emit as a local hit (own id space so hitsSince() stays monotonic).
            OastHit hit;
            { QMutexLocker lk(&m_mutex); hit.id = m_nextHitId++; }
            hit.atMs        = static_cast<qint64>(ho.value("atMs").toDouble());
            hit.token       = ho.value("token").toString();
            hit.sourceIp    = ho.value("sourceIp").toString();
            hit.method      = ho.value("method").toString();
            hit.hostHeader  = ho.value("hostHeader").toString();
            hit.path        = ho.value("path").toString();
            hit.bodyBytes   = ho.value("bodyBytes").toInt();
            hit.userAgent   = ho.value("userAgent").toString();
            hit.bodyPreview = ho.value("bodyPreview").toString();
            {
                QMutexLocker lk(&m_mutex);
                m_hits.append(hit);
                while (m_hits.size() > kMaxHits) m_hits.removeFirst();
            }
            emit hitReceived(hit);
        }
    });
}

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
    if (m_remoteMode) {
        // Proxy to the remote sink so the minted callback URL carries the remote's
        // public host + port (what a target must actually reach), not ours.
        return remoteRequest(QStringLiteral("POST"), QStringLiteral("/mint"));
    }
    // 64 bits of randomness as 16 hex chars. Long enough that an attacker
    // can't realistically guess valid tokens to spam our log; short enough
    // to fit into a DNS subdomain (max 63 chars total per label).
    //
    // system() (a CSPRNG), NOT global() (Qt-documented Mersenne-Twister, non-
    // cryptographic): a registered-token hit auto-confirms a high/critical
    // finding, so a predictable token stream is a finding-fabrication /
    // token-replay surface. Matches how the tool already mints admin keys.
    // (maybefix #11)
    quint64 a = QRandomGenerator::system()->generate64();
    QString tok = QString::number(a, 16).rightJustified(16, '0');
    const quint16 p = port();
    // Detect IP literal vs. DNS name: only DNS names can take a subdomain
    // prefix in the host-form callback URL. (You can't write
    // "abc.127.0.0.1" -- name resolution will fail.) For IP literals,
    // both forms fall back to the path-form URL.
    static const QRegularExpression kIpv4(R"(^\d{1,3}(?:\.\d{1,3}){3}$)");
    static const QRegularExpression kIpv6(R"(^[0-9a-fA-F:]+$)");
    const bool baseIsIpLiteral =
        kIpv4.match(m_baseHost).hasMatch() ||
        (m_baseHost.contains(':') && kIpv6.match(m_baseHost).hasMatch());
    const QString pathUrl = QString("http://%1:%2/oast/%3/cb")
                                .arg(m_baseHost).arg(p).arg(tok);
    QString hostUrl;
    if (baseIsIpLiteral) {
        // No DNS subdomain available -- reuse the path-form URL.
        hostUrl = pathUrl;
    } else {
        hostUrl = QString("http://%1.%2:%3/").arg(tok, m_baseHost).arg(p);
    }
    QJsonObject o;
    o["token"]      = tok;
    o["pathUrl"]    = pathUrl;
    o["hostUrl"]    = hostUrl;
    o["port"]       = p;
    o["baseHost"]   = m_baseHost;
    return o;
}

QString OastServer::extractToken(const QString &hostHeader, const QString &path) {
    // Pure logic in oast_logic.cpp so it can be unit-tested against Qt6::Core
    // alone (this TU pulls QtNetwork). Both inputs are attacker-controlled.
    return OastLogic::extractToken(hostHeader, path);
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
    // Slowloris defence: absolute wall-clock deadline across header read.
    // OAST listens on a publicly-reachable interface so a hostile peer
    // dribbling header bytes 1 byte at a time would otherwise pin the
    // main thread forever. Same pattern as control_server's R7 fix.
    constexpr qint64 kHeaderDeadlineMs = 8'000;
    QElapsedTimer deadline; deadline.start();
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        const qint64 remaining = kHeaderDeadlineMs - deadline.elapsed();
        if (remaining <= 0) { socket->disconnectFromHost(); return; }
        const int waitMs = static_cast<int>(std::min<qint64>(remaining, 2000));
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(waitMs)) {
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

    // Best-effort body read, capped for safety. Like the header read, bound it
    // with an ABSOLUTE deadline: this sink binds a PUBLIC interface and runs on
    // the main thread, so without it a remote peer that declares a large
    // Content-Length and dribbles one byte every <2s would reset the per-read
    // timeout forever and pin the whole UI/API for the lifetime of the transfer.
    if (contentLength > 0 && contentLength <= 4 * 1024 * 1024) {
        constexpr qint64 kBodyDeadlineMs = 8'000;
        QElapsedTimer bodyDeadline; bodyDeadline.start();
        while (rest.size() < contentLength) {
            const qint64 remaining = kBodyDeadlineMs - bodyDeadline.elapsed();
            if (remaining <= 0) break;
            const int waitMs = static_cast<int>(std::min<qint64>(remaining, 2000));
            if (!socket->waitForReadyRead(waitMs)) break;
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
    static const QByteArray kBody = "nullock-oast: callback received\n";
    QByteArray resp;
    resp += "HTTP/1.1 200 OK\r\n";
    resp += "Content-Type: text/plain\r\n";
    resp += "Content-Length: " + QByteArray::number(kBody.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += kBody;
    socket->write(resp);
    socket->flush();
    socket->disconnectFromHost();
}

} // namespace Nullock::Core

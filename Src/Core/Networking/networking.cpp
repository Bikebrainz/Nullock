#include "networking.hpp"

#include <QAbstractSocket>
#include <QList>
#include <QPair>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>

namespace Nullock::Core {

namespace {

constexpr int kTimeoutMs = 15'000;

bool readHeaderBlock(QTcpSocket *socket, QByteArray &out) {
    while (!out.contains("\r\n\r\n")) {
        if (out.size() > 64 * 1024) return false;
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kTimeoutMs))
            return false;
        out.append(socket->readAll());
        if (socket->state() != QAbstractSocket::ConnectedState && !out.contains("\r\n\r\n"))
            return false;
    }
    return true;
}

bool readExact(QTcpSocket *socket, qint64 n, QByteArray &out) {
    while (out.size() < n) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kTimeoutMs))
            return false;
        out.append(socket->read(n - out.size()));
        if (socket->state() != QAbstractSocket::ConnectedState && out.size() < n)
            return false;
    }
    return true;
}

void readUntilClose(QTcpSocket *socket, QByteArray &out) {
    while (socket->state() == QAbstractSocket::ConnectedState) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kTimeoutMs))
            break;
        out.append(socket->readAll());
    }
    out.append(socket->readAll());
}

bool readChunkedBody(QTcpSocket *socket, QByteArray &buffer, QByteArray &decoded,
                    QByteArray &allBytes) {
    while (true) {
        int crlf = buffer.indexOf("\r\n");
        while (crlf < 0) {
            if (!socket->waitForReadyRead(kTimeoutMs)) return false;
            const QByteArray chunk = socket->readAll();
            buffer.append(chunk);
            allBytes.append(chunk);
            crlf = buffer.indexOf("\r\n");
        }
        QByteArray sizeLine = buffer.left(crlf);
        const int semi = sizeLine.indexOf(';');
        if (semi >= 0) sizeLine = sizeLine.left(semi);
        bool ok = false;
        const qint64 chunkSize = sizeLine.trimmed().toLongLong(&ok, 16);
        if (!ok) return false;
        buffer.remove(0, crlf + 2);
        if (chunkSize == 0) {
            while (buffer.indexOf("\r\n") < 0) {
                if (!socket->waitForReadyRead(kTimeoutMs)) return false;
                const QByteArray chunk = socket->readAll();
                buffer.append(chunk);
                allBytes.append(chunk);
            }
            const int end = buffer.indexOf("\r\n");
            buffer.remove(0, end + 2);
            return true;
        }
        while (buffer.size() < chunkSize + 2) {
            if (!socket->waitForReadyRead(kTimeoutMs)) return false;
            const QByteArray chunk = socket->readAll();
            buffer.append(chunk);
            allBytes.append(chunk);
        }
        decoded.append(buffer.left(chunkSize));
        buffer.remove(0, chunkSize + 2);
    }
}

QList<QPair<QString, QString>> parseHeaders(const QByteArray &block) {
    QList<QPair<QString, QString>> out;
    const QList<QByteArray> lines = block.split('\n');
    for (int i = 1; i < lines.size(); ++i) {
        QByteArray line = lines[i];
        if (line.endsWith('\r')) line.chop(1);
        if (line.isEmpty()) continue;
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        out.append({
            QString::fromLatin1(line.left(colon)).trimmed(),
            QString::fromLatin1(line.mid(colon + 1)).trimmed(),
        });
    }
    return out;
}

QString findHeader(const QList<QPair<QString, QString>> &h, const QString &name) {
    for (const auto &kv : h)
        if (kv.first.compare(name, Qt::CaseInsensitive) == 0)
            return kv.second;
    return {};
}

} // namespace

HttpClient::HttpClient(QObject *parent) : QObject(parent) {}

HttpClient::SendResult HttpClient::send(const QString &host,
                                        quint16 port,
                                        bool useTls,
                                        const QByteArray &requestBytes) {
    SendResult result;

    QTcpSocket *socket = nullptr;
    QSslSocket *ssl = nullptr;
    if (useTls) {
        ssl = new QSslSocket(this);
        QSslConfiguration cfg = ssl->sslConfiguration();
        cfg.setAllowedNextProtocols({ QByteArrayLiteral("http/1.1") });
        ssl->setSslConfiguration(cfg);
        socket = ssl;
        ssl->connectToHostEncrypted(host, port);
        if (!ssl->waitForEncrypted(kTimeoutMs)) {
            result.errorMessage = "TLS handshake failed: " + ssl->errorString();
            socket->deleteLater();
            return result;
        }
    } else {
        socket = new QTcpSocket(this);
        socket->connectToHost(host, port);
        if (!socket->waitForConnected(kTimeoutMs)) {
            result.errorMessage = "connect failed: " + socket->errorString();
            socket->deleteLater();
            return result;
        }
    }

    socket->write(requestBytes);
    if (!socket->waitForBytesWritten(kTimeoutMs)) {
        result.errorMessage = "write failed: " + socket->errorString();
        socket->deleteLater();
        return result;
    }

    QByteArray headerBuf;
    if (!readHeaderBlock(socket, headerBuf)) {
        result.errorMessage = "no response headers received";
        socket->deleteLater();
        return result;
    }
    result.rawResponse = headerBuf;

    const int sep = headerBuf.indexOf("\r\n\r\n");
    const QByteArray headerBlock = headerBuf.left(sep);
    QByteArray rest = headerBuf.mid(sep + 4);

    const int firstLineEnd = headerBlock.indexOf("\r\n");
    const QByteArray statusLine = headerBlock.left(firstLineEnd);
    const int sp1 = statusLine.indexOf(' ');
    const int sp2 = statusLine.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) {
        result.errorMessage = "malformed status line: " + QString::fromLatin1(statusLine);
        socket->deleteLater();
        return result;
    }
    result.parsed.httpVersion  = QString::fromLatin1(statusLine.left(sp1));
    result.parsed.statusCode   = statusLine.mid(sp1 + 1, sp2 - sp1 - 1).toInt();
    result.parsed.reasonPhrase = QString::fromLatin1(statusLine.mid(sp2 + 1));
    result.parsed.headers      = parseHeaders(headerBlock);
    result.parsed.peerAddress  = socket->peerAddress().toString();
    result.parsed.wasTls       = useTls;

    const QString te = findHeader(result.parsed.headers, "Transfer-Encoding");
    const QString cl = findHeader(result.parsed.headers, "Content-Length");

    if (te.compare("chunked", Qt::CaseInsensitive) == 0) {
        QByteArray decoded;
        if (!readChunkedBody(socket, rest, decoded, result.rawResponse)) {
            result.errorMessage = "chunked body read failed";
            socket->deleteLater();
            return result;
        }
        result.parsed.body = decoded;
    } else if (!cl.isEmpty()) {
        const qint64 n = cl.toLongLong();
        result.parsed.body = rest;
        if (result.parsed.body.size() < n) {
            QByteArray extra;
            if (!readExact(socket, n - result.parsed.body.size(), extra)) {
                result.errorMessage = "content-length body read truncated";
                socket->deleteLater();
                return result;
            }
            result.rawResponse.append(extra);
            result.parsed.body.append(extra);
        } else {
            result.parsed.body = result.parsed.body.left(n);
        }
    } else {
        QByteArray tail;
        readUntilClose(socket, tail);
        result.rawResponse.append(tail);
        result.parsed.body = rest + tail;
    }

    socket->disconnectFromHost();
    socket->deleteLater();
    result.ok = true;
    return result;
}

} // namespace Nullock::Core

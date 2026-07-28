#include "networking.hpp"

#include "networking_logic.hpp"

#include <QAbstractSocket>
#include <QList>
#include <QPair>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslSocket>
#include <QStringList>
#include <QTcpSocket>

namespace Nullock::Core {

namespace {

constexpr int     kTimeoutMs    = 15'000;
// Hard cap on the response body we'll accept. A hostile / MitM upstream
// announcing Content-Length: 10 GiB or streaming forever otherwise OOMs.
// 128 MB is comfortably larger than any real recon/replay payload we'd
// look at; anything bigger we just truncate and bail with an error. Single
// source of truth lives in networking_logic so the pure parsers and this
// socket TU can never drift apart.
constexpr qint64  kMaxBodyBytes = NetworkingLogic::kMaxBodyBytes;

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
    if (n < 0 || n > kMaxBodyBytes) return false;
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
        if (out.size() >= kMaxBodyBytes) break;   // hard cap
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(kTimeoutMs))
            break;
        out.append(socket->readAll());
    }
    out.append(socket->readAll());
    if (out.size() > kMaxBodyBytes) out.truncate(kMaxBodyBytes);
}

// Read a chunked body off the socket. The chunk FRAMING is decoded by the pure
// NetworkingLogic::feedChunked state machine (which enforces the per-chunk,
// decoded-total, and size-line/trailer caps); this loop only supplies bytes and
// bounds the RAW accumulator. Without that raw cap a peer could keep `decoded`
// under kMaxBodyBytes while streaming framing overhead forever (tiny 1-byte
// chunks are ~6x raw:decoded), OOMing us via allBytes/rawResponse.
bool readChunkedBody(QTcpSocket *socket, QByteArray &buffer, QByteArray &decoded,
                    QByteArray &allBytes) {
    using NetworkingLogic::ChunkDecode;
    while (true) {
        const ChunkDecode st = NetworkingLogic::feedChunked(buffer, decoded);
        if (st == ChunkDecode::Done)  return true;
        if (st == ChunkDecode::Error) return false;
        // NeedMore: pull more bytes, then cap the raw accumulator.
        if (!socket->waitForReadyRead(kTimeoutMs)) return false;
        const QByteArray chunk = socket->readAll();
        buffer.append(chunk);
        allBytes.append(chunk);
        if (allBytes.size() > kMaxBodyBytes) return false;
    }
}

} // namespace

namespace {
// Process-wide default profile so callers that construct HttpClient
// ad-hoc (Crawler, ContentDiscovery, Recon, scattered QtConcurrent::run
// lambdas) all inherit it without us having to thread a config through
// every call site.
TlsProfile::Profile g_defaultProfile = TlsProfile::Profile::None;
}

void HttpClient::setDefaultProfile(TlsProfile::Profile p) {
    g_defaultProfile = p;
}
TlsProfile::Profile HttpClient::defaultProfile() {
    return g_defaultProfile;
}

HttpClient::HttpClient(QObject *parent) : QObject(parent),
    m_profile(g_defaultProfile) {}

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
        // Explicit peer verification. Repeater/replay/scanner all flow
        // through here; without this an upstream MITM could feed us
        // forged response bytes for the user to act on.
        cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
        // Apply the configured TLS handshake profile (browser-shaped
        // cipher order + protocol). Default is Profile::None which
        // leaves Qt defaults alone.
        TlsProfile::apply(cfg, m_profile);
        ssl->setSslConfiguration(cfg);
        ssl->setPeerVerifyName(host);
        QStringList tlsErrors;
        QObject::connect(ssl, &QSslSocket::sslErrors, ssl,
                         [&tlsErrors, host](const QList<QSslError> &errs) {
            for (const auto &e : errs) {
                tlsErrors << (host + ": " + e.errorString());
            }
        });
        socket = ssl;
        ssl->connectToHostEncrypted(host, port);
        if (!ssl->waitForEncrypted(kTimeoutMs)) {
            QString reason = ssl->errorString();
            if (!tlsErrors.isEmpty()) {
                reason = tlsErrors.join("; ") + " :: " + reason;
            }
            result.outcome = SocketOutcome::ConnectError;
            result.errorMessage = "TLS handshake failed: " + reason;
            socket->deleteLater();
            return result;
        }
    } else {
        socket = new QTcpSocket(this);
        socket->connectToHost(host, port);
        if (!socket->waitForConnected(kTimeoutMs)) {
            result.outcome = SocketOutcome::ConnectError;
            result.errorMessage = "connect failed: " + socket->errorString();
            socket->deleteLater();
            return result;
        }
    }

    socket->write(requestBytes);
    if (!socket->waitForBytesWritten(kTimeoutMs)) {
        result.outcome = classifySocketOutcome(socket->error(), socket->state());
        result.errorMessage = "write failed: " + socket->errorString();
        socket->deleteLater();
        return result;
    }

    QByteArray headerBuf;
    if (!readHeaderBlock(socket, headerBuf)) {
        // The desync-vs-quarantine distinction the smuggling probe relies on:
        // a socket held OPEN and silent (Timeout) vs one the peer RST/closed
        // (Reset) -- both surface here as "no headers", told apart by the
        // socket's error()/state() at the moment of failure.
        result.outcome = classifySocketOutcome(socket->error(), socket->state());
        result.errorMessage = "no response headers received";
        socket->deleteLater();
        return result;
    }

    // Skip 1xx interim responses (100 Continue, 103 Early Hints) to the
    // real final response. Each interim is a complete header block; the
    // bytes after its CRLFCRLF are the start of the next one, so re-seed
    // readHeaderBlock with them. A guard caps pathological loops.
    QByteArray headerBlock, rest;
    NetworkingLogic::StatusLine status;
    for (int guard = 0; ; ++guard) {
        const int sep = headerBuf.indexOf("\r\n\r\n");
        headerBlock = headerBuf.left(sep);
        rest = headerBuf.mid(sep + 4);
        const int firstLineEnd = headerBlock.indexOf("\r\n");
        const QByteArray statusLine =
            headerBlock.left(firstLineEnd < 0 ? headerBlock.size() : firstLineEnd);
        status = NetworkingLogic::parseStatusLine(statusLine);
        if (status.ok && status.statusCode >= 100 && status.statusCode < 200
                && guard < 8) {
            headerBuf = rest;                    // next response starts here
            if (!headerBuf.contains("\r\n\r\n") && !readHeaderBlock(socket, headerBuf)) {
                result.outcome = classifySocketOutcome(socket->error(), socket->state());
                result.errorMessage = "no final response after 1xx";
                socket->deleteLater();
                return result;
            }
            continue;
        }
        break;
    }
    result.rawResponse = headerBuf;

    if (!status.ok) {
        const QByteArray statusLine =
            headerBlock.left(qMax(0, headerBlock.indexOf("\r\n")));
        result.errorMessage = "malformed status line: " + QString::fromLatin1(statusLine);
        socket->deleteLater();
        return result;
    }
    result.parsed.httpVersion  = status.httpVersion;
    result.parsed.statusCode   = status.statusCode;
    result.parsed.reasonPhrase = status.reasonPhrase;
    result.parsed.headers      = NetworkingLogic::parseHeaders(headerBlock);
    result.parsed.peerAddress  = socket->peerAddress().toString();
    result.parsed.wasTls       = useTls;

    const QString te = NetworkingLogic::findHeader(result.parsed.headers, "Transfer-Encoding");
    const QString cl = NetworkingLogic::findHeader(result.parsed.headers, "Content-Length");

    // A response to HEAD, and any 204/304, has NO body regardless of the
    // Content-Length / Transfer-Encoding it advertises (RFC 9110). Reading
    // one would block until the timeout waiting for bytes that never come
    // -- the classic HEAD hang. Detect it from the request method + status
    // and stop after the headers. (1xx is already skipped above.)
    const QByteArray reqMethod = requestBytes.left(qMax(0, requestBytes.indexOf(' ')));
    const int sc = result.parsed.statusCode;
    const bool bodyless = reqMethod.compare("HEAD", Qt::CaseInsensitive) == 0
                       || sc == 204 || sc == 304;
    // Transfer-Encoding may be a stacked list ("gzip, chunked"); the body
    // is chunk-framed when the FINAL coding is chunked.
    const bool isChunked = NetworkingLogic::transferEncodingIsChunked(te);
    if (bodyless) {
        result.parsed.body = QByteArray();
    } else if (isChunked) {
        QByteArray decoded;
        if (!readChunkedBody(socket, rest, decoded, result.rawResponse)) {
            result.outcome = classifySocketOutcome(socket->error(), socket->state());
            result.errorMessage = "chunked body read failed";
            socket->deleteLater();
            return result;
        }
        result.parsed.body = decoded;
    } else if (!cl.isEmpty()) {
        // A present-but-malformed Content-Length (non-numeric, negative, or
        // over-cap) is a framing error -- reject it rather than silently
        // truncating to an empty / mis-sized body (cl.toLongLong() with no
        // &ok would yield 0 on "garbage" and a whole-rest/empty body on a
        // negative value). The bytes DID arrive, so like the malformed
        // status-line path we leave outcome == Ok and fail with ok == false.
        const auto clv = NetworkingLogic::parseContentLength(cl);
        if (!clv.ok) {
            result.errorMessage = "invalid Content-Length: " + cl;
            socket->deleteLater();
            return result;
        }
        const qint64 n = clv.value;
        result.parsed.body = rest;
        if (result.parsed.body.size() < n) {
            QByteArray extra;
            if (!readExact(socket, n - result.parsed.body.size(), extra)) {
                result.outcome = classifySocketOutcome(socket->error(), socket->state());
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

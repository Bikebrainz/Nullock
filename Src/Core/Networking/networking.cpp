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

#include <memory>

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

    // The socket is owned by THIS CALL, not by the client. Every HttpClient in the
    // repo is a stack local, but a single one drives a WHOLE scan loop --
    // content_discovery.cpp holds one client and calls send() once per wordlist
    // entry, with the request cap defaulting to INT_MAX-2. Parenting each socket to
    // the client and retiring it with deleteLater() therefore kept EVERY socket of a
    // run alive until the client left scope: deleteLater only runs on an event-loop
    // turn, and probes execute inside QtConcurrent::run() pool threads, which never
    // turn one. Nothing was lost forever (~QObject reaps them with the parent), but a
    // 100k-word run held 100k live QSslSockets, and any request that failed BEFORE
    // the disconnectFromHost() below also held its descriptor for the rest of the
    // scan -- which a hostile target can force at will just by stalling reads.
    // unique_ptr retires the socket at every return, including the error paths.
    // The parent is kept as a backstop; ~QObject de-registers from it either way,
    // so there is no double delete.
    std::unique_ptr<QTcpSocket> socketOwner;
    QTcpSocket *socket = nullptr;
    QSslSocket *ssl = nullptr;
    if (useTls) {
        ssl = new QSslSocket(this);
        socketOwner.reset(ssl);
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
        // The collector is heap-owned and captured BY VALUE (shared_ptr), NOT a
        // stack local captured by reference: its lifetime is tied to the CONNECTION
        // that writes to it, not to this stack frame. socketOwner above now retires
        // the socket (and with it this connection) at every return, so the window is
        // closed today -- but a by-reference capture would silently re-open a
        // use-after-free the moment socket ownership is deferred again, which is
        // exactly the state this code was in before. Keep the ownership explicit.
        auto tlsErrors = std::make_shared<QStringList>();
        QObject::connect(ssl, &QSslSocket::sslErrors, ssl,
                         [tlsErrors, host](const QList<QSslError> &errs) {
            for (const auto &e : errs) {
                *tlsErrors << (host + ": " + e.errorString());
            }
        });
        socket = ssl;
        ssl->connectToHostEncrypted(host, port);
        if (!ssl->waitForEncrypted(kTimeoutMs)) {
            QString reason = ssl->errorString();
            if (!tlsErrors->isEmpty()) {
                reason = tlsErrors->join("; ") + " :: " + reason;
            }
            result.outcome = SocketOutcome::ConnectError;
            result.errorMessage = "TLS handshake failed: " + reason;
            return result;
        }
    } else {
        socket = new QTcpSocket(this);
        socketOwner.reset(socket);
        socket->connectToHost(host, port);
        if (!socket->waitForConnected(kTimeoutMs)) {
            result.outcome = SocketOutcome::ConnectError;
            result.errorMessage = "connect failed: " + socket->errorString();
            return result;
        }
    }

    socket->write(requestBytes);
    if (!socket->waitForBytesWritten(kTimeoutMs)) {
        result.outcome = classifySocketOutcome(socket->error(), socket->state());
        result.errorMessage = "write failed: " + socket->errorString();
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
        return result;
    }

    // Skip 1xx interim responses (100 Continue, 103 Early Hints) to the
    // real final response. Each interim is a complete header block; the
    // bytes after its CRLFCRLF are the start of the next one, so re-seed
    // readHeaderBlock with them. A guard caps pathological loops.
    QByteArray headerBlock, rest;
    NetworkingLogic::StatusLine status;
    bool tooManyInterim = false;
    for (int seen = 0; ; ++seen) {
        const int sep = headerBuf.indexOf("\r\n\r\n");
        headerBlock = headerBuf.left(sep);
        rest = headerBuf.mid(sep + 4);
        const int firstLineEnd = headerBlock.indexOf("\r\n");
        const QByteArray statusLine =
            headerBlock.left(firstLineEnd < 0 ? headerBlock.size() : firstLineEnd);
        status = NetworkingLogic::parseStatusLine(statusLine);
        const auto action = NetworkingLogic::classifyInterimResponse(status, seen);
        if (action == NetworkingLogic::InterimAction::SkipToNext) {
            headerBuf = rest;                    // next response starts here
            if (!headerBuf.contains("\r\n\r\n") && !readHeaderBlock(socket, headerBuf)) {
                result.outcome = classifySocketOutcome(socket->error(), socket->state());
                result.errorMessage = "no final response after 1xx";
                return result;
            }
            continue;
        }
        tooManyInterim = (action == NetworkingLogic::InterimAction::TooManyInterim);
        break;
    }
    result.rawResponse = headerBuf;

    // Budget spent with an interim STILL in hand. Falling through here reported
    // ok == true carrying the 1xx's status code and headers, with the real final
    // response's raw bytes (status line included) delivered as the BODY -- a false
    // success any target can force by prefixing its reply with nine 103s. The
    // bytes did arrive, so like the malformed-status-line path below we leave
    // outcome == Ok and fail with ok == false.
    if (tooManyInterim) {
        result.errorMessage = "too many 1xx interim responses";
        return result;
    }

    if (!status.ok) {
        const QByteArray statusLine =
            headerBlock.left(qMax(0, headerBlock.indexOf("\r\n")));
        result.errorMessage = "malformed status line: " + QString::fromLatin1(statusLine);
        return result;
    }
    result.parsed.httpVersion  = status.httpVersion;
    result.parsed.statusCode   = status.statusCode;
    result.parsed.reasonPhrase = status.reasonPhrase;
    result.parsed.headers      = NetworkingLogic::parseHeaders(headerBlock);
    result.parsed.peerAddress  = socket->peerAddress().toString();
    result.parsed.wasTls       = useTls;

    const QString te = NetworkingLogic::findHeader(result.parsed.headers, "Transfer-Encoding");
    // Every Content-Length field line, not just the first. findHeader() is
    // FIRST-wins, so a response deliberately carrying "Content-Length: 5" and
    // "Content-Length: 9" was framed from the 5 and the disagreement never
    // surfaced -- the exact desync this scanner exists to FIND, silently
    // resolved in the target's favour. (RFC 9112 6.3; the proxy path already
    // enforces this via HttpLogic::isFramingSafe.)
    const auto clAll = NetworkingLogic::parseContentLengthHeaders(result.parsed.headers);

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
            return result;
        }
        result.parsed.body = decoded;
    } else if (clAll.present) {
        // A present-but-malformed Content-Length (non-numeric, negative, or
        // over-cap) is a framing error -- reject it rather than silently
        // truncating to an empty / mis-sized body (cl.toLongLong() with no
        // &ok would yield 0 on "garbage" and a whole-rest/empty body on a
        // negative value). CONFLICTING duplicates are the same class of error:
        // there is no single correct body length, so framing one at all means
        // picking a side. The bytes DID arrive, so like the malformed
        // status-line path we leave outcome == Ok and fail with ok == false.
        if (!clAll.ok) {
            result.errorMessage = "invalid or conflicting Content-Length: "
                                + clAll.values.join(QStringLiteral(", "));
            return result;
        }
        const qint64 n = clAll.value;
        result.parsed.body = rest;
        if (result.parsed.body.size() < n) {
            QByteArray extra;
            if (!readExact(socket, n - result.parsed.body.size(), extra)) {
                result.outcome = classifySocketOutcome(socket->error(), socket->state());
                result.errorMessage = "content-length body read truncated";
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
    result.ok = true;
    return result;
}

} // namespace Nullock::Core

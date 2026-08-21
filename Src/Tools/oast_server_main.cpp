// nullock-oast -- the standalone, headless OAST (out-of-band) callback sink.
//
// This is the deployable half of the "hosted OAST tier": run it on a box with a
// public address (and ideally a wildcard DNS name pointing at it), and remote
// Nullock instances mint tokens / poll callbacks against it instead of relying
// on a LAN-only in-process sink. It reuses the exact same OastServer used inside
// the desktop app, so callback parsing/token-extraction behaviour is identical.
//
// Two listeners:
//   * CALLBACK port (OAST_PORT, default 8888) -- the public sink. ANY inbound
//     HTTP request is logged as a hit; a vulnerable target hitting
//     http://<token>.<host>:<port>/ or .../oast/<token>/cb lands here.
//   * ADMIN port (OAST_ADMIN_PORT, default 8889) -- a tiny JSON control plane
//     for remote clients: GET /poll?since=N, POST /mint, GET /healthz. Every
//     endpoint except /healthz requires the admin key (X-Oast-Key header or
//     ?key=), so a public callback log can't be read or seeded by strangers.
//
// Config is all environment variables (12-factor / container friendly):
//   OAST_PORT        callback listener port            (default 8888)
//   OAST_BASE_HOST   host embedded in minted URLs       (default 127.0.0.1;
//                    set to your public wildcard domain, e.g. oast.example.com)
//   OAST_ADMIN_PORT  admin/control listener port        (default 8889)
//   OAST_ADMIN_BIND  admin bind address                 (default 0.0.0.0)
//   OAST_ADMIN_KEY   shared secret for the admin API    (default: random,
//                    printed once at startup)
//
// See DEPLOY_OAST.md for DNS, TLS/reverse-proxy and hardening guidance.

#include "oast_server.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrlQuery>

#include <algorithm>
#include <cstdio>

using namespace Nullock::Core;

namespace {

QString envOr(const char *key, const QString &dflt) {
    const QByteArray v = qgetenv(key);
    return v.isEmpty() ? dflt : QString::fromUtf8(v);
}
int envInt(const char *key, int dflt) {
    bool ok = false;
    const int v = qEnvironmentVariableIntValue(key, &ok);
    return ok ? v : dflt;
}
QString randomKey() {
    static const char hex[] = "0123456789abcdef";
    QString s;
    for (int i = 0; i < 32; ++i) s += hex[QRandomGenerator::system()->bounded(16)];
    return s;
}

QJsonObject hitToJson(const OastHit &h) {
    return QJsonObject{
        { "id", static_cast<double>(h.id) },
        { "atMs", static_cast<double>(h.atMs) },
        { "token", h.token },
        { "sourceIp", h.sourceIp },
        { "method", h.method },
        { "hostHeader", h.hostHeader },
        { "path", h.path },
        { "bodyBytes", h.bodyBytes },
        { "userAgent", h.userAgent },
        { "bodyPreview", h.bodyPreview },
    };
}

void sendJson(QTcpSocket *s, int status, const char *reason, const QJsonObject &obj) {
    const QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray resp;
    resp += "HTTP/1.1 " + QByteArray::number(status) + " " + reason + "\r\n";
    resp += "Content-Type: application/json\r\n";
    resp += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    s->write(resp);
    s->flush();
    s->disconnectFromHost();
}

// Read one HTTP header block with a wall-clock deadline + size cap (the admin
// API takes no large bodies). Returns the raw header bytes, or empty on timeout.
QByteArray readHeaderBlock(QTcpSocket *s) {
    constexpr qint64 kDeadlineMs = 5'000;
    QElapsedTimer t; t.start();
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        const qint64 remaining = kDeadlineMs - t.elapsed();
        if (remaining <= 0) return {};
        if (s->bytesAvailable() == 0 &&
            !s->waitForReadyRead(static_cast<int>(std::min<qint64>(remaining, 1500))))
            return {};
        buf.append(s->readAll());
        if (buf.size() > 16 * 1024) break;   // admin requests are tiny
    }
    const int sep = buf.indexOf("\r\n\r\n");
    return sep < 0 ? QByteArray() : buf.left(sep);
}

void handleAdmin(QTcpSocket *s, OastServer &oast, const QString &adminKey) {
    const QByteArray header = readHeaderBlock(s);
    if (header.isEmpty()) { s->disconnectFromHost(); return; }

    const int eol = header.indexOf("\r\n");
    const QByteArray line = eol > 0 ? header.left(eol) : header;
    const QList<QByteArray> parts = line.split(' ');
    if (parts.size() < 2) { sendJson(s, 400, "Bad Request", {{ "error", "malformed" }}); return; }
    const QString method = QString::fromLatin1(parts[0]);
    const QString rawTarget = QString::fromLatin1(parts[1]);
    const int q = rawTarget.indexOf('?');
    const QString path = q >= 0 ? rawTarget.left(q) : rawTarget;
    const QUrlQuery query(q >= 0 ? rawTarget.mid(q + 1) : QString());

    // Liveness is unauthenticated so load balancers / orchestrators can probe.
    if (method == "GET" && path == "/healthz") {
        sendJson(s, 200, "OK", {
            { "ok", true }, { "hits", oast.hitCount() },
            { "baseHost", oast.baseHost() }, { "callbackPort", oast.port() } });
        return;
    }

    // Everything else needs the admin key (header or query param).
    QString key = query.queryItemValue(QStringLiteral("key"));
    for (const QByteArray &h : header.split('\n')) {
        QByteArray l = h; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        if (QString::fromLatin1(l.left(c)).compare("X-Oast-Key", Qt::CaseInsensitive) == 0)
            key = QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
    }
    if (adminKey.isEmpty() || key != adminKey) {
        sendJson(s, 401, "Unauthorized", {{ "error", "missing or invalid admin key" }});
        return;
    }

    if (method == "GET" && path == "/poll") {
        const qint64 since = query.queryItemValue(QStringLiteral("since")).toLongLong();
        QJsonArray hits;
        for (const auto &h : oast.hitsSince(since)) hits.append(hitToJson(h));
        sendJson(s, 200, "OK", {{ "ok", true }, { "hits", hits }});
        return;
    }
    if (method == "POST" && path == "/mint") {
        QJsonObject o = oast.mintToken();
        o["ok"] = true;
        sendJson(s, 200, "OK", o);
        return;
    }
    sendJson(s, 404, "Not Found", {{ "error", "unknown endpoint" }});
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const quint16 callbackPort = static_cast<quint16>(envInt("OAST_PORT", 8888));
    const QString  baseHost    = envOr("OAST_BASE_HOST", QStringLiteral("127.0.0.1"));
    const quint16 adminPort    = static_cast<quint16>(envInt("OAST_ADMIN_PORT", 8889));
    // Loopback by default (maybefix #8): the admin API can mint tokens + read
    // callbacks, so it must not be exposed on every interface unless the operator
    // opts in explicitly (OAST_ADMIN_BIND=0.0.0.0 for a remote-hosted sink).
    const QString  adminBind   = envOr("OAST_ADMIN_BIND", QStringLiteral("127.0.0.1"));
    QString        adminKey    = envOr("OAST_ADMIN_KEY", QString());
    bool generatedKey = false;
    if (adminKey.isEmpty()) { adminKey = randomKey(); generatedKey = true; }

    OastServer oast;
    const quint16 bound = oast.start(callbackPort, baseHost);
    if (bound == 0) {
        std::fprintf(stderr, "nullock-oast: FATAL: could not bind callback port %u\n", callbackPort);
        return 1;
    }
    // Stream every callback to stdout so a hosted deployment has an audit log
    // (journald / docker logs / a log shipper picks it up).
    QObject::connect(&oast, &OastServer::hitReceived, [](const OastHit &h) {
        std::fprintf(stdout, "[hit] %s id=%lld token=%s src=%s %s host=%s path=%s body=%dB ua=%s\n",
            QDateTime::fromMSecsSinceEpoch(h.atMs).toUTC().toString(Qt::ISODate).toUtf8().constData(),
            static_cast<long long>(h.id), h.token.toUtf8().constData(),
            h.sourceIp.toUtf8().constData(), h.method.toUtf8().constData(),
            h.hostHeader.toUtf8().constData(), h.path.toUtf8().constData(),
            h.bodyBytes, h.userAgent.toUtf8().constData());
        std::fflush(stdout);
    });

    QTcpServer admin;
    if (!admin.listen(QHostAddress(adminBind), adminPort)) {
        std::fprintf(stderr, "nullock-oast: FATAL: could not bind admin %s:%u\n",
                     adminBind.toUtf8().constData(), adminPort);
        return 1;
    }
    QObject::connect(&admin, &QTcpServer::newConnection, [&admin, &oast, adminKey]() {
        while (admin.hasPendingConnections()) {
            QTcpSocket *s = admin.nextPendingConnection();
            QObject::connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
            handleAdmin(s, oast, adminKey);
        }
    });

    std::fprintf(stdout,
        "nullock-oast listening\n"
        "  callback sink : http://%s:%u/  (public; ANY inbound request is logged)\n"
        "  admin API     : http://%s:%u/  (GET /poll, POST /mint, GET /healthz)\n"
        "  base host     : %s  (embedded into minted callback URLs)\n",
        baseHost.toUtf8().constData(), bound,
        adminBind.toUtf8().constData(), adminPort,
        baseHost.toUtf8().constData());
    if (generatedKey) {
        // Do NOT print a generated admin key to stdout (maybefix #8): this
        // process streams to journald / docker logs, and the admin key grants
        // token-mint + callback-read -- a log reader would inherit that
        // authority. Write it to an owner-only file and print only the path.
        const QString keyPath = envOr("OAST_ADMIN_KEY_FILE",
                                      QDir::current().filePath(QStringLiteral("nullock-oast-admin.key")));
        QFile kf(keyPath);
        if (kf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            kf.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);   // 0600
            kf.write(adminKey.toUtf8());
            kf.write("\n");
            kf.close();
            std::fprintf(stdout,
                "  admin key     : (generated; written to %s -- or set OAST_ADMIN_KEY to pin it)\n",
                keyPath.toUtf8().constData());
        } else {
            std::fprintf(stdout,
                "  admin key     : (generated; could NOT write %s -- set OAST_ADMIN_KEY to pin a key)\n",
                keyPath.toUtf8().constData());
        }
    } else {
        std::fprintf(stdout, "  admin key     : (from OAST_ADMIN_KEY)\n");
    }
    std::fflush(stdout);

    return app.exec();
}

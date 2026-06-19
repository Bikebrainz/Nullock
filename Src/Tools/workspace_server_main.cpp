// nullock-workspace -- the standalone team-workspace sync server (v3 MVP).
//
// Phase-1 of design/team-workspaces.md: a headless, deployable server that lets
// several operators share an engagement's FINDINGS. Clients push their local
// findings and pull teammates' deltas; the server merges by the same stable
// finding identity key the desktop app already uses for baseline/diff
// (kind | host | url | summary, U+001F-separated), so a client's findings map
// onto the shared set with zero translation.
//
// MVP scope + defaults (deliberately chosen so this is buildable without the
// open product decisions in the design doc):
//   * Storage: SQLite (WAL), the same engine as HistoryIndex. One DB file.
//   * Auth: a single shared bearer key (X-Workspace-Key header or ?key=). Full
//     OIDC/SSO + per-user roles is the separate design/enterprise-sso.md track;
//     this MVP is "shared team key", which is enough to stand a workspace up.
//   * Sync: per-engagement monotonic seq; push upserts by identity key and
//     bumps seq, pull returns everything with seq > since. Last-write-wins.
//
// Endpoints:
//   GET  /healthz                                  -> liveness (unauthenticated)
//   POST /api/ws/push  {engagement,name?,author?,findings:[...]}
//   GET  /api/ws/pull?engagement=<id>&since=<seq>
//
// Config (env): WORKSPACE_PORT (8790), WORKSPACE_BIND (0.0.0.0),
//   WORKSPACE_DB (./nullock-workspace.sqlite), WORKSPACE_KEY (random if unset).
//
// See design/team-workspaces.md for the full model and the roadmap phases.

#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrlQuery>
#include <QVariant>

#include <algorithm>
#include <cstdio>

namespace {

const QChar kSep(QChar(0x1f));   // the finding identity-key separator

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

QString identityKey(const QJsonObject &f) {
    return f.value("kind").toString() + kSep + f.value("host").toString() + kSep
         + f.value("url").toString() + kSep + f.value("summary").toString();
}

void sendJson(QTcpSocket *s, int status, const char *reason, const QJsonObject &obj) {
    const QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray resp;
    resp += "HTTP/1.1 " + QByteArray::number(status) + " " + reason + "\r\n";
    resp += "Content-Type: application/json\r\n";
    resp += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    s->write(resp); s->flush(); s->disconnectFromHost();
}

// Read the header block + (up to Content-Length) body, with a wall-clock
// deadline and a size cap so a hostile/slow peer can't pin the thread.
bool readRequest(QTcpSocket *s, QByteArray &headerOut, QByteArray &bodyOut) {
    constexpr qint64 kDeadlineMs = 8'000;
    constexpr int kMaxTotal = 16 * 1024 * 1024;   // 16 MiB push cap
    QElapsedTimer t; t.start();
    QByteArray buf;
    while (!buf.contains("\r\n\r\n")) {
        if (t.elapsed() > kDeadlineMs) return false;
        if (s->bytesAvailable() == 0 && !s->waitForReadyRead(1500)) return false;
        buf.append(s->readAll());
        if (buf.size() > kMaxTotal) return false;
    }
    const int sep = buf.indexOf("\r\n\r\n");
    headerOut = buf.left(sep);
    QByteArray rest = buf.mid(sep + 4);
    qint64 contentLength = 0;
    for (const QByteArray &line : headerOut.split('\n')) {
        QByteArray l = line; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        if (QString::fromLatin1(l.left(c)).compare("Content-Length", Qt::CaseInsensitive) == 0)
            contentLength = QByteArray(l.mid(c + 1)).trimmed().toLongLong();
    }
    if (contentLength > 0 && contentLength <= kMaxTotal) {
        while (rest.size() < contentLength) {
            if (t.elapsed() > kDeadlineMs) return false;
            if (!s->waitForReadyRead(1500)) break;
            rest.append(s->readAll());
        }
        rest = rest.left(contentLength);
    }
    bodyOut = rest;
    return true;
}

QString headerValue(const QByteArray &header, const char *name) {
    for (const QByteArray &h : header.split('\n')) {
        QByteArray l = h; if (l.endsWith('\r')) l.chop(1);
        const int c = l.indexOf(':');
        if (c <= 0) continue;
        if (QString::fromLatin1(l.left(c)).compare(name, Qt::CaseInsensitive) == 0)
            return QString::fromLatin1(QByteArray(l.mid(c + 1)).trimmed());
    }
    return QString();
}

void ensureSchema(QSqlDatabase &db) {
    QSqlQuery q(db);
    q.exec("PRAGMA journal_mode=WAL");
    q.exec("CREATE TABLE IF NOT EXISTS engagements ("
           "  id TEXT PRIMARY KEY, name TEXT, created_ms INTEGER, seq INTEGER DEFAULT 0)");
    q.exec("CREATE TABLE IF NOT EXISTS findings ("
           "  engagement TEXT, ikey TEXT, seq INTEGER, updated_ms INTEGER,"
           "  author TEXT, json TEXT, PRIMARY KEY (engagement, ikey))");
    q.exec("CREATE INDEX IF NOT EXISTS findings_seq ON findings(engagement, seq)");
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const quint16 port  = static_cast<quint16>(envInt("WORKSPACE_PORT", 8790));
    const QString  bind = envOr("WORKSPACE_BIND", QStringLiteral("0.0.0.0"));
    const QString  dbPath = envOr("WORKSPACE_DB", QStringLiteral("nullock-workspace.sqlite"));
    QString        key  = envOr("WORKSPACE_KEY", QString());
    bool generatedKey = false;
    if (key.isEmpty()) { key = randomKey(); generatedKey = true; }

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);
    if (!db.open()) {
        std::fprintf(stderr, "nullock-workspace: FATAL: cannot open DB %s: %s\n",
                     dbPath.toUtf8().constData(), db.lastError().text().toUtf8().constData());
        return 1;
    }
    ensureSchema(db);

    auto authed = [&](const QByteArray &header, const QUrlQuery &query) {
        QString k = query.queryItemValue(QStringLiteral("key"));
        const QString hk = headerValue(header, "X-Workspace-Key");
        if (!hk.isEmpty()) k = hk;
        return !key.isEmpty() && k == key;
    };

    QTcpServer server;
    if (!server.listen(QHostAddress(bind), port)) {
        std::fprintf(stderr, "nullock-workspace: FATAL: cannot bind %s:%u\n",
                     bind.toUtf8().constData(), port);
        return 1;
    }

    QObject::connect(&server, &QTcpServer::newConnection, [&]() {
        while (server.hasPendingConnections()) {
            QTcpSocket *s = server.nextPendingConnection();
            QObject::connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);

            QByteArray header, body;
            if (!readRequest(s, header, body)) { s->disconnectFromHost(); continue; }

            const int eol = header.indexOf("\r\n");
            const QByteArray line = eol > 0 ? header.left(eol) : header;
            const QList<QByteArray> parts = line.split(' ');
            if (parts.size() < 2) { sendJson(s, 400, "Bad Request", {{ "error", "malformed" }}); continue; }
            const QString method = QString::fromLatin1(parts[0]);
            const QString rawTarget = QString::fromLatin1(parts[1]);
            const int qm = rawTarget.indexOf('?');
            const QString path = qm >= 0 ? rawTarget.left(qm) : rawTarget;
            const QUrlQuery query(qm >= 0 ? rawTarget.mid(qm + 1) : QString());

            if (method == "GET" && path == "/healthz") {
                sendJson(s, 200, "OK", {{ "ok", true }, { "service", "nullock-workspace" }});
                continue;
            }
            if (!authed(header, query)) {
                sendJson(s, 401, "Unauthorized", {{ "error", "missing or invalid workspace key" }});
                continue;
            }

            if (method == "POST" && path == "/api/ws/push") {
                const QJsonObject in = QJsonDocument::fromJson(body).object();
                const QString eng = in.value("engagement").toString();
                if (eng.isEmpty()) { sendJson(s, 400, "Bad Request", {{ "error", "engagement required" }}); continue; }
                const QString author = in.value("author").toString();
                const QJsonArray findings = in.value("findings").toArray();
                if (findings.isEmpty()) { sendJson(s, 400, "Bad Request", {{ "error", "findings array required and non-empty" }}); continue; }

                // The whole push runs in one transaction with no event-loop yield
                // (no waitForReadyRead between BEGIN and commit), so even though
                // waitForReadyRead can re-enter the server during request READING,
                // the seq read->bump->write critical section cannot interleave with
                // another request -- they serialise on this one event-loop thread.
                // (A QMutex around the handler would self-deadlock on that
                // re-entrancy, so it is deliberately not used.) Any SQL failure
                // rolls the whole push back rather than committing a partial /
                // seq-regressed state.
                QSqlQuery q(db);
                db.transaction();
                auto fail = [&](const QString &what) {
                    db.rollback();
                    sendJson(s, 500, "Internal Server Error",
                             {{ "error", "db error: " + what }});
                };
                q.prepare("INSERT INTO engagements(id,name,created_ms,seq) VALUES(?,?,?,0) "
                          "ON CONFLICT(id) DO UPDATE SET name=COALESCE(excluded.name,name)");
                q.addBindValue(eng);
                q.addBindValue(in.value("name").toString());
                q.addBindValue(QDateTime::currentMSecsSinceEpoch());
                if (!q.exec()) { fail("engagement upsert"); continue; }
                qint64 seq = 0;
                q.prepare("SELECT seq FROM engagements WHERE id=?"); q.addBindValue(eng);
                // A failed seq read must abort -- proceeding from 0 could write
                // findings with a seq BELOW existing ones and make pulls miss them.
                if (!q.exec() || !q.next()) { fail("seq read"); continue; }
                seq = q.value(0).toLongLong();

                int accepted = 0;
                bool ok = true;
                const qint64 now = QDateTime::currentMSecsSinceEpoch();
                for (const QJsonValue &fv : findings) {
                    const QJsonObject f = fv.toObject();
                    if (f.value("kind").toString().isEmpty()) continue;  // skip junk entries
                    const QString ikey = identityKey(f);
                    ++seq;
                    q.prepare("INSERT INTO findings(engagement,ikey,seq,updated_ms,author,json) "
                              "VALUES(?,?,?,?,?,?) ON CONFLICT(engagement,ikey) DO UPDATE SET "
                              "seq=excluded.seq, updated_ms=excluded.updated_ms, "
                              "author=excluded.author, json=excluded.json");
                    q.addBindValue(eng); q.addBindValue(ikey); q.addBindValue(seq);
                    q.addBindValue(now); q.addBindValue(author);
                    q.addBindValue(QString::fromUtf8(QJsonDocument(f).toJson(QJsonDocument::Compact)));
                    if (!q.exec()) { ok = false; break; }
                    ++accepted;
                }
                if (!ok) { fail("finding upsert"); continue; }
                q.prepare("UPDATE engagements SET seq=? WHERE id=?");
                q.addBindValue(seq); q.addBindValue(eng);
                if (!q.exec()) { fail("seq write"); continue; }
                if (!db.commit()) { fail("commit"); continue; }
                sendJson(s, 200, "OK", {{ "ok", true }, { "engagement", eng },
                                        { "newSeq", static_cast<double>(seq) },
                                        { "accepted", accepted }});
                continue;
            }

            if (method == "GET" && path == "/api/ws/pull") {
                const QString eng = query.queryItemValue(QStringLiteral("engagement"));
                if (eng.isEmpty()) { sendJson(s, 400, "Bad Request", {{ "error", "engagement required" }}); continue; }
                const qint64 since = query.queryItemValue(QStringLiteral("since")).toLongLong();
                QSqlQuery q(db);
                q.prepare("SELECT json, seq FROM findings WHERE engagement=? AND seq>? ORDER BY seq");
                q.addBindValue(eng); q.addBindValue(since);
                QJsonArray out; qint64 maxSeq = since;
                if (q.exec()) {
                    while (q.next()) {
                        out.append(QJsonDocument::fromJson(q.value(0).toString().toUtf8()).object());
                        maxSeq = std::max(maxSeq, q.value(1).toLongLong());
                    }
                }
                sendJson(s, 200, "OK", {{ "ok", true }, { "engagement", eng },
                                        { "seq", static_cast<double>(maxSeq) },
                                        { "count", out.size() }, { "findings", out }});
                continue;
            }

            if (method == "GET" && path == "/api/ws/engagements") {
                // Let a client discover what engagements exist (and how big they
                // are) before pulling -- you can't pull what you can't name.
                QSqlQuery q(db);
                q.exec("SELECT e.id, e.name, e.seq, e.created_ms, "
                       "       (SELECT COUNT(*) FROM findings f WHERE f.engagement=e.id) "
                       "FROM engagements e ORDER BY e.id");
                QJsonArray out;
                while (q.next())
                    out.append(QJsonObject{
                        { "id", q.value(0).toString() }, { "name", q.value(1).toString() },
                        { "seq", static_cast<double>(q.value(2).toLongLong()) },
                        { "createdMs", static_cast<double>(q.value(3).toLongLong()) },
                        { "findings", q.value(4).toInt() } });
                sendJson(s, 200, "OK", {{ "ok", true }, { "count", out.size() },
                                        { "engagements", out }});
                continue;
            }

            sendJson(s, 404, "Not Found", {{ "error", "unknown endpoint" }});
        }
    });

    std::fprintf(stdout,
        "nullock-workspace listening\n"
        "  api  : http://%s:%u/  (POST /api/ws/push, GET /api/ws/pull,\n"
        "         GET /api/ws/engagements, GET /healthz)\n"
        "  db   : %s\n",
        bind.toUtf8().constData(), port, dbPath.toUtf8().constData());
    if (generatedKey)
        std::fprintf(stdout, "  key  : %s  (generated -- set WORKSPACE_KEY to pin it)\n",
                     key.toUtf8().constData());
    else
        std::fprintf(stdout, "  key  : (from WORKSPACE_KEY)\n");
    std::fflush(stdout);

    return app.exec();
}

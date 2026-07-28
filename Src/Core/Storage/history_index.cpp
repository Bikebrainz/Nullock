#include "history_index.hpp"

#include "history_logic.hpp"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>

namespace Nullock::Core {

HistoryIndex::HistoryIndex(QObject *parent) : QObject(parent) {}
HistoryIndex::~HistoryIndex() { close(); }

bool HistoryIndex::open(const QString &projectDir) {
    QMutexLocker lk(&m_mutex);
    // Atomic teardown + re-open under ONE lock. Calling the public close()
    // here would release the lock between teardown and re-create, leaving a
    // window where another thread (under the documented multi-thread model)
    // could observe a half-open connection.
    closeLocked();
    m_dir = projectDir;
    m_dbPath = projectDir + "/history-index.sqlite";
    // Unique connection name so multiple HistoryIndex instances (across
    // project switches) don't collide on the global QSqlDatabase registry.
    m_connName = "nullock_history_" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_db = QSqlDatabase::addDatabase("QSQLITE", m_connName);
    m_db.setDatabaseName(m_dbPath);
    if (!m_db.open()) {
        qWarning() << "history-index: open failed:" << m_db.lastError().text();
        return false;
    }
    QSqlQuery pragma(m_db);
    // WAL keeps reads cheap and tolerates a single writer. Today every
    // open/append/find/loadFullRow runs on the main event loop (queued
    // connections marshal the proxy-worker capture path back to it), so access
    // is already serialized; WAL + m_mutex keep it correct if that ever changes.
    pragma.exec("PRAGMA journal_mode=WAL");
    pragma.exec("PRAGMA synchronous=NORMAL");
    return ensureSchema();
}

void HistoryIndex::close() {
    QMutexLocker lk(&m_mutex);
    closeLocked();
}

void HistoryIndex::closeLocked() {
    // Caller already holds m_mutex.
    if (m_db.isOpen()) m_db.close();
    if (!m_connName.isEmpty()) {
        // Drop the member's handle BEFORE removeDatabase so Qt doesn't warn
        // about a connection still in use.
        m_db = QSqlDatabase();
        QSqlDatabase::removeDatabase(m_connName);
        m_connName.clear();
    }
    m_dbPath.clear();
}

bool HistoryIndex::isOpen() const {
    QMutexLocker lk(&m_mutex);
    return m_db.isOpen();
}

bool HistoryIndex::ensureSchema() {
    // Caller already holds m_mutex.
    static const char *kSchema =
        "CREATE TABLE IF NOT EXISTS rows ("
        "  id        INTEGER PRIMARY KEY,"
        "  ts        INTEGER,"          // epoch ms
        "  method    TEXT NOT NULL,"
        "  host      TEXT NOT NULL,"
        "  port      INTEGER,"
        "  path      TEXT NOT NULL,"
        "  status    INTEGER,"
        "  size      INTEGER,"          // response body size
        "  tls       INTEGER,"          // 0/1
        "  mime      TEXT,"
        "  req_json  TEXT,"             // full HttpRequest serialized
        "  resp_json TEXT"              // full HttpResponse serialized
        ")";
    QSqlQuery q(m_db);
    if (!q.exec(kSchema)) {
        qWarning() << "history-index: schema create failed:" << q.lastError().text();
        return false;
    }
    // Index on the columns most often filtered. Drops query time
    // from O(n) to O(log n) on 200k-row history.
    q.exec("CREATE INDEX IF NOT EXISTS rows_host_idx   ON rows(host)");
    q.exec("CREATE INDEX IF NOT EXISTS rows_status_idx ON rows(status)");
    q.exec("CREATE INDEX IF NOT EXISTS rows_method_idx ON rows(method)");
    q.exec("CREATE INDEX IF NOT EXISTS rows_ts_idx     ON rows(ts)");
    return true;
}

int HistoryIndex::rowCount() const {
    QMutexLocker lk(&m_mutex);
    if (!m_db.isOpen()) return 0;
    QSqlQuery q(m_db);
    if (!q.exec("SELECT COUNT(*) FROM rows") || !q.next()) return 0;
    return q.value(0).toInt();
}

namespace {
QString mimeOf(const Nullock::Proxy::HttpResponse &r) {
    for (const auto &h : r.headers)
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0)
            return h.second;
    return {};
}

QJsonObject requestToJson(const Nullock::Proxy::HttpRequest &r) {
    QJsonObject o;
    o["method"]      = r.method;
    o["target"]      = r.target;
    o["path"]        = r.path;
    o["host"]        = r.host;
    o["port"]        = r.port;
    o["httpVersion"] = r.httpVersion;
    o["ts"]          = r.timestamp.toMSecsSinceEpoch();
    QJsonArray hs;
    for (const auto &h : r.headers) {
        QJsonArray pair;
        pair.append(h.first);
        pair.append(h.second);
        hs.append(pair);
    }
    o["headers"] = hs;
    o["body_b64"] = QString::fromLatin1(r.body.toBase64());
    return o;
}

QJsonObject responseToJson(const Nullock::Proxy::HttpResponse &r) {
    QJsonObject o;
    o["httpVersion"]  = r.httpVersion;
    o["statusCode"]   = r.statusCode;
    o["reasonPhrase"] = r.reasonPhrase;
    o["wasTls"]       = r.wasTls;
    o["peerAddress"]  = r.peerAddress;
    QJsonArray hs;
    for (const auto &h : r.headers) {
        QJsonArray pair;
        pair.append(h.first);
        pair.append(h.second);
        hs.append(pair);
    }
    o["headers"] = hs;
    o["body_b64"] = QString::fromLatin1(r.body.toBase64());
    return o;
}

Nullock::Proxy::HttpRequest requestFromJson(const QJsonObject &o) {
    Nullock::Proxy::HttpRequest r;
    r.method      = o.value("method").toString();
    r.target      = o.value("target").toString();
    r.path        = o.value("path").toString();
    r.host        = o.value("host").toString();
    r.port        = static_cast<quint16>(o.value("port").toInt());
    r.httpVersion = o.value("httpVersion").toString();
    r.timestamp   = QDateTime::fromMSecsSinceEpoch(
                        o.value("ts").toVariant().toLongLong());
    for (const QJsonValue &v : o.value("headers").toArray()) {
        const QJsonArray pair = v.toArray();
        if (pair.size() == 2)
            r.headers.append({ pair[0].toString(), pair[1].toString() });
    }
    r.body = QByteArray::fromBase64(o.value("body_b64").toString().toLatin1());
    return r;
}

Nullock::Proxy::HttpResponse responseFromJson(const QJsonObject &o) {
    Nullock::Proxy::HttpResponse r;
    r.httpVersion  = o.value("httpVersion").toString();
    r.statusCode   = o.value("statusCode").toInt();
    r.reasonPhrase = o.value("reasonPhrase").toString();
    r.wasTls       = o.value("wasTls").toBool();
    r.peerAddress  = o.value("peerAddress").toString();
    for (const QJsonValue &v : o.value("headers").toArray()) {
        const QJsonArray pair = v.toArray();
        if (pair.size() == 2)
            r.headers.append({ pair[0].toString(), pair[1].toString() });
    }
    r.body = QByteArray::fromBase64(o.value("body_b64").toString().toLatin1());
    return r;
}

QString renderRawRequest(const Nullock::Proxy::HttpRequest &req) {
    QString out;
    out += QString("%1 %2 %3\n").arg(req.method, req.path, req.httpVersion);
    for (const auto &h : req.headers)
        out += QString("%1: %2\n").arg(h.first, h.second);
    out += "\n";
    out += QString::fromUtf8(req.body.left(64 * 1024));
    return out;
}

QString renderRawResponse(const Nullock::Proxy::HttpResponse &resp) {
    QString out;
    // Simultaneous multi-arg (not chained .arg) so a literal "%2"/"%3" inside the
    // target-controlled httpVersion/reasonPhrase can't be refilled by a later
    // .arg -- matches renderRawRequest. Display-only, but keep it placeholder-safe.
    out += QString("%1 %2 %3\n")
              .arg(resp.httpVersion,
                   QString::number(resp.statusCode),
                   resp.reasonPhrase);
    for (const auto &h : resp.headers)
        out += QString("%1: %2\n").arg(h.first, h.second);
    out += "\n";
    out += QString::fromUtf8(resp.body.left(64 * 1024));
    return out;
}

}

void HistoryIndex::append(int rowId,
                          const Nullock::Proxy::HttpRequest &req,
                          const Nullock::Proxy::HttpResponse &resp) {
    QMutexLocker lk(&m_mutex);
    if (!m_db.isOpen()) return;
    const QString reqJson  = QString::fromUtf8(QJsonDocument(requestToJson(req))
                                  .toJson(QJsonDocument::Compact));
    const QString respJson = QString::fromUtf8(QJsonDocument(responseToJson(resp))
                                  .toJson(QJsonDocument::Compact));
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO rows (id, ts, method, host, port, path, status, size, tls, mime, req_json, resp_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  ts=excluded.ts, method=excluded.method, host=excluded.host, "
        "  port=excluded.port, path=excluded.path, status=excluded.status, "
        "  size=excluded.size, tls=excluded.tls, mime=excluded.mime, "
        "  req_json=excluded.req_json, resp_json=excluded.resp_json");
    q.addBindValue(rowId);
    q.addBindValue(req.timestamp.isValid()
                       ? req.timestamp.toMSecsSinceEpoch()
                       : QDateTime::currentMSecsSinceEpoch());
    q.addBindValue(req.method);
    q.addBindValue(req.host);
    q.addBindValue(req.port);
    q.addBindValue(req.path);
    q.addBindValue(resp.statusCode);
    q.addBindValue(static_cast<qint64>(resp.body.size()));
    q.addBindValue(resp.wasTls ? 1 : 0);
    q.addBindValue(mimeOf(resp));
    q.addBindValue(reqJson);
    q.addBindValue(respJson);
    if (!q.exec()) {
        qWarning() << "history-index: insert failed:" << q.lastError().text();
    }
}

HistoryIndex::FullRow HistoryIndex::loadFullRow(int id) const {
    FullRow out;
    QMutexLocker lk(&m_mutex);
    if (!m_db.isOpen()) return out;
    QSqlQuery q(m_db);
    q.prepare("SELECT req_json, resp_json FROM rows WHERE id = ?");
    q.addBindValue(id);
    if (!q.exec() || !q.next()) return out;
    const QJsonDocument req  = QJsonDocument::fromJson(q.value(0).toString().toUtf8());
    const QJsonDocument resp = QJsonDocument::fromJson(q.value(1).toString().toUtf8());
    if (!req.isObject() || !resp.isObject()) return out;
    out.request  = requestFromJson(req.object());
    out.response = responseFromJson(resp.object());
    out.ok = true;
    return out;
}

QString HistoryIndex::loadFullRequestRaw(int id) const {
    const FullRow r = loadFullRow(id);
    return r.ok ? renderRawRequest(r.request) : QString();
}

QString HistoryIndex::loadFullResponseRaw(int id) const {
    const FullRow r = loadFullRow(id);
    return r.ok ? renderRawResponse(r.response) : QString();
}

QList<int> HistoryIndex::allIds() const {
    QMutexLocker lk(&m_mutex);
    QList<int> out;
    if (!m_db.isOpen()) return out;
    QSqlQuery q(m_db);
    if (!q.exec("SELECT id FROM rows ORDER BY id ASC")) return out;
    while (q.next()) out.append(q.value(0).toInt());
    return out;
}

QJsonArray HistoryIndex::find(const QJsonObject &filters) const {
    QMutexLocker lk(&m_mutex);
    QJsonArray out;
    if (!m_db.isOpen()) return out;

    // Build the parameterized SELECT in pure logic (unit-tested for
    // injection-safety + limit clamping). Every operator value is a bound ?.
    // Unreadable numeric filters are DROPPED rather than guessed at (a
    // non-numeric "status" used to bind 0 and match only transport failures).
    // Surface that, so a typo'd filter is not silently answered with the wrong
    // rows. find() returns rows only, with no status channel, so the log is
    // where it goes -- changing the return shape would ripple into the API and UI.
    QStringList ignoredFilters;
    const HistoryLogic::FindQuery fq =
        HistoryLogic::buildFindQuery(filters, &ignoredFilters);
    if (!ignoredFilters.isEmpty()) {
        qWarning() << "history-index: ignoring unreadable filter(s):"
                   << ignoredFilters.join(QStringLiteral(", "));
    }
    QSqlQuery q(m_db);
    q.prepare(fq.sql);
    for (const auto &b : fq.binds) q.addBindValue(b);
    if (!q.exec()) {
        qWarning() << "history-index: find failed:" << q.lastError().text();
        return out;
    }
    while (q.next()) {
        QJsonObject o;
        o["id"]     = q.value(0).toInt();
        o["ts"]     = QString::number(q.value(1).toLongLong());
        o["method"] = q.value(2).toString();
        o["host"]   = q.value(3).toString();
        o["port"]   = q.value(4).toInt();
        o["path"]   = q.value(5).toString();
        o["status"] = q.value(6).toInt();
        o["size"]   = q.value(7).toInt();
        o["tls"]    = (q.value(8).toInt() != 0);
        o["mime"]   = q.value(9).toString();
        out.append(o);
    }
    return out;
}

} // namespace Nullock::Core

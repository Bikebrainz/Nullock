#include "history_index.hpp"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QMutexLocker>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>

namespace Nullock::Core {

HistoryIndex::HistoryIndex(QObject *parent) : QObject(parent) {}
HistoryIndex::~HistoryIndex() { close(); }

bool HistoryIndex::open(const QString &projectDir) {
    close();
    QMutexLocker lk(&m_mutex);
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
    // WAL mode survives concurrent reads / single writer cleanly. The
    // proxy thread writes; the control server thread reads via find().
    pragma.exec("PRAGMA journal_mode=WAL");
    pragma.exec("PRAGMA synchronous=NORMAL");
    return ensureSchema();
}

void HistoryIndex::close() {
    QMutexLocker lk(&m_mutex);
    if (m_db.isOpen()) m_db.close();
    if (!m_connName.isEmpty()) {
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
        "  id      INTEGER PRIMARY KEY,"
        "  ts      INTEGER,"          // epoch ms
        "  method  TEXT NOT NULL,"
        "  host    TEXT NOT NULL,"
        "  port    INTEGER,"
        "  path    TEXT NOT NULL,"
        "  status  INTEGER,"
        "  size    INTEGER,"          // response body size
        "  tls     INTEGER,"          // 0/1
        "  mime    TEXT"
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
}

void HistoryIndex::append(int rowId,
                          const Nullock::Proxy::HttpRequest &req,
                          const Nullock::Proxy::HttpResponse &resp) {
    QMutexLocker lk(&m_mutex);
    if (!m_db.isOpen()) return;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO rows (id, ts, method, host, port, path, status, size, tls, mime) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  ts=excluded.ts, method=excluded.method, host=excluded.host, "
        "  port=excluded.port, path=excluded.path, status=excluded.status, "
        "  size=excluded.size, tls=excluded.tls, mime=excluded.mime");
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
    if (!q.exec()) {
        qWarning() << "history-index: insert failed:" << q.lastError().text();
    }
}

QJsonArray HistoryIndex::find(const QJsonObject &filters) const {
    QMutexLocker lk(&m_mutex);
    QJsonArray out;
    if (!m_db.isOpen()) return out;

    QString sql = "SELECT id, ts, method, host, port, path, status, size, tls, mime "
                  "FROM rows WHERE 1=1";
    QList<QVariant> binds;
    if (filters.contains("method")) {
        sql += " AND UPPER(method) = ?";
        binds << filters.value("method").toString().toUpper();
    }
    if (filters.contains("host")) {
        // Treat as LIKE; user can pass % wildcards or a literal hostname.
        sql += " AND host LIKE ?";
        binds << filters.value("host").toString();
    }
    if (filters.contains("path")) {
        sql += " AND path LIKE ?";
        binds << filters.value("path").toString();
    }
    if (filters.contains("status")) {
        sql += " AND status = ?";
        binds << filters.value("status").toInt();
    }
    if (filters.contains("minSize")) {
        sql += " AND size >= ?";
        binds << static_cast<qint64>(filters.value("minSize").toDouble());
    }
    if (filters.contains("maxSize")) {
        sql += " AND size <= ?";
        binds << static_cast<qint64>(filters.value("maxSize").toDouble());
    }
    if (filters.contains("sinceMs")) {
        sql += " AND ts >= ?";
        binds << static_cast<qint64>(filters.value("sinceMs").toDouble());
    }
    sql += " ORDER BY id DESC";
    int limit = filters.value("limit").toInt(200);
    if (limit <= 0)    limit = 200;
    if (limit > 5000)  limit = 5000;
    sql += " LIMIT ?";
    binds << limit;

    QSqlQuery q(m_db);
    q.prepare(sql);
    for (const auto &b : binds) q.addBindValue(b);
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

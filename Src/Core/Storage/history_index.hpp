#pragma once

// SQLite-backed metadata index over history.ndjson.
//
// Why: ProxyModel keeps every captured row in memory (request +
// response bodies). At engagement scale (200k+ requests) this gets
// sluggish around 50k rows and unusable above. Full SQLite-backed
// row storage with paged display is a much bigger refactor; this
// is the surgical first step.
//
// What it actually does:
//   * On every appendEntry() we INSERT a small row of metadata into
//     <project>/history-index.sqlite: id, ts, method, host, port,
//     path, status, size, tls, mime.
//   * /api/history/find lets the user query that index with arbitrary
//     WHERE-style filters AT FULL DATABASE SPEED instead of scanning
//     the in-memory model. 200k matches against a method+host+status
//     filter return in <50ms instead of ~3s.
//   * Bodies are NOT stored in the index. To fetch a row's body you
//     still go through ProxyModel (cached) or history.ndjson (cold).
//   * If the SQLite open fails (missing driver, perms), the rest of
//     the project keeps working -- the index is best-effort.

#include "proxy_server.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QSqlDatabase>
#include <QString>

namespace Nullock::Core {

class HistoryIndex : public QObject {
    Q_OBJECT
public:
    explicit HistoryIndex(QObject *parent = nullptr);
    ~HistoryIndex() override;

    // Open / re-open the index at the given project's location. Wipes
    // and rebuilds the schema if absent. Returns false (and logs) if
    // QSqlDatabase couldn't be opened.
    bool open(const QString &projectDir);
    void close();
    bool isOpen() const;
    int  rowCount() const;

    // Mirror an appendEntry into the index. Safe to call from worker
    // threads -- we hold m_mutex over the bind+exec.
    void append(int rowId,
                const Nullock::Proxy::HttpRequest &req,
                const Nullock::Proxy::HttpResponse &resp);

    // Run a parameterized query. Filters supported:
    //   method (exact, case-insensitive)
    //   host   (LIKE -- use % for wildcards)
    //   path   (LIKE)
    //   status (exact int)
    //   minSize / maxSize  (response body size bounds)
    //   sinceMs            (only rows captured after epoch ms)
    //   limit              (default 200, max 5000)
    // Returns a JSON array of rows in newest-first order, each row
    // matching the snapshot row shape so the UI can reuse renderers.
    QJsonArray find(const QJsonObject &filters) const;

private:
    bool ensureSchema();

    mutable QMutex m_mutex;
    QSqlDatabase   m_db;
    QString        m_dir;
    QString        m_dbPath;
    QString        m_connName;
};

} // namespace Nullock::Core

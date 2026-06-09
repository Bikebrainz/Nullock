#pragma once

#include "frontend_gui_export.hpp"
#include "proxy_server.hpp"

#include <QAbstractListModel>
#include <QList>

namespace Nullock::FrontEnd {

class FRONTEND_GUI_EXPORT ProxyModel : public QAbstractListModel {
    Q_OBJECT
public:
    enum Roles {
        IdRole = Qt::UserRole + 1,
        HostRole,
        MethodRole,
        UrlRole,
        StatusCodeRole,
        MimeRole,
        ParamsRole,
        TlsRole,
        IpRole,
        TimestampRole,
    };

    explicit ProxyModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void clear();
    Q_INVOKABLE QString requestRawAt(int row) const;
    Q_INVOKABLE QString responseRawAt(int row) const;
    Q_INVOKABLE QString summaryAt(int row) const;
    Q_INVOKABLE QString hostAt(int row) const;
    Q_INVOKABLE int     portAt(int row) const;
    Q_INVOKABLE bool    tlsAt(int row) const;
    // requestAt / responseAt take a WINDOW INDEX (0..rowCount()-1).
    // For ID-based lookup that survives eviction, use requestById /
    // responseById -- those return nullptr when the row has been
    // evicted from the in-memory window, and the control server falls
    // back to HistoryIndex for the full row.
    const Nullock::Proxy::HttpRequest  *requestAt(int row) const;
    const Nullock::Proxy::HttpResponse *responseAt(int row) const;
    const Nullock::Proxy::HttpRequest  *requestById(int id) const;
    const Nullock::Proxy::HttpResponse *responseById(int id) const;
    QString requestRawById(int id) const;
    QString responseRawById(int id) const;

public slots:
    void addResponse(const Nullock::Proxy::HttpRequest &request,
                     const Nullock::Proxy::HttpResponse &response);

    // Bounded in-memory window. Older rows get evicted from the front
    // to keep memory under control on 200k+ row engagements. They stay
    // accessible via /api/history/find + /api/history/full from the
    // SQLite-backed HistoryIndex, which sees the full history.
    // requestAt(row) / responseAt(row) interpret row as a 0-based offset
    // FROM THE START OF HISTORY (i.e. id - 1), not as an index into the
    // current in-memory window -- so callers can still pass `id - 1`
    // and either get a valid pointer (still in window), or nullptr
    // (evicted; control server has to hit HistoryIndex instead).
    void setMaxRowsInMemory(int n);
    int  maxRowsInMemory() const { return m_maxRows; }
    int  firstId() const { return m_firstId; }
    int  lastId()  const { return m_firstId + static_cast<int>(m_entries.size()) - 1; }

private:
    struct Entry {
        int id;
        Nullock::Proxy::HttpRequest request;
        Nullock::Proxy::HttpResponse response;
    };

    static int countParams(const Nullock::Proxy::HttpRequest &request);
    static QString extractMime(const Nullock::Proxy::HttpResponse &response);

    QList<Entry> m_entries;
    int m_nextId  = 1;
    int m_firstId = 1;             // id of m_entries[0]; bumps on eviction
    int m_maxRows = 10'000;        // window cap
};

} // namespace Nullock::FrontEnd

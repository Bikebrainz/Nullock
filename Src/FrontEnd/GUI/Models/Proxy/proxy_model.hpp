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

public slots:
    void addResponse(const Nullock::Proxy::HttpRequest &request,
                     const Nullock::Proxy::HttpResponse &response);

private:
    struct Entry {
        int id;
        Nullock::Proxy::HttpRequest request;
        Nullock::Proxy::HttpResponse response;
    };

    static int countParams(const Nullock::Proxy::HttpRequest &request);
    static QString extractMime(const Nullock::Proxy::HttpResponse &response);

    QList<Entry> m_entries;
    int m_nextId = 1;
};

} // namespace Nullock::FrontEnd

#pragma once

#include "frontend_gui_export.hpp"

#include <QAbstractListModel>
#include <QHash>
#include <QList>
#include <QString>

namespace Nullock::FrontEnd {

class ProxyModel;

// Aggregates unique hosts from ProxyModel with per-host request counts.
// Stays in sync with the source model -- when a new response lands we
// bump the matching host's count (or insert a new row), so the QML side
// just binds to this model and the view updates live.
class FRONTEND_GUI_EXPORT SiteMapModel : public QAbstractListModel {
    Q_OBJECT
public:
    enum Roles {
        HostRole = Qt::UserRole + 1,
        CountRole,
        TlsRole,
    };

    explicit SiteMapModel(ProxyModel *source = nullptr, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void clear();

private slots:
    void onSourceRowsInserted(const QModelIndex &parent, int first, int last);
    void onSourceModelReset();

private:
    struct Entry {
        QString host;
        int     count = 0;
        bool    anyTls = false;
    };

    void rebuild();
    int  indexOfHost(const QString &host) const;

    ProxyModel        *m_source;
    QList<Entry>       m_entries;
    QHash<QString,int> m_lookup; // host -> row index
};

} // namespace Nullock::FrontEnd

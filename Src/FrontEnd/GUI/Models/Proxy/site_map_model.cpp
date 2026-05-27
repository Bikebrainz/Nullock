#include "site_map_model.hpp"
#include "proxy_model.hpp"

namespace Nullock::FrontEnd {

SiteMapModel::SiteMapModel(ProxyModel *source, QObject *parent)
    : QAbstractListModel(parent), m_source(source) {
    if (m_source) {
        connect(m_source, &QAbstractItemModel::rowsInserted,
                this, &SiteMapModel::onSourceRowsInserted);
        connect(m_source, &QAbstractItemModel::modelReset,
                this, &SiteMapModel::onSourceModelReset);
        rebuild();
    }
}

int SiteMapModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(m_entries.size());
}

QVariant SiteMapModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= m_entries.size())
        return {};
    const Entry &e = m_entries[index.row()];
    switch (role) {
        case HostRole:  return e.host;
        case CountRole: return e.count;
        case TlsRole:   return e.anyTls;
        default:        return {};
    }
}

QHash<int, QByteArray> SiteMapModel::roleNames() const {
    return {
        { HostRole,  "host"  },
        { CountRole, "count" },
        { TlsRole,   "tls"   },
    };
}

void SiteMapModel::clear() {
    if (m_entries.isEmpty()) return;
    beginResetModel();
    m_entries.clear();
    m_lookup.clear();
    endResetModel();
}

int SiteMapModel::indexOfHost(const QString &host) const {
    const auto it = m_lookup.constFind(host);
    return it == m_lookup.constEnd() ? -1 : it.value();
}

void SiteMapModel::rebuild() {
    beginResetModel();
    m_entries.clear();
    m_lookup.clear();
    if (m_source) {
        const int n = m_source->rowCount();
        for (int row = 0; row < n; ++row) {
            const QModelIndex idx = m_source->index(row, 0);
            const QString host = m_source->data(idx, ProxyModel::HostRole).toString();
            const bool   tls  = m_source->data(idx, ProxyModel::TlsRole).toBool();
            if (host.isEmpty()) continue;
            const int existing = indexOfHost(host);
            if (existing >= 0) {
                m_entries[existing].count++;
                m_entries[existing].anyTls = m_entries[existing].anyTls || tls;
            } else {
                m_lookup.insert(host, m_entries.size());
                m_entries.append({ host, 1, tls });
            }
        }
    }
    endResetModel();
}

void SiteMapModel::onSourceRowsInserted(const QModelIndex &parent, int first, int last) {
    if (!m_source || parent.isValid()) return;
    for (int row = first; row <= last; ++row) {
        const QModelIndex idx = m_source->index(row, 0);
        const QString host = m_source->data(idx, ProxyModel::HostRole).toString();
        const bool   tls  = m_source->data(idx, ProxyModel::TlsRole).toBool();
        if (host.isEmpty()) continue;
        const int existing = indexOfHost(host);
        if (existing >= 0) {
            m_entries[existing].count++;
            if (tls) m_entries[existing].anyTls = true;
            const QModelIndex changed = index(existing);
            emit dataChanged(changed, changed, { CountRole, TlsRole });
        } else {
            const int newRow = m_entries.size();
            beginInsertRows({}, newRow, newRow);
            m_lookup.insert(host, newRow);
            m_entries.append({ host, 1, tls });
            endInsertRows();
        }
    }
}

void SiteMapModel::onSourceModelReset() {
    rebuild();
}

} // namespace Nullock::FrontEnd

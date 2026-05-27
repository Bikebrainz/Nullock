#include "proxy_filter_model.hpp"
#include "proxy_model.hpp"

namespace Nullock::FrontEnd {

ProxyFilterModel::ProxyFilterModel(QObject *parent)
    : QSortFilterProxyModel(parent), m_statusClass(QStringLiteral("all")) {
    setDynamicSortFilter(true);
}

int ProxyFilterModel::hiddenCount() const {
    if (!sourceModel()) return 0;
    return sourceModel()->rowCount() - rowCount();
}

void ProxyFilterModel::setHostSubstring(const QString &s) {
    if (s == m_hostSubstring) return;
    m_hostSubstring = s;
    invalidateFilter();
    emit filtersChanged();
}

void ProxyFilterModel::setStatusClass(const QString &c) {
    if (c == m_statusClass) return;
    m_statusClass = c;
    invalidateFilter();
    emit filtersChanged();
}

void ProxyFilterModel::setMethodFilter(const QString &m) {
    if (m == m_methodFilter) return;
    m_methodFilter = m;
    invalidateFilter();
    emit filtersChanged();
}

int ProxyFilterModel::sourceRow(int filteredRow) const {
    if (filteredRow < 0 || filteredRow >= rowCount()) return -1;
    return mapToSource(index(filteredRow, 0)).row();
}

void ProxyFilterModel::clearFilters() {
    m_hostSubstring.clear();
    m_statusClass = QStringLiteral("all");
    m_methodFilter.clear();
    invalidateFilter();
    emit filtersChanged();
}

bool ProxyFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const {
    auto *src = sourceModel();
    if (!src) return true;
    const QModelIndex idx = src->index(sourceRow, 0, sourceParent);

    if (!m_hostSubstring.isEmpty()) {
        const QString host = src->data(idx, ProxyModel::HostRole).toString();
        if (!host.contains(m_hostSubstring, Qt::CaseInsensitive)) return false;
    }

    if (m_statusClass != QLatin1String("all") && !m_statusClass.isEmpty()) {
        const int status = src->data(idx, ProxyModel::StatusCodeRole).toInt();
        const int family = status / 100;
        if (m_statusClass == QLatin1String("2xx") && family != 2) return false;
        if (m_statusClass == QLatin1String("3xx") && family != 3) return false;
        if (m_statusClass == QLatin1String("4xx") && family != 4) return false;
        if (m_statusClass == QLatin1String("5xx") && family != 5) return false;
    }

    if (!m_methodFilter.isEmpty()) {
        const QString method = src->data(idx, ProxyModel::MethodRole).toString();
        if (method.compare(m_methodFilter, Qt::CaseInsensitive) != 0) return false;
    }

    return true;
}

} // namespace Nullock::FrontEnd

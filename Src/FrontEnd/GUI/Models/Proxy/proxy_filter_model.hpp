#pragma once

#include "frontend_gui_export.hpp"

#include <QSortFilterProxyModel>
#include <QString>

namespace Nullock::FrontEnd {

// Live-filtered view over ProxyModel. QSortFilterProxyModel handles all the
// row mapping; we just override filterAcceptsRow to apply our three filter
// dimensions. The QML HTTP History binds to *this* model instead of the raw
// ProxyModel so changes to any filter property re-evaluate the visible rows
// immediately.
class FRONTEND_GUI_EXPORT ProxyFilterModel : public QSortFilterProxyModel {
    Q_OBJECT
    Q_PROPERTY(QString hostSubstring READ hostSubstring WRITE setHostSubstring NOTIFY filtersChanged)
    Q_PROPERTY(QString statusClass   READ statusClass   WRITE setStatusClass   NOTIFY filtersChanged)
    Q_PROPERTY(QString methodFilter  READ methodFilter  WRITE setMethodFilter  NOTIFY filtersChanged)
    Q_PROPERTY(int hiddenCount       READ hiddenCount                          NOTIFY filtersChanged)
public:
    explicit ProxyFilterModel(QObject *parent = nullptr);

    QString hostSubstring() const { return m_hostSubstring; }
    QString statusClass() const   { return m_statusClass; }
    QString methodFilter() const  { return m_methodFilter; }
    int     hiddenCount() const;

    void setHostSubstring(const QString &s);
    void setStatusClass(const QString &c);
    void setMethodFilter(const QString &m);

    Q_INVOKABLE void clearFilters();

    // QML helper: turn a row index in our filtered view into the equivalent
    // row index in the underlying ProxyModel so callers can hand it to
    // ProxyModel::requestRawAt / hostAt / etc.
    Q_INVOKABLE int sourceRow(int filteredRow) const;

signals:
    void filtersChanged();

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    QString m_hostSubstring;
    QString m_statusClass;  // "all", "2xx", "3xx", "4xx", "5xx"
    QString m_methodFilter; // empty = all
};

} // namespace Nullock::FrontEnd

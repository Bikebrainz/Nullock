#include "proxy_model.hpp"

namespace Nullock::FrontEnd {

ProxyModel::ProxyModel(QObject *parent)
    : QAbstractListModel(parent) {}

int ProxyModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(m_entries.size());
}

QVariant ProxyModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= m_entries.size())
        return {};

    const Entry &e = m_entries[index.row()];
    switch (role) {
        case IdRole:         return e.id;
        case HostRole:       return e.request.host;
        case MethodRole:     return e.request.method;
        case UrlRole:        return e.request.path;
        case StatusCodeRole: return e.response.statusCode;
        case MimeRole:       return extractMime(e.response);
        case ParamsRole:     return countParams(e.request);
        case TlsRole:        return e.response.wasTls;
        case IpRole:         return e.response.peerAddress;
        case TimestampRole:  return e.request.timestamp.toString("HH:mm:ss.zzz");
        default:             return {};
    }
}

QHash<int, QByteArray> ProxyModel::roleNames() const {
    return {
        { IdRole,         "rowId" },
        { HostRole,       "host" },
        { MethodRole,     "method" },
        { UrlRole,        "url" },
        { StatusCodeRole, "statusCode" },
        { MimeRole,       "mime" },
        { ParamsRole,     "params" },
        { TlsRole,        "tls" },
        { IpRole,         "ip" },
        { TimestampRole,  "timestamp" },
    };
}

void ProxyModel::clear() {
    if (m_entries.isEmpty()) return;
    beginResetModel();
    m_entries.clear();
    m_nextId = 1;
    endResetModel();
}

void ProxyModel::addResponse(const Nullock::Proxy::HttpRequest &request,
                             const Nullock::Proxy::HttpResponse &response) {
    const int row = static_cast<int>(m_entries.size());
    beginInsertRows({}, row, row);
    m_entries.append({ m_nextId++, request, response });
    endInsertRows();
}

int ProxyModel::countParams(const Nullock::Proxy::HttpRequest &request) {
    int count = 0;
    const int q = request.path.indexOf('?');
    if (q >= 0 && q + 1 < request.path.size()) {
        const QString query = request.path.mid(q + 1);
        count += query.count('&') + 1;
    }
    for (const auto &h : request.headers) {
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0
            && h.second.contains("application/x-www-form-urlencoded", Qt::CaseInsensitive)) {
            if (!request.body.isEmpty())
                count += request.body.count('&') + 1;
            break;
        }
    }
    return count;
}

QString ProxyModel::extractMime(const Nullock::Proxy::HttpResponse &response) {
    for (const auto &h : response.headers) {
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) {
            const QString v = h.second;
            const int semi = v.indexOf(';');
            return semi >= 0 ? v.left(semi).trimmed() : v.trimmed();
        }
    }
    return {};
}

} // namespace Nullock::FrontEnd

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
    m_nextId  = 1;
    m_firstId = 1;
    endResetModel();
}

void ProxyModel::setMaxRowsInMemory(int n) {
    m_maxRows = std::max(100, n);
    // Trim immediately if we're now over the new cap.
    while (static_cast<int>(m_entries.size()) > m_maxRows) {
        beginRemoveRows({}, 0, 0);
        m_entries.removeFirst();
        ++m_firstId;
        endRemoveRows();
    }
}

void ProxyModel::addResponse(const Nullock::Proxy::HttpRequest &request,
                             const Nullock::Proxy::HttpResponse &response) {
    const int row = static_cast<int>(m_entries.size());
    beginInsertRows({}, row, row);
    m_entries.append({ m_nextId++, request, response });
    endInsertRows();
    // Window cap. Evict the oldest entry when we'd otherwise grow the
    // in-memory window past m_maxRows. The evicted row stays in
    // history.ndjson + HistoryIndex so /api/history/find and
    // /api/history/full/<id> still see it -- only the live model loses it.
    while (static_cast<int>(m_entries.size()) > m_maxRows) {
        beginRemoveRows({}, 0, 0);
        m_entries.removeFirst();
        ++m_firstId;
        endRemoveRows();
    }
}

const Nullock::Proxy::HttpRequest *ProxyModel::requestById(int id) const {
    if (id < m_firstId) return nullptr;
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return nullptr;
    return &m_entries[idx].request;
}

const Nullock::Proxy::HttpResponse *ProxyModel::responseById(int id) const {
    if (id < m_firstId) return nullptr;
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return nullptr;
    return &m_entries[idx].response;
}

QString ProxyModel::requestRawById(int id) const {
    if (id < m_firstId) return {};
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return {};
    return requestRawAt(idx);
}

QString ProxyModel::responseRawById(int id) const {
    if (id < m_firstId) return {};
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return {};
    return responseRawAt(idx);
}

// host/port/tls resolved by stable finding ID (not window row index). The window
// evicts oldest rows and advances m_firstId, so id-1 is NOT the row index once
// anything has been evicted -- callers that hold an ID (e.g. "send to Repeater")
// must use these, mirroring requestRawById.
QString ProxyModel::hostById(int id) const {
    if (id < m_firstId) return {};
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return {};
    return hostAt(idx);
}
int ProxyModel::portById(int id) const {
    if (id < m_firstId) return 0;
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return 0;
    return portAt(idx);
}
bool ProxyModel::tlsById(int id) const {
    if (id < m_firstId) return false;
    const int idx = id - m_firstId;
    if (idx < 0 || idx >= m_entries.size()) return false;
    return tlsAt(idx);
}

namespace {

constexpr int kMaxBodyPreviewBytes = 64 * 1024;

bool looksTextual(const QString &contentType) {
    if (contentType.startsWith("text/", Qt::CaseInsensitive)) return true;
    if (contentType.contains("json", Qt::CaseInsensitive)) return true;
    if (contentType.contains("javascript", Qt::CaseInsensitive)) return true;
    if (contentType.contains("xml", Qt::CaseInsensitive)) return true;
    if (contentType.contains("html", Qt::CaseInsensitive)) return true;
    if (contentType.contains("x-www-form-urlencoded", Qt::CaseInsensitive)) return true;
    return contentType.isEmpty();
}

QString renderBody(const QByteArray &body,
                   const QList<QPair<QString, QString>> &headers,
                   const QString &headerName) {
    if (body.isEmpty()) return {};
    QString contentType;
    for (const auto &h : headers) {
        if (h.first.compare(headerName, Qt::CaseInsensitive) == 0) {
            contentType = h.second;
            break;
        }
    }
    if (!looksTextual(contentType))
        return QString("[binary %1 bytes, %2]").arg(body.size()).arg(contentType.isEmpty() ? "no content-type" : contentType);

    const QByteArray slice = body.left(kMaxBodyPreviewBytes);
    QString out = QString::fromUtf8(slice);
    if (body.size() > kMaxBodyPreviewBytes)
        out += QString("\n\n[truncated; %1 more bytes]").arg(body.size() - kMaxBodyPreviewBytes);
    return out;
}

} // namespace

QString ProxyModel::requestRawAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return {};
    const Nullock::Proxy::HttpRequest &req = m_entries[row].request;
    QString out;
    out += QString("%1 %2 %3\n").arg(req.method, req.path, req.httpVersion);
    for (const auto &h : req.headers)
        out += QString("%1: %2\n").arg(h.first, h.second);
    out += "\n";
    out += renderBody(req.body, req.headers, "Content-Type");
    return out;
}

QString ProxyModel::responseRawAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return {};
    const Nullock::Proxy::HttpResponse &resp = m_entries[row].response;
    QString out;
    out += QString("%1 %2 %3\n").arg(resp.httpVersion).arg(resp.statusCode).arg(resp.reasonPhrase);
    for (const auto &h : resp.headers)
        out += QString("%1: %2\n").arg(h.first, h.second);
    out += "\n";
    // Render the DECODED body (gzip/deflate inflated by the proxy) so the
    // response view and /api/search see readable content instead of compressed
    // bytes -- like Burp/ZAP, which display the decoded body. Falls back to the
    // raw body when it wasn't compressed.
    out += renderBody(resp.bodyForInspection(), resp.headers, "Content-Type");
    return out;
}

QString ProxyModel::summaryAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return {};
    const Entry &e = m_entries[row];
    return QString("#%1  %2  %3://%4:%5%6  →  %7 %8")
        .arg(e.id)
        .arg(e.request.method)
        .arg(e.response.wasTls ? "https" : "http")
        .arg(e.request.host)
        .arg(e.request.port)
        .arg(e.request.path)
        .arg(e.response.statusCode)
        .arg(e.response.reasonPhrase);
}

QString ProxyModel::hostAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return {};
    return m_entries[row].request.host;
}

int ProxyModel::portAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return 0;
    return m_entries[row].request.port;
}

bool ProxyModel::tlsAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return false;
    return m_entries[row].response.wasTls;
}

const Nullock::Proxy::HttpRequest *ProxyModel::requestAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return nullptr;
    return &m_entries[row].request;
}

const Nullock::Proxy::HttpResponse *ProxyModel::responseAt(int row) const {
    if (row < 0 || row >= m_entries.size()) return nullptr;
    return &m_entries[row].response;
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

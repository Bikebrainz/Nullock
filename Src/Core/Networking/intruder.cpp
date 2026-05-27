#include "intruder.hpp"

#include "Proxy/proxy_model.hpp"

#include <QElapsedTimer>
#include <QMetaObject>
#include <QRegularExpression>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core {

namespace {

// Burp-style position marker: a paired § (U+00A7). The text between the
// two §s is the placeholder for the original/default value; we replace
// the whole match (markers and their content) with the payload.
QRegularExpression markerRegex() {
    static const QRegularExpression rx(QStringLiteral("§[^§]*§"));
    return rx;
}

} // namespace

Intruder::Intruder(Nullock::FrontEnd::ProxyModel *historyModel, QObject *parent)
    : QAbstractListModel(parent), m_model(historyModel) {}

Intruder::~Intruder() {
    stop();
    qDeleteAll(m_attacks);
}

int Intruder::rowCount(const QModelIndex &parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(m_attacks.size());
}

QVariant Intruder::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= m_attacks.size())
        return {};
    const IntruderAttack *a = m_attacks[index.row()];
    switch (role) {
        case IdRole:       return a->m_id;
        case PayloadRole:  return a->m_payload;
        case StatusRole:   return a->m_statusCode;
        case SizeRole:     return a->m_responseSize;
        case TimeRole:     return a->m_elapsedMs;
        case ErrorRole:    return a->m_errorMessage;
        case CompleteRole: return a->m_complete;
        default:           return {};
    }
}

QHash<int, QByteArray> Intruder::roleNames() const {
    return {
        { IdRole,       "rowId"        },
        { PayloadRole,  "payload"      },
        { StatusRole,   "statusCode"   },
        { SizeRole,     "responseSize" },
        { TimeRole,     "elapsedMs"    },
        { ErrorRole,    "errorMessage" },
        { CompleteRole, "complete"     },
    };
}

void Intruder::setHost(const QString &h)     { if (h == m_host) return; m_host = h; emit targetChanged(); }
void Intruder::setPort(int p)                { if (p == m_port) return; m_port = p; emit targetChanged(); }
void Intruder::setUseTls(bool tls) {
    if (tls == m_useTls) return;
    m_useTls = tls;
    if (m_port == 80 && m_useTls)        m_port = 443;
    else if (m_port == 443 && !m_useTls) m_port = 80;
    emit targetChanged();
}
void Intruder::setRequestTemplate(const QString &t) { if (t == m_template) return; m_template = t; emit templateChanged(); }
void Intruder::setPayloads(const QString &p)        { if (p == m_payloads) return; m_payloads = p; emit payloadsChanged(); }

void Intruder::loadFromHistory(int row) {
    if (!m_model) return;
    const QString host = m_model->hostAt(row);
    if (host.isEmpty()) return;
    m_host    = host;
    m_port    = m_model->portAt(row);
    m_useTls  = m_model->tlsAt(row);
    m_template = m_model->requestRawAt(row);
    emit targetChanged();
    emit templateChanged();
}

void Intruder::clear() {
    stop();
    if (m_attacks.isEmpty()) return;
    beginResetModel();
    qDeleteAll(m_attacks);
    m_attacks.clear();
    m_completedCount = 0;
    endResetModel();
    emit progressChanged();
}

void Intruder::stop() {
    if (!m_running) return;
    m_stopRequested = true;
}

void Intruder::start() {
    if (m_running) return;
    if (m_host.isEmpty() || m_template.isEmpty()) return;

    QStringList payloads;
    for (const QString &line : m_payloads.split('\n')) {
        const QString trimmed = line.trimmed();
        if (!trimmed.isEmpty()) payloads.append(trimmed);
    }
    if (payloads.isEmpty()) return;

    // Build the result rows up front so the table populates immediately
    // and each individual attack just has to fill its slot.
    beginResetModel();
    qDeleteAll(m_attacks);
    m_attacks.clear();
    m_completedCount = 0;
    for (int i = 0; i < payloads.size(); ++i) {
        auto *a = new IntruderAttack(this);
        a->m_id = i + 1;
        a->m_payload = payloads[i];
        m_attacks.append(a);
    }
    endResetModel();

    m_running = true;
    m_stopRequested = false;
    emit runningChanged();
    emit progressChanged();

    const QString templateCopy = m_template;
    const QString hostCopy = m_host;
    const int portCopy = m_port;
    const bool tlsCopy = m_useTls;
    QStringList payloadsCopy = payloads;

    (void)QtConcurrent::run([this, payloadsCopy, templateCopy,
                             hostCopy, portCopy, tlsCopy]() {
        runWorker(payloadsCopy, templateCopy, hostCopy, portCopy, tlsCopy);
    });
}

void Intruder::runWorker(const QStringList &payloadsCopy,
                         const QString &templateCopy,
                         const QString &host, int port, bool useTls) {
    HttpClient client;
    const QRegularExpression rx = markerRegex();

    for (int i = 0; i < payloadsCopy.size(); ++i) {
        if (m_stopRequested) break;

        QString req = templateCopy;
        req.replace(rx, payloadsCopy[i]);
        // Normalize line endings for the wire.
        req.replace("\r\n", "\n");
        req.replace("\n", "\r\n");
        if (!req.contains("\r\n\r\n")) req += "\r\n\r\n";

        QElapsedTimer t;
        t.start();
        const auto result = client.send(host, static_cast<quint16>(port),
                                        useTls, req.toUtf8());
        const qint64 elapsedMs = t.elapsed();

        const int row = i;
        const int statusCode = result.ok ? result.parsed.statusCode : 0;
        const int size       = result.parsed.body.size();
        const QString errMsg = result.ok ? QString() : result.errorMessage;

        QMetaObject::invokeMethod(this, [this, row, statusCode, size, elapsedMs, errMsg]() {
            if (row < 0 || row >= m_attacks.size()) return;
            auto *a = m_attacks[row];
            a->m_statusCode = statusCode;
            a->m_responseSize = size;
            a->m_elapsedMs = static_cast<int>(elapsedMs);
            a->m_errorMessage = errMsg;
            a->m_complete = true;
            emit a->changed();
            const QModelIndex idx = index(row);
            emit dataChanged(idx, idx);
            attackFinished(row);
        }, Qt::QueuedConnection);
    }

    QMetaObject::invokeMethod(this, [this]() {
        m_running = false;
        m_stopRequested = false;
        emit runningChanged();
    }, Qt::QueuedConnection);
}

void Intruder::attackFinished(int /*row*/) {
    ++m_completedCount;
    emit progressChanged();
}

} // namespace Nullock::Core

#include "intercept.hpp"

#include <QMetaObject>
#include <QMutexLocker>
#include <QThread>

namespace Nullock::Proxy {

InterceptController::InterceptController(QObject *parent) : QObject(parent) {
    qRegisterMetaType<PendingRequest *>("Nullock::Proxy::PendingRequest*");
}

int InterceptController::queueDepth() const {
    QMutexLocker lk(&m_queueMutex);
    return m_queue.size() + (m_current ? 1 : 0);
}

void InterceptController::setEnabled(bool e) {
    if (e == m_enabled) return;
    m_enabled = e;
    if (!e) releaseAllAsForward();
    emit enabledChanged();
    emit currentChanged();
}

void InterceptController::forward(const QString &editedText) {
    PendingRequest *p = nullptr;
    {
        QMutexLocker lk(&m_queueMutex);
        p = m_current;
    }
    if (!p) return;
    p->m_text = editedText;
    p->decision.storeRelease(0);
    p->done.release();
    QMutexLocker lk(&m_queueMutex);
    promoteNextLocked();
}

void InterceptController::drop() {
    PendingRequest *p = nullptr;
    {
        QMutexLocker lk(&m_queueMutex);
        p = m_current;
    }
    if (!p) return;
    p->decision.storeRelease(1);
    p->done.release();
    QMutexLocker lk(&m_queueMutex);
    promoteNextLocked();
}

void InterceptController::forwardAll() { releaseAllAsForward(); }

void InterceptController::releaseAllAsForward() {
    QList<PendingRequest *> toRelease;
    {
        QMutexLocker lk(&m_queueMutex);
        if (m_current) {
            toRelease.append(m_current);
            m_current = nullptr;
        }
        while (!m_queue.isEmpty()) toRelease.append(m_queue.dequeue());
    }
    for (auto *p : toRelease) {
        p->decision.storeRelease(0);
        p->done.release();
    }
    emit currentChanged();
}

void InterceptController::promoteNextLocked() {
    m_current = m_queue.isEmpty() ? nullptr : m_queue.dequeue();
    emit currentChanged();
}

void InterceptController::addPendingOnMain(PendingRequest *p) {
    QMutexLocker lk(&m_queueMutex);
    if (!m_current) m_current = p;
    else            m_queue.enqueue(p);
    emit currentChanged();
}

void InterceptController::deleteLaterOnMain(PendingRequest *p) {
    if (p) p->deleteLater();
}

InterceptResult InterceptController::pend(const QByteArray &requestBytes,
                                          const QString &host, int port, bool tls) {
    if (!m_enabled) return { false, requestBytes };

    auto *p = new PendingRequest;
    {
        QMutexLocker lk(&m_queueMutex);
        p->m_id = m_nextId++;
    }
    p->m_text = QString::fromUtf8(requestBytes);
    p->m_host = host;
    p->m_port = port;
    p->m_tls  = tls;
    p->moveToThread(this->thread());

    QMetaObject::invokeMethod(this, "addPendingOnMain", Qt::QueuedConnection,
                              Q_ARG(Nullock::Proxy::PendingRequest *, p));

    p->done.acquire();

    InterceptResult r;
    r.dropped = (p->decision.loadAcquire() == 1);
    if (!r.dropped) r.bytes = p->m_text.toUtf8();

    QMetaObject::invokeMethod(this, "deleteLaterOnMain", Qt::QueuedConnection,
                              Q_ARG(Nullock::Proxy::PendingRequest *, p));
    return r;
}

} // namespace Nullock::Proxy

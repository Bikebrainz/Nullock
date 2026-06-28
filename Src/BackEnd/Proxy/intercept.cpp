#include "intercept.hpp"

#include "intercept_logic.hpp"

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
    const int want = e ? 1 : 0;
    if (want == m_enabled.loadAcquire()) return;
    // Publish the new state BEFORE draining, so a worker that reads m_enabled
    // after this point sees the disabled state and auto-forwards via pend().
    m_enabled.storeRelease(want);
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
    {
        QMutexLocker lk(&m_queueMutex);
        promoteNextLocked();
    }
    // Emit AFTER releasing the lock. QML rebinds synchronously on signal
    // emit and reads back queueDepth() which re-acquires m_queueMutex --
    // a recursive lock attempt that deadlocks the main thread.
    emit currentChanged();
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
    {
        QMutexLocker lk(&m_queueMutex);
        promoteNextLocked();
    }
    emit currentChanged();
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
    // Caller already holds m_queueMutex. Do NOT emit currentChanged here:
    // QML's intercept.queueDepth binding evaluates synchronously on the
    // signal and re-acquires the same mutex -> deadlock. Callers emit
    // currentChanged after releasing the lock.
    m_current = m_queue.isEmpty() ? nullptr : m_queue.dequeue();
}

void InterceptController::addPendingOnMain(PendingRequest *p) {
    // Race window: pend() reads m_enabled = true on a worker thread and
    // queues a call to addPendingOnMain; before this slot runs, the user
    // (or a project switch) calls setEnabled(false), which already drained
    // m_queue + m_current. p is still in worker-local scope, so
    // releaseAllAsForward() missed it. Without this re-check, p lands in
    // m_queue while the GUI shows intercept-off; the user can't see or
    // forward it, the worker thread blocks on p->done forever, and the
    // request body (including auth headers / cookies) sits resident in
    // memory until process death. Re-check enabled state under the mutex
    // here -- if the toggle flipped during the race, treat the request as
    // an immediate forward.
    bool releaseAsForward = false;
    {
        QMutexLocker lk(&m_queueMutex);
        const int outstanding = m_queue.size() + (m_current ? 1 : 0);
        if (m_enabled.loadAcquire() == 0) {
            releaseAsForward = true;
        } else if (!InterceptLogic::interceptQueueHasRoom(outstanding)) {
            // Backpressure: the operator is too far behind. Auto-forward (the
            // same operator-visible passthrough used for the disabled race)
            // rather than pin another worker thread + secret-bearing bytes copy
            // without bound. The request still appears in History as normal.
            releaseAsForward = true;
        } else if (!m_current) {
            m_current = p;
        } else {
            m_queue.enqueue(p);
        }
    }
    if (releaseAsForward) {
        p->decision.storeRelease(0);
        p->done.release();
        return;  // no queue change -> no signal needed
    }
    // Emit outside the lock -- same recursive-lock deadlock story as
    // forward() / drop(). Without this fix, a single intercepted
    // request freezes the whole control server.
    emit currentChanged();
}

void InterceptController::deleteLaterOnMain(PendingRequest *p) {
    if (p) p->deleteLater();
}

InterceptResult InterceptController::pend(const QByteArray &requestBytes,
                                          const QString &host, int port, bool tls) {
    if (m_enabled.loadAcquire() == 0) return { false, requestBytes };

    auto *p = new PendingRequest;
    {
        QMutexLocker lk(&m_queueMutex);
        p->m_id = m_nextId++;
    }
    p->m_originalBytes = requestBytes;
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
    // Unedited -> forward the captured bytes verbatim (preserves a binary body
    // byte-for-byte and keeps Content-Length honest); edited -> re-encode.
    if (!r.dropped)
        r.bytes = InterceptLogic::resolveForwardBytes(p->m_originalBytes, p->m_text);

    QMetaObject::invokeMethod(this, "deleteLaterOnMain", Qt::QueuedConnection,
                              Q_ARG(Nullock::Proxy::PendingRequest *, p));
    return r;
}

} // namespace Nullock::Proxy

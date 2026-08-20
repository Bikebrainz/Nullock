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
    // Only drain REQUEST pendings -- a held response must survive a request
    // toggle-off (its own toggle governs it).
    if (!e) releaseKindAsForward(PendingRequest::Request);
    emit enabledChanged();
    emit currentChanged();
}

void InterceptController::setResponsesEnabled(bool e) {
    const int want = e ? 1 : 0;
    if (want == m_enabledResponses.loadAcquire()) return;
    // Same publish-before-drain ordering as setEnabled: a worker that reads
    // m_enabledResponses after this store sees disabled and auto-forwards.
    m_enabledResponses.storeRelease(want);
    if (!e) releaseKindAsForward(PendingRequest::Response);
    emit responsesEnabledChanged();
    emit currentChanged();
}

void InterceptController::setAutoContentLength(bool e) {
    const int want = e ? 1 : 0;
    if (want == m_autoContentLength.loadAcquire()) return;
    // storeRelease so a worker sampling m_autoContentLength in pendImpl after
    // this call sees the new value; no drain needed (this only affects how a
    // future edited request's Content-Length is resolved, not parked messages).
    m_autoContentLength.storeRelease(want);
    emit autoContentLengthChanged();
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
    emit currentChanged();
}

void InterceptController::forwardInterceptingResponse(const QString &editedText) {
    PendingRequest *p = nullptr;
    {
        QMutexLocker lk(&m_queueMutex);
        p = m_current;
    }
    if (!p) return;
    p->m_text = editedText;
    p->holdResponse.storeRelease(1);   // the worker reads this after done.acquire()
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

void InterceptController::releaseKindAsForward(int kind) {
    // Drain only pendings of `kind` (used when that kind's toggle flips off).
    // The other kind's parked messages -- including m_current if it is the
    // other kind -- stay exactly where they are.
    QList<PendingRequest *> toRelease;
    {
        QMutexLocker lk(&m_queueMutex);
        // Rebuild the FIFO keeping the other-kind pendings in order; pull the
        // matching-kind ones out to auto-forward.
        QQueue<PendingRequest *> keep;
        while (!m_queue.isEmpty()) {
            PendingRequest *p = m_queue.dequeue();
            if (p->m_kind == kind) toRelease.append(p);
            else                   keep.enqueue(p);
        }
        m_queue = keep;
        // If the currently-shown pending is this kind, release it and promote
        // the next waiting pending (of whatever kind) into its place.
        if (m_current && m_current->m_kind == kind) {
            toRelease.append(m_current);
            m_current = m_queue.isEmpty() ? nullptr : m_queue.dequeue();
        }
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
        // Re-check the toggle that governs THIS pending's direction under the
        // mutex -- a response pending is gated by m_enabledResponses, a request
        // by m_enabled. (The cap below counts both kinds: it is a total cap on
        // parked worker threads + secret-bearing byte copies, direction-agnostic.)
        const bool kindEnabled = p->m_forceHold   // per-request "intercept this response"
            || ((p->m_kind == PendingRequest::Response)
                    ? (m_enabledResponses.loadAcquire() != 0)
                    : (m_enabled.loadAcquire() != 0));
        if (!kindEnabled) {
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
    // Worker-thread early-out: interception off -> pass the bytes straight
    // through without touching the main thread or allocating a pending.
    if (m_enabled.loadAcquire() == 0) return { false, requestBytes };
    // Intercept match rules decide whether THIS request is held. Copy under the
    // rules mutex (a cheap COW copy), evaluate lock-free. An empty list holds all.
    QVector<InterceptLogic::InterceptRule> reqRules;
    { QMutexLocker lk(&m_rulesMutex); reqRules = m_interceptRules; }
    if (!reqRules.isEmpty()
        && !InterceptLogic::interceptRulesHold(
               reqRules, InterceptLogic::extractRequestFields(requestBytes, host)))
        return { false, requestBytes };
    return pendImpl(requestBytes, host, port, tls, PendingRequest::Request);
}

InterceptResult InterceptController::pendResponse(const QByteArray &responseBytes,
                                                  const QString &host, int port, bool tls,
                                                  bool forceHold) {
    // forceHold ("intercept the response to THIS request") bypasses the global
    // response toggle AND the intercept rules -- the operator asked for this exact
    // response, so neither gate applies.
    if (!forceHold && m_enabledResponses.loadAcquire() == 0) return { false, responseBytes };
    QVector<InterceptLogic::InterceptRule> respRules;
    { QMutexLocker lk(&m_rulesMutex); respRules = m_interceptRules; }
    if (!forceHold && !respRules.isEmpty()
        && !InterceptLogic::interceptRulesHold(
               respRules, InterceptLogic::extractResponseFields(responseBytes, host)))
        return { false, responseBytes };
    return pendImpl(responseBytes, host, port, tls, PendingRequest::Response, forceHold);
}

void InterceptController::setInterceptRules(const QVector<InterceptLogic::InterceptRule> &rules) {
    { QMutexLocker lk(&m_rulesMutex); m_interceptRules = rules; }
    emit interceptRulesChanged();
}

QVector<InterceptLogic::InterceptRule> InterceptController::interceptRules() const {
    QMutexLocker lk(&m_rulesMutex);
    return m_interceptRules;
}

InterceptResult InterceptController::pendImpl(const QByteArray &bytes, const QString &host,
                                              int port, bool tls, int kind, bool forceHold) {
    auto *p = new PendingRequest;
    {
        QMutexLocker lk(&m_queueMutex);
        p->m_id = m_nextId++;
    }
    p->m_kind = kind;
    p->m_forceHold = forceHold;   // set before addPendingOnMain reads it (like m_kind)
    p->m_originalBytes = bytes;
    p->m_text = QString::fromUtf8(bytes);
    p->m_host = host;
    p->m_port = port;
    p->m_tls  = tls;
    p->moveToThread(this->thread());

    QMetaObject::invokeMethod(this, "addPendingOnMain", Qt::QueuedConnection,
                              Q_ARG(Nullock::Proxy::PendingRequest *, p));

    p->done.acquire();

    InterceptResult r;
    r.dropped = (p->decision.loadAcquire() == 1);
    r.holdResponse = (p->holdResponse.loadAcquire() != 0);   // "intercept this response"
    // Unedited -> forward the captured bytes verbatim (preserves a binary body
    // byte-for-byte and keeps Content-Length honest); edited -> re-encode.
    // Identical resolver for requests and responses.
    if (!r.dropped) {
        const InterceptLogic::ForwardResult fr =
            InterceptLogic::resolveForward(p->m_originalBytes, p->m_text);
        r.bytes = fr.bytes;
        // "Update Content-Length" (Burp default ON): when the operator EDITED a
        // REQUEST, bring its Content-Length in line with the new body. Surgical
        // (recomputeContentLength) so a chunked / duplicate-CL smuggling probe is
        // still forwarded verbatim. Response side is intentionally excluded (a
        // HEAD/204/304 carries a CL with an empty body this layer can't tell from
        // a real one). fr.edited is the single source of truth for "was edited".
        if (InterceptLogic::shouldRecomputeContentLength(
                r.dropped, p->m_kind == PendingRequest::Request,
                m_autoContentLength.loadAcquire() != 0, fr.edited))
            r.bytes = InterceptLogic::recomputeContentLength(r.bytes);
    }

    QMetaObject::invokeMethod(this, "deleteLaterOnMain", Qt::QueuedConnection,
                              Q_ARG(Nullock::Proxy::PendingRequest *, p));
    return r;
}

} // namespace Nullock::Proxy

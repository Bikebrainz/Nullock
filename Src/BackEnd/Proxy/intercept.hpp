#pragma once

#include "intercept_logic.hpp"

#include <QAtomicInt>
#include <QByteArray>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QSemaphore>
#include <QString>
#include <QVector>

namespace Nullock::Proxy {

// One in-flight message -- an outbound REQUEST or an upstream RESPONSE --
// that the user can edit / forward / drop.
//
// Ownership moves, so read this before touching it from either side:
//   * The capturing WORKER thread constructs it and fills every field, then
//     moveToThread()s it and hands it over with a queued invokeMethod. That
//     queued call is the happens-before edge publishing those fields.
//   * While the message is parked the MAIN thread owns it, and is the only
//     thread that reads or writes m_text (the QML/control-API `text`).
//   * The worker blocks on `done`. After acquire() it reads `decision` AND
//     m_text (see resolveForwardBytes), and the release/acquire pair on
//     `done` is the ONLY happens-before edge covering that read-back.
// None of these fields is mutex-guarded, so nothing may touch a pending
// after done.release(). (Class name kept as
// PendingRequest for source-compat with the QML/control-API bindings that
// already reference it; a `kind` field distinguishes the two directions.)
class PendingRequest : public QObject {
    Q_OBJECT
    Q_PROPERTY(int id MEMBER m_id CONSTANT)
    Q_PROPERTY(int kind MEMBER m_kind CONSTANT)
    Q_PROPERTY(QString text MEMBER m_text NOTIFY textChanged)
    Q_PROPERTY(QString host MEMBER m_host CONSTANT)
    Q_PROPERTY(int port MEMBER m_port CONSTANT)
    Q_PROPERTY(bool tls MEMBER m_tls CONSTANT)
public:
    // Which half of the round-trip is parked. Surfaced to the control API /
    // GUI as the `kind` field so the intercept view can render + label a
    // request editor vs a response editor. Requests and responses share ONE
    // queue and ONE m_current: the operator resolves them FIFO exactly as
    // Burp does, and forward()/drop() act on whatever is current regardless
    // of kind.
    enum Kind { Request = 0, Response = 1 };

    int     m_id   = 0;
    int     m_kind = Request;
    QString m_text;
    QString m_host;
    int     m_port = 0;
    bool    m_tls  = false;

    // The exact bytes pend()/pendResponse() captured (start line + headers +
    // RAW body). Kept so an unedited forward can return them verbatim instead
    // of re-encoding the lossy QString round-trip (which would mangle any
    // non-UTF-8 body and break Content-Length). Written + read only by the
    // capturing worker thread; the main thread never touches it. See
    // InterceptLogic::resolveForwardBytes.
    QByteArray m_originalBytes;

    QSemaphore done {0};
    QAtomicInt decision {0};  // 0 = forward, 1 = drop
    // Set by forwardInterceptingResponse() on a REQUEST pending: "hold the response
    // to THIS request too", even if the global response toggle is off. Read by the
    // worker in pendImpl after done.acquire() and carried out in InterceptResult.
    QAtomicInt holdResponse {0};
    // Set on the worker (in pendImpl) before addPendingOnMain, read there on the
    // main thread (like m_kind): a force-held RESPONSE pending must NOT be drained
    // by addPendingOnMain's m_enabledResponses re-check. Plain bool -- the queued
    // addPendingOnMain call synchronizes the write, same as m_kind.
    bool       m_forceHold = false;

signals:
    void textChanged();
};

struct InterceptResult {
    bool       dropped = false;
    QByteArray bytes;
    // True when the operator chose "forward + intercept the response to this one".
    // The proxy worker holds the paired response regardless of responsesEnabled().
    bool       holdResponse = false;
};

class InterceptController : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool   enabled          READ enabled          WRITE setEnabled          NOTIFY enabledChanged)
    Q_PROPERTY(bool   responsesEnabled READ responsesEnabled WRITE setResponsesEnabled NOTIFY responsesEnabledChanged)
    Q_PROPERTY(bool   autoContentLength READ autoContentLength WRITE setAutoContentLength NOTIFY autoContentLengthChanged)
    Q_PROPERTY(QObject* current   READ current     NOTIFY currentChanged)
    Q_PROPERTY(int    queueDepth  READ queueDepth  NOTIFY currentChanged)
public:
    explicit InterceptController(QObject *parent = nullptr);

    bool enabled() const { return m_enabled.loadAcquire() != 0; }
    Q_INVOKABLE void setEnabled(bool e);

    // Independent toggle for the RESPONSE direction so enabling response
    // interception does not force request interception (and vice versa) --
    // the operator can hold requests, responses, both, or neither.
    bool responsesEnabled() const { return m_enabledResponses.loadAcquire() != 0; }
    Q_INVOKABLE void setResponsesEnabled(bool e);

    // "Update Content-Length" -- when an operator EDITS an intercepted REQUEST,
    // recompute its Content-Length to match the new body before forwarding (Burp
    // default ON). Surgical: chunked / duplicate-CL requests are still forwarded
    // verbatim so a deliberate desync probe survives (see recomputeContentLength).
    // Read on the per-connection worker in pendImpl, written on the main thread;
    // the QAtomicInt matches the file's m_enabled idiom.
    bool autoContentLength() const { return m_autoContentLength.loadAcquire() != 0; }
    Q_INVOKABLE void setAutoContentLength(bool e);

    QObject *current() const { return m_current; }
    int queueDepth() const;

    Q_INVOKABLE void forward(const QString &editedText);
    // Like forward(), but also flags the CURRENT request pending so the proxy holds
    // the response it comes back with -- Burp's "Do intercept > Response to this
    // request", a per-message opt-in independent of the global response toggle.
    Q_INVOKABLE void forwardInterceptingResponse(const QString &editedText);
    Q_INVOKABLE void drop();
    Q_INVOKABLE void forwardAll();

    // Intercept match rules -- decide which in-scope messages are HELD, in place
    // of the global all-or-nothing toggle. Evaluated in pend()/pendResponse() on
    // worker threads; guarded by m_rulesMutex. An empty list holds everything
    // (interception is still gated by the enabled toggle + scope), matching Burp.
    void setInterceptRules(const QVector<InterceptLogic::InterceptRule> &rules);
    QVector<InterceptLogic::InterceptRule> interceptRules() const;

    // Worker-thread API. Blocks the calling per-connection worker until the
    // operator resolves the message (or until the matching intercept toggle
    // is turned off / the queue overflows, in which case it auto-forwards --
    // the proxy must never deadlock on a parked message). pend() parks an
    // outbound REQUEST before it goes upstream; pendResponse() parks an
    // upstream RESPONSE before it is written back to the client. Both share
    // the same queue + semaphore + main-thread promote machinery.
    InterceptResult pend(const QByteArray &requestBytes,
                         const QString &host, int port, bool tls);
    // forceHold=true holds the response even if the global response toggle is off
    // and regardless of intercept rules -- the per-request "intercept this response"
    // opt-in. The backpressure cap still applies.
    InterceptResult pendResponse(const QByteArray &responseBytes,
                                 const QString &host, int port, bool tls,
                                 bool forceHold = false);

signals:
    void enabledChanged();
    void responsesEnabledChanged();
    void autoContentLengthChanged();
    void currentChanged();
    void interceptRulesChanged();

private slots:
    void addPendingOnMain(Nullock::Proxy::PendingRequest *p);
    void deleteLaterOnMain(Nullock::Proxy::PendingRequest *p);

private:
    // Shared body of pend()/pendResponse(): capture the bytes into a pending
    // of the given kind, hand it to the main thread, block on the semaphore,
    // and resolve the outgoing bytes once the operator (or a drain) releases.
    InterceptResult pendImpl(const QByteArray &bytes, const QString &host,
                             int port, bool tls, int kind, bool forceHold = false);
    void promoteNextLocked();
    void releaseAllAsForward();
    // Auto-forward every parked message of one kind (used when that kind's
    // toggle flips off), leaving the other kind's pendings untouched.
    void releaseKindAsForward(int kind);

    // Atomic: written on the main thread (setEnabled / setResponsesEnabled)
    // and read on per-connection worker threads (pend/pendResponse early-out).
    // Plain-bool here is a data race; the QAtomicInt matches the file's own
    // `decision` idiom. The authoritative drain-race guard remains the
    // under-mutex re-check in addPendingOnMain.
    QAtomicInt                    m_enabled {0};
    QAtomicInt                    m_enabledResponses {0};
    // "Update Content-Length on edit" -- Burp-parity default ON. Main writes
    // (setAutoContentLength), worker reads once in pendImpl after done.acquire().
    QAtomicInt                    m_autoContentLength {1};
    PendingRequest               *m_current = nullptr;
    QQueue<PendingRequest *>      m_queue;
    int                           m_nextId  = 1;
    mutable QMutex                m_queueMutex;
    // Intercept match rules. Copied out under this mutex on the worker thread
    // (pend), evaluated lock-free; set on the main thread. Separate from
    // m_queueMutex so rule eval never contends with the park/promote path.
    QVector<InterceptLogic::InterceptRule> m_interceptRules;
    mutable QMutex                m_rulesMutex;
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::PendingRequest *)

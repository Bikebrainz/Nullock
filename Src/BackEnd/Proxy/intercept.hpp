#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QSemaphore>
#include <QString>

namespace Nullock::Proxy {

// One in-flight request that the user can edit / forward / drop. Owned
// by the InterceptController on the main thread; worker threads only
// touch the semaphore and the atomically-set decision after acquire().
class PendingRequest : public QObject {
    Q_OBJECT
    Q_PROPERTY(int id MEMBER m_id CONSTANT)
    Q_PROPERTY(QString text MEMBER m_text NOTIFY textChanged)
    Q_PROPERTY(QString host MEMBER m_host CONSTANT)
    Q_PROPERTY(int port MEMBER m_port CONSTANT)
    Q_PROPERTY(bool tls MEMBER m_tls CONSTANT)
public:
    int     m_id   = 0;
    QString m_text;
    QString m_host;
    int     m_port = 0;
    bool    m_tls  = false;

    QSemaphore done {0};
    QAtomicInt decision {0};  // 0 = forward, 1 = drop

signals:
    void textChanged();
};

struct InterceptResult {
    bool       dropped = false;
    QByteArray bytes;
};

class InterceptController : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool   enabled     READ enabled     WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(QObject* current   READ current     NOTIFY currentChanged)
    Q_PROPERTY(int    queueDepth  READ queueDepth  NOTIFY currentChanged)
public:
    explicit InterceptController(QObject *parent = nullptr);

    bool enabled() const { return m_enabled; }
    Q_INVOKABLE void setEnabled(bool e);

    QObject *current() const { return m_current; }
    int queueDepth() const;

    Q_INVOKABLE void forward(const QString &editedText);
    Q_INVOKABLE void drop();
    Q_INVOKABLE void forwardAll();

    // Worker-thread API. Blocks until the user resolves (or until intercept
    // is disabled, in which case all pending requests auto-forward).
    InterceptResult pend(const QByteArray &requestBytes,
                         const QString &host, int port, bool tls);

signals:
    void enabledChanged();
    void currentChanged();

private slots:
    void addPendingOnMain(Nullock::Proxy::PendingRequest *p);
    void deleteLaterOnMain(Nullock::Proxy::PendingRequest *p);

private:
    void promoteNextLocked();
    void releaseAllAsForward();

    bool                          m_enabled = false;
    PendingRequest               *m_current = nullptr;
    QQueue<PendingRequest *>      m_queue;
    int                           m_nextId  = 1;
    mutable QMutex                m_queueMutex;
};

} // namespace Nullock::Proxy

Q_DECLARE_METATYPE(Nullock::Proxy::PendingRequest *)

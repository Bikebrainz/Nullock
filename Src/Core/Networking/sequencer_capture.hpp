#pragma once

// Sequencer live-capture engine. Burp's Sequencer "live capture" equivalent:
// fire the SAME request N times, harvest one token from each response, and build
// the corpus the randomness analysis (Sequencer::analyze) then scores.
//
// This is a long-running background job on the PortScanner model: start() returns
// immediately and launches a worker on the QtConcurrent pool; progress is polled
// via snapshot() (counters only, cheap) and the harvested corpus is fetched once
// via tokens(). It is cooperatively cancellable (stop()) and the worker is
// stop-joined in the destructor so it never outlives the engine.
//
// Safety is the point of a tool that auto-issues traffic: the shot count is hard
// capped, pacing is bounded, a run of failures trips a circuit breaker, and the
// CALLER (the control endpoint) enforces the engagement-scope gate before start.
// All the decision logic lives in sequencer_capture_logic.* (pure, unit-tested).

#include "sequencer_capture_logic.hpp"

#include <QAtomicInt>
#include <QByteArray>
#include <QFuture>
#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

class SequencerCapture : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY runningChanged)
public:
    explicit SequencerCapture(QObject *parent = nullptr) : QObject(parent) {}
    ~SequencerCapture() override;   // stop-join: the capture worker must not outlive us

    // Hard fanout cap -- a live-capture auto-issues this many requests, so an
    // unbounded count is a self-inflicted DoS. 10000 is well past the Sequencer's
    // statistical needs (~100-1000 tokens) yet bounded.
    static constexpr int kMaxTokens       = 10000;
    // Abort after this many CONSECUTIVE transport/5xx failures (target down / WAF
    // tripped) rather than burning all N shots.
    static constexpr int kConsecFailAbort = 10;
    // Cap a 429 Retry-After backoff so a hostile "Retry-After: 999999" can't stall.
    static constexpr int kRetryAfterCapMs = 60000;

    struct Request {
        QByteArray request;   // raw HTTP/1.1 bytes, fired verbatim each shot
        QString    host;
        int        port = 443;
        bool       tls  = true;
        int        extractFrom = SequencerCaptureLogic::FromCookie;
        QString    extractKey;
        int        count = 0;        // clamped to [0, kMaxTokens]
        int        throttleMs = 0;   // clamped to [0, 60000]
    };

    bool running() const { return m_running.loadAcquire() != 0; }

    // Launch a background capture. Returns false (with *err set) if one is already
    // running or the request is unusable (empty host/request, count clamps to 0).
    // The scope gate + self-port guard are the CALLER's responsibility (they need
    // the proxy/project-store the engine doesn't hold).
    Q_INVOKABLE bool start(const Request &req, QString *err = nullptr);
    Q_INVOKABLE void stop();    // cooperative: sets the atomic stop flag
    Q_INVOKABLE void clear();   // reset counters + corpus (only when idle)

    // Live counters (mutex/atomic guarded). NO tokens -- keeps a 250ms poll cheap
    // even for a large capture. Fields: running, host, done, total, harvested,
    // emptyExtract, httpErrors, transportErrors, lastStatus, error.
    QJsonObject snapshot() const;
    // The harvested corpus, fetched once on completion. Mutex-guarded copy.
    QStringList tokens() const;

signals:
    void runningChanged();
    void progressChanged();

private:
    void run(Request req);          // worker body -- runs on a QtConcurrent pool thread
    void interruptibleSleep(int ms);

    mutable QMutex m_mutex;         // guards m_host / m_error / m_tokens
    QAtomicInt m_running         { 0 };
    QAtomicInt m_stop            { 0 };
    QAtomicInt m_done            { 0 };
    QAtomicInt m_total           { 0 };
    QAtomicInt m_harvested       { 0 };
    QAtomicInt m_emptyExtract    { 0 };
    QAtomicInt m_httpErrors      { 0 };
    QAtomicInt m_transportErrors { 0 };
    QAtomicInt m_lastStatus      { 0 };
    QString       m_host;
    QString       m_error;
    QStringList   m_tokens;
    QFuture<void> m_worker;         // joined in ~SequencerCapture()
};

} // namespace Nullock::Core

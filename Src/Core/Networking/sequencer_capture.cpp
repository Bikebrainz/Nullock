// Sequencer live-capture engine (see sequencer_capture.hpp). The QObject that
// drives the real HttpClient loop; every decision it makes is in the pure,
// unit-tested sequencer_capture_logic.*.

#include "sequencer_capture.hpp"

#include "chain_runner.hpp"          // normalizeContentLength (fix a stale Content-Length)
#include "networking.hpp"            // HttpClient
#include "session_rules_logic.hpp"   // findHeader (Retry-After)

#include <QThread>
#include <QtConcurrent>

#include <algorithm>

namespace Nullock::Core {

namespace SCL = Nullock::Core::SequencerCaptureLogic;

SequencerCapture::~SequencerCapture() {
    m_stop.storeRelease(1);
    if (m_worker.isRunning()) m_worker.waitForFinished();
}

bool SequencerCapture::start(const Request &reqIn, QString *err) {
    if (m_running.loadAcquire() != 0) {
        if (err) *err = QStringLiteral("a capture is already running");
        return false;
    }
    // m_running flips to 0 INSIDE the worker just before it returns, so a caller
    // that starts a new capture the instant the snapshot reads running=false can
    // race the previous worker's tail (which still holds the mutex and could
    // append one last token). Join that finished-but-not-returned worker before
    // resetting state, so the old and new corpora never mix.
    if (m_worker.isRunning()) m_worker.waitForFinished();

    Request req = reqIn;
    if (req.host.trimmed().isEmpty() || req.request.isEmpty()) {
        if (err) *err = QStringLiteral("empty host or request");
        return false;
    }
    req.count      = SCL::clampCaptureCount(req.count, kMaxTokens);
    req.throttleMs = SCL::clampThrottleMs(req.throttleMs);
    if (req.count <= 0) {
        if (err) *err = QStringLiteral("count must be between 1 and %1").arg(kMaxTokens);
        return false;
    }

    {
        QMutexLocker lk(&m_mutex);
        m_tokens.clear();
        m_error.clear();
        m_host = req.host;
    }
    m_stop.storeRelease(0);
    m_done.storeRelease(0);
    m_total.storeRelease(req.count);
    m_harvested.storeRelease(0);
    m_emptyExtract.storeRelease(0);
    m_httpErrors.storeRelease(0);
    m_transportErrors.storeRelease(0);
    m_lastStatus.storeRelease(0);
    m_running.storeRelease(1);
    emit runningChanged();

    m_worker = QtConcurrent::run([this, req] { run(req); });
    return true;
}

void SequencerCapture::stop() { m_stop.storeRelease(1); }

void SequencerCapture::clear() {
    if (m_running.loadAcquire() != 0) return;   // never wipe a live capture
    // Same tail-race as start(): join a just-finished worker so it can't append
    // after we clear.
    if (m_worker.isRunning()) m_worker.waitForFinished();
    {
        QMutexLocker lk(&m_mutex);
        m_tokens.clear();
        m_error.clear();
        m_host.clear();
    }
    m_done.storeRelease(0);
    m_total.storeRelease(0);
    m_harvested.storeRelease(0);
    m_emptyExtract.storeRelease(0);
    m_httpErrors.storeRelease(0);
    m_transportErrors.storeRelease(0);
    m_lastStatus.storeRelease(0);
    emit progressChanged();
}

void SequencerCapture::interruptibleSleep(int ms) {
    // Sleep in small chunks so stop() / app shutdown is honored within ~50ms even
    // for a long 429 backoff, instead of blocking waitForFinished() for minutes.
    constexpr int kChunkMs = 50;
    int slept = 0;
    while (slept < ms && m_stop.loadAcquire() == 0) {
        const int step = std::min(kChunkMs, ms - slept);
        QThread::msleep(static_cast<unsigned long>(step));
        slept += step;
    }
}

void SequencerCapture::run(Request req) {
    // ONE HttpClient, constructed HERE on the pool thread so its sockets take this
    // thread's affinity; reused across every shot (send() retires its socket each
    // call, so N iterations don't accumulate descriptors).
    HttpClient client;
    const QByteArray reqBytes = ChainRunner::normalizeContentLength(req.request);

    const int total = m_total.loadAcquire();
    int consecFail = 0;

    for (int i = 0; i < total; ++i) {
        if (m_stop.loadAcquire() != 0) break;

        const auto res = client.send(req.host, static_cast<quint16>(req.port),
                                     req.tls, reqBytes);
        int status = 0;
        QString token;
        if (res.ok) {
            status = res.parsed.statusCode;
            m_lastStatus.storeRelease(status);
            // Extract over the DECODED body (bodyForInspection): a gzip response
            // would otherwise silently yield empty tokens on every shot. Raw, un-
            // sanitized -- the token is an analysis sample, never re-sent.
            token = SCL::extractToken(req.extractFrom, req.extractKey, status,
                                      res.parsed.headers, res.parsed.bodyForInspection());
        }

        const auto cls = SCL::classifyShot(res.ok, status, token.isEmpty());
        switch (cls) {
            case SCL::ShotToken:
                { QMutexLocker lk(&m_mutex); m_tokens.append(token); }
                m_harvested.fetchAndAddRelaxed(1);
                consecFail = 0;
                break;
            case SCL::ShotEmptyExtract:
                // A valid response that just didn't match the extractor -- a config
                // issue, not a target-down signal, so it doesn't feed the breaker.
                m_emptyExtract.fetchAndAddRelaxed(1);
                consecFail = 0;
                break;
            case SCL::ShotHttpError:
                m_httpErrors.fetchAndAddRelaxed(1);
                ++consecFail;
                break;
            case SCL::ShotTransportError:
                m_transportErrors.fetchAndAddRelaxed(1);
                ++consecFail;
                break;
        }

        const int done = m_done.fetchAndAddRelaxed(1) + 1;
        // Emit periodically (every 8th) + always on the last shot, so a fast
        // capture doesn't flood the cross-thread signal queue.
        if ((done & 0x7) == 0 || done == total) emit progressChanged();

        if (SCL::circuitTripped(consecFail, kConsecFailAbort)) {
            QMutexLocker lk(&m_mutex);
            m_error = QStringLiteral("aborted after %1 consecutive failures "
                                     "(target unreachable or blocking)").arg(consecFail);
            break;
        }

        // Pace the next shot: the larger of the user's throttle and a 429
        // Retry-After (bounded + interruptible). Skip after the final shot.
        if (i + 1 < total && m_stop.loadAcquire() == 0) {
            int waitMs = req.throttleMs;
            if (res.ok && status == 429) {
                const QString ra = SessionRulesLogic::findHeader(res.parsed.headers, "Retry-After");
                waitMs = std::max(waitMs, SCL::retryAfterMs(ra, kRetryAfterCapMs));
            }
            if (waitMs > 0) interruptibleSleep(waitMs);
        }
    }

    m_running.storeRelease(0);
    emit progressChanged();
    emit runningChanged();
}

QJsonObject SequencerCapture::snapshot() const {
    QMutexLocker lk(&m_mutex);
    return QJsonObject{
        { "running",         m_running.loadAcquire() != 0 },
        { "host",            m_host },
        { "done",            m_done.loadAcquire() },
        { "total",           m_total.loadAcquire() },
        { "harvested",       m_harvested.loadAcquire() },
        { "emptyExtract",    m_emptyExtract.loadAcquire() },
        { "httpErrors",      m_httpErrors.loadAcquire() },
        { "transportErrors", m_transportErrors.loadAcquire() },
        { "lastStatus",      m_lastStatus.loadAcquire() },
        { "error",           m_error },
    };
}

QStringList SequencerCapture::tokens() const {
    QMutexLocker lk(&m_mutex);
    return m_tokens;
}

} // namespace Nullock::Core

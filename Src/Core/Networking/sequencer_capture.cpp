// Sequencer live-capture engine (see sequencer_capture.hpp). The QObject that
// drives the real HttpClient loop; every decision it makes is in the pure,
// unit-tested sequencer_capture_logic.*.

#include "sequencer_capture.hpp"

#include "chain_runner.hpp"          // normalizeContentLength (fix a stale Content-Length)
#include "networking.hpp"            // HttpClient
#include "session_rules_logic.hpp"   // findHeader (Retry-After)

#include <QJsonArray>
#include <QThread>
#include <QtConcurrent/QtConcurrent>   // module-qualified: bare <QtConcurrent> won't resolve on Linux/GCC

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
    if (req.host.trimmed().isEmpty() || req.request.isEmpty() || req.port < 1 || req.port > 65535) {
        if (err) *err = QStringLiteral("empty host or request");
        return false;
    }
    if (req.request.size() > 1024 * 1024 || req.extractKey.size() > 1024 * 1024) {
        if (err) *err = "Capture request or extraction key exceeds the workspace limit";
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
        m_tokenCharacters = 0;
        m_cookieNames.clear();
        m_error.clear();
        m_host = req.host;
        m_draft["capHost"] = req.host; m_draft["capPort"] = req.port;
        m_draft["capTls"] = req.tls; m_draft["capRequest"] = QString::fromUtf8(req.request);
        m_draft["capCount"] = req.count; m_draft["capThrottleMs"] = req.throttleMs;
        const QStringList modes{"header", "cookie", "json", "regex", "status", "delimiter"};
        m_draft["capExtractFrom"] = modes.value(req.extractFrom, "header");
        m_draft["capExtractKey"] = req.extractKey;
        if (req.extractFrom == SCL::FromDelimiter) {
            m_draft["capDelimStart"] = req.extractKey.section(QChar(0x1f), 0, 0);
            m_draft["capDelimEnd"] = req.extractKey.section(QChar(0x1f), 1);
        }
        ++m_revision;
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
        m_tokenCharacters = 0;
        m_cookieNames.clear();
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

            // Track distinct Set-Cookie NAMES seen this run (not values), so the
            // UI can offer a live "cookies seen" picker instead of a blind
            // free-text key -- independent of extractFrom, so a capture started
            // in Header/JSON/Regex mode still builds a usable cookie list if the
            // response happens to set one.
            for (const auto &h : res.parsed.headers) {
                if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
                const QString name = SCL::cookieNameFromSetCookie(h.second);
                if (name.isEmpty()) continue;
                QMutexLocker lk(&m_mutex);
                if (!m_cookieNames.contains(name) && m_cookieNames.size() < kMaxCookieNames)
                    m_cookieNames.append(name);
            }
        }

        const auto cls = SCL::classifyShot(res.ok, status, token.isEmpty());
        switch (cls) {
            case SCL::ShotToken:
                { QMutexLocker lk(&m_mutex);
                  QString corpus = m_draft.value("text").toString();
                  if (m_tokenCharacters + token.size() > 4 * 1024 * 1024
                      || corpus.size() + token.size() + 1 > 4 * 1024 * 1024) {
                      m_error = "Capture corpus reached its size limit; export or clear the capture";
                      m_stop.storeRelease(1); break;
                  }
                  if (!corpus.isEmpty() && !corpus.endsWith('\n')) corpus += '\n';
                  m_draft["text"] = corpus + token;
                  m_tokens.append(token); m_tokenCharacters += token.size();
                  ++m_revision; ++m_textRevision;
                }
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
        { "revision",        m_revision },
        { "textRevision",    m_textRevision },
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
        { "cookieNames",     QJsonArray::fromStringList(m_cookieNames) },
    };
}

QStringList SequencerCapture::tokens() const {
    QMutexLocker lk(&m_mutex);
    return m_tokens;
}

QJsonObject SequencerCapture::exportState() const {
    auto capture = snapshot();
    QMutexLocker lk(&m_mutex);
    capture["harvested"] = m_tokens.size();
    return {{"version", 1}, {"draft", m_draft}, {"capture", capture},
            {"revision", m_revision}, {"textRevision", m_textRevision},
            {"tokens", QJsonArray::fromStringList(m_tokens)}};
}

void SequencerCapture::importState(const QJsonObject &state) {
    if (running()) return;
    clear();
    {
        QMutexLocker lk(&m_mutex);
        m_draft = state.value("draft").toObject();
        for (const auto &v : state.value("tokens").toArray()) { m_tokens.append(v.toString()); m_tokenCharacters += v.toString().size(); }
        const auto c = state.value("capture").toObject();
        m_host = c.value("host").toString();
        m_error = c.value("running").toBool() ? "Capture interrupted; restored idle. Start explicitly to collect more samples." : c.value("error").toString();
        m_done.storeRelease(c.value("done").toInt());
        m_total.storeRelease(c.value("total").toInt());
        m_harvested.storeRelease(m_tokens.size());
        m_emptyExtract.storeRelease(c.value("emptyExtract").toInt());
        m_httpErrors.storeRelease(c.value("httpErrors").toInt());
        m_transportErrors.storeRelease(c.value("transportErrors").toInt());
        m_lastStatus.storeRelease(c.value("lastStatus").toInt());
        for (const auto &v : c.value("cookieNames").toArray()) if (m_cookieNames.size() < kMaxCookieNames) m_cookieNames.append(v.toString());
        ++m_revision; ++m_textRevision;
    }
    emit progressChanged();
}

bool SequencerCapture::patchDraft(const QJsonObject &patch, qint64 textRevision, QString *error) {
    {
        QMutexLocker lk(&m_mutex);
        if (patch.contains("text") && textRevision != m_textRevision) {
            *error = "Token text changed in another client or capture. Copy your edit before reloading the saved corpus.";
            return false;
        }
        auto draft = m_draft;
        for (auto it = patch.begin(); it != patch.end(); ++it) {
            const QString key = it.key(); const auto value = it.value();
            bool valid = false;
            if (key == "capTls") valid = value.isBool();
            else if (key == "sigLevel") valid = value.isDouble() && value.toDouble() >= 0.000001 && value.toDouble() <= 0.2;
            else if (key == "capPort" || key == "capCount" || key == "capThrottleMs") {
                const double n = value.toDouble(-1);
                valid = value.isDouble() && n == value.toInt(-1) && n >= 0
                    && n <= (key == "capPort" ? 65535 : key == "capCount" ? kMaxTokens : 60000);
            } else if (key == "text" || key == "capHost" || key == "capRequest" || key == "capExtractFrom"
                       || key == "capExtractKey" || key == "capDelimStart" || key == "capDelimEnd")
                valid = value.isString() && value.toString().size() <= (key == "text" ? 4 : 1) * 1024 * 1024;
            if (!valid) { *error = "Invalid Sequencer field: " + key; return false; }
            draft[key] = value;
        }
        m_draft = draft;
        ++m_revision;
        if (patch.contains("text")) ++m_textRevision;
    }
    emit progressChanged();
    return true;
}

bool SequencerCapture::appendText(const QString &text, QString *error) {
    {
        QMutexLocker lk(&m_mutex);
        QString corpus = m_draft.value("text").toString();
        if (corpus.size() + text.size() + 1 > 4 * 1024 * 1024) {
            *error = "Sequencer corpus reached its 4 MiB character limit; export or clear it before adding samples";
            return false;
        }
        if (!corpus.isEmpty() && !corpus.endsWith('\n')) corpus += '\n';
        m_draft["text"] = corpus + text;
        ++m_revision; ++m_textRevision;
    }
    emit progressChanged();
    return true;
}

} // namespace Nullock::Core

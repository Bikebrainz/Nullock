#include "intruder.hpp"

#include "session_rules.hpp"

#include "intruder_engine.hpp"
#include "intruder_pool_logic.hpp"
#include "Proxy/proxy_model.hpp"

#include <QElapsedTimer>
#include <QMetaObject>
#include <QSemaphore>
#include <QThread>
#include <QtConcurrent/QtConcurrent>

namespace Nullock::Core {

namespace IE = Nullock::Core::IntruderEngine;

namespace {

// Split a newline-separated payload block into trimmed, non-empty entries.
QStringList parseSet(const QString &block) {
    QStringList out;
    for (const QString &line : block.split('\n')) {
        const QString trimmed = line.trimmed();
        if (!trimmed.isEmpty()) out.append(trimmed);
    }
    return out;
}

// Per-position display values for a result row -- engine nulls (a marker left
// at its default, e.g. Sniper's non-active positions) render as "(default)".
QStringList displayValues(const QStringList &combo) {
    QStringList out;
    out.reserve(combo.size());
    for (const QString &v : combo)
        out.append(v.isNull() ? QStringLiteral("(default)") : v);
    return out;
}

// Thread each NON-null payload value through the processing rule chain before it
// reaches the request. A null value means "leave this marker at its default" and
// must never be transformed. No rules -> the combo is returned unchanged.
QStringList applyRulesToCombo(const QStringList &combo,
                              const QList<IntruderRules::Rule> &rules) {
    if (rules.isEmpty()) return combo;
    QStringList out;
    out.reserve(combo.size());
    for (const QString &v : combo)
        out.append(v.isNull() ? v : IntruderRules::applyRules(v, rules));
    return out;
}

// Flatten a response into the single text the grep engine scans: the header
// lines first (so a token in Set-Cookie / Location is caught), a blank line,
// then the DECODED body (bodyForInspection, never the raw compressed bytes).
// IntruderGrep bounds this to kMaxScan internally, so a huge body is safe.
QString grepScanText(const Nullock::Proxy::HttpResponse &resp) {
    QString s;
    for (const auto &h : resp.headers) {
        s += h.first;
        s += QLatin1String(": ");
        s += h.second;
        s += QLatin1Char('\n');
    }
    s += QLatin1Char('\n');
    s += QString::fromUtf8(resp.bodyForInspection());
    return s;
}

// Compute matched/extracted for one response. Skips all work (and the scan-text
// build) when neither column is configured. Safe to call off the GUI thread --
// it's pure and bounded (see IntruderGrep). `resp` is the parsed response.
void computeGrep(const Nullock::Proxy::HttpResponse &resp,
                 const QStringList &needles,
                 const QStringList &combo,
                 bool reflectionOn,
                 const IntruderGrep::ExtractSpec &spec,
                 bool &matchedOut, bool &reflectedOut, QString &extractedOut) {
    const bool wantMatch = !needles.isEmpty();
    const bool wantExtract =
        !spec.regex.isEmpty() || !spec.start.isEmpty() || !spec.end.isEmpty();
    const bool wantReflected = reflectionOn && !combo.isEmpty();
    matchedOut = false;
    reflectedOut = false;
    extractedOut.clear();
    if (!wantMatch && !wantExtract && !wantReflected) return;
    const QString scan = grepScanText(resp);
    if (wantMatch)   matchedOut   = IntruderGrep::grepMatch(scan, needles);
    if (wantExtract) extractedOut = IntruderGrep::grepExtract(scan, spec);
    if (wantReflected) {
        // Flag the row if ANY of its submitted payloads echoes literally in the
        // response. Null combo entries are "leave the marker at its default" and
        // aren't a submitted payload, so they're skipped.
        for (const QString &p : combo) {
            if (!p.isNull() && IntruderGrep::payloadReflected(scan, p)) {
                reflectedOut = true;
                break;
            }
        }
    }
}

// Wait `totalMs`, abandoning the wait the moment `stop` is set. QThread::msleep
// is uninterruptible, so both waits in an attack -- the inter-dispatch throttle
// (up to kMaxThrottleMs = 60s) and the per-request 429 Retry-After back-off (up
// to 59s) -- ignored a stop() request entirely. Since ~Intruder sets the flag and
// then waits on the worker, that also meant application shutdown hung for the
// same duration. See IntruderPool::sleepSliceMs.
void interruptibleSleep(int totalMs, const std::atomic<bool> &stop) {
    int remaining = totalMs;
    while (remaining > 0 && !stop.load()) {
        const int slice = IntruderPool::sleepSliceMs(remaining);
        if (slice <= 0) break;
        QThread::msleep(static_cast<unsigned long>(slice));
        remaining -= slice;
    }
}

} // namespace

Intruder::Intruder(Nullock::FrontEnd::ProxyModel *historyModel, QObject *parent)
    : QAbstractListModel(parent), m_model(historyModel) {}

Intruder::~Intruder() {
    // Stop-join. Both the attack worker and any in-flight resend worker capture
    // `this` and reach back into m_attacks (via a queued call, and the attack
    // worker also reads m_stopRequested directly). Signal stop, then block until
    // both have fully returned BEFORE qDeleteAll frees the rows they index --
    // otherwise a shutdown mid-attack is a use-after-free.
    m_stopRequested.store(true);
    if (m_worker.isRunning())       m_worker.waitForFinished();
    if (m_resendWorker.isRunning()) m_resendWorker.waitForFinished();
    // m_worker only returns after it has waited on the pool, but wait again here
    // as a belt-and-suspenders join: no request task may still touch m_attacks
    // once we start freeing the rows below.
    m_pool.waitForDone();
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
        case PayloadsRole: return a->m_payloadValues;
        case StatusRole:   return a->m_statusCode;
        case SizeRole:     return a->m_responseSize;
        case TimeRole:     return a->m_elapsedMs;
        case ErrorRole:    return a->m_errorMessage;
        case CompleteRole: return a->m_complete;
        case MatchedRole:  return a->m_matched;
        case ReflectedRole:return a->m_reflected;
        case ExtractedRole:return a->m_extracted;
        default:           return {};
    }
}

QHash<int, QByteArray> Intruder::roleNames() const {
    return {
        { IdRole,       "rowId"        },
        { PayloadRole,  "payload"      },
        { PayloadsRole, "payloads"     },
        { StatusRole,   "statusCode"   },
        { SizeRole,     "responseSize" },
        { TimeRole,     "elapsedMs"    },
        { ErrorRole,    "errorMessage" },
        { CompleteRole, "complete"     },
        { MatchedRole,  "matched"      },
        { ReflectedRole,"reflected"    },
        { ExtractedRole,"extracted"    },
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

void Intruder::setPayloads(const QString &p) {
    if (!m_payloadSets.isEmpty() && m_payloadSets.constFirst() == p) return;
    if (m_payloadSets.isEmpty()) m_payloadSets.append(p);
    else                         m_payloadSets[0] = p;
    emit payloadsChanged();
}

void Intruder::setPayloadSets(const QStringList &s) {
    if (s == m_payloadSets) return;
    m_payloadSets = s;
    emit payloadsChanged();
}

void Intruder::setAttackType(int t) {
    if (t < Sniper || t > ClusterBomb || t == m_attackType) return;
    m_attackType = t;
    emit attackTypeChanged();
}

void Intruder::setPayloadRules(const QList<IntruderRules::Rule> &rules) {
    m_payloadRules = rules;
}

void Intruder::setGlobalEncodeChars(const QString &chars) {
    m_globalEncodeChars = chars;
}

void Intruder::setGrepPayloadReflection(bool on) {
    m_grepPayloadReflection = on;
}

void Intruder::setGrepMatch(const QStringList &needles) {
    m_grepMatch = needles;
}

void Intruder::setGrepExtract(const IntruderGrep::ExtractSpec &spec) {
    m_grepExtract = spec;
}

void Intruder::setMaxConcurrency(int n) {
    m_maxConcurrency = IntruderPool::clampConcurrency(n);
}

void Intruder::setThrottleMs(int ms) {
    m_throttleMs = IntruderPool::clampThrottleMs(ms);
}

int Intruder::positionCount() const {
    return IE::countMarkers(m_template);
}

QString Intruder::payloadSetAt(int i) const {
    return (i >= 0 && i < m_payloadSets.size()) ? m_payloadSets[i] : QString();
}

void Intruder::setPayloadSetAt(int i, const QString &v) {
    if (i < 0) return;
    while (m_payloadSets.size() <= i) m_payloadSets.append(QString());
    if (m_payloadSets[i] == v) return;
    m_payloadSets[i] = v;
    emit payloadsChanged();
}

void Intruder::syncSetsToPositions() {
    const int want = qMax(1, positionCount());
    if (m_payloadSets.size() == want) return;
    while (m_payloadSets.size() < want) m_payloadSets.append(QString());
    while (m_payloadSets.size() > want) m_payloadSets.removeLast();
    emit payloadsChanged();
}

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

QByteArray Intruder::saveRun() const {
    IntruderPersist::SavedRun run;
    IntruderPersist::RunConfig &c = run.config;
    c.host            = m_host;
    c.port            = m_port;
    c.tls             = m_useTls;
    c.requestTemplate = m_template;
    c.attackType      = m_attackType;
    c.payloadSets     = m_payloadSets;
    c.rules           = m_payloadRules;
    c.grepMatch       = m_grepMatch;
    c.grepPayloadReflection = m_grepPayloadReflection;
    c.grepExtract     = m_grepExtract;
    c.concurrency     = m_maxConcurrency;
    c.throttleMs      = m_throttleMs;

    for (const IntruderAttack *a : m_attacks) {
        IntruderPersist::ResultRow r;
        r.id            = a->m_id;
        r.payloadValues = a->m_payloadValues;
        r.combo         = a->m_combo;          // raw combo, nulls included
        r.statusCode    = a->m_statusCode;
        r.responseSize  = a->m_responseSize;
        r.elapsedMs     = a->m_elapsedMs;
        r.errorMessage  = a->m_errorMessage;
        r.complete      = a->m_complete;
        r.matched       = a->m_matched;
        r.reflected     = a->m_reflected;
        r.extracted     = a->m_extracted;
        run.rows.append(r);
    }
    return IntruderPersist::toBytes(run);
}

bool Intruder::loadRun(const QByteArray &bytes) {
    // Never clobber a live attack -- the worker is mid-flight over m_attacks.
    if (m_running) return false;

    const IntruderPersist::SavedRun run = IntruderPersist::fromBytes(bytes);
    const IntruderPersist::RunConfig &c = run.config;

    // Restore config. Concurrency/throttle go through the clamping setters; the
    // rest are plain fields (attackType is bounded to the valid enum range).
    m_host        = c.host;
    m_port        = c.port;
    m_useTls      = c.tls;
    m_template    = c.requestTemplate;
    m_attackType  = qBound(static_cast<int>(Sniper), c.attackType,
                           static_cast<int>(ClusterBomb));
    m_payloadSets = c.payloadSets;
    m_payloadRules = c.rules;
    m_grepMatch   = c.grepMatch;
    m_grepPayloadReflection = c.grepPayloadReflection;
    m_grepExtract = c.grepExtract;
    setMaxConcurrency(c.concurrency);
    setThrottleMs(c.throttleMs);

    // Rebuild the result rows.
    beginResetModel();
    qDeleteAll(m_attacks);
    m_attacks.clear();
    m_completedCount = 0;
    for (const IntruderPersist::ResultRow &r : run.rows) {
        auto *a = new IntruderAttack(this);
        a->m_id            = r.id;
        a->m_payloadValues = r.payloadValues;
        a->m_payload       = r.payloadValues.join(QStringLiteral(" / "));
        a->m_combo         = r.combo;
        a->m_statusCode    = r.statusCode;
        a->m_responseSize  = r.responseSize;
        a->m_elapsedMs     = r.elapsedMs;
        a->m_errorMessage  = r.errorMessage;
        a->m_complete      = r.complete;
        a->m_matched       = r.matched;
        a->m_reflected     = r.reflected;
        a->m_extracted     = r.extracted;
        if (r.complete) ++m_completedCount;
        m_attacks.append(a);
    }
    endResetModel();

    // Nudge every bound property so the UI re-reads the restored state.
    emit targetChanged();
    emit templateChanged();
    emit payloadsChanged();
    emit attackTypeChanged();
    emit progressChanged();
    return true;
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

void Intruder::clearAll() {
    clear();
    m_host.clear();
    m_port = 443;
    m_useTls = true;
    m_template.clear();
    m_payloadSets.clear();
    m_attackType = Sniper;
    emit targetChanged();
    emit templateChanged();
    emit payloadsChanged();
    emit attackTypeChanged();
}

void Intruder::stop() {
    if (!m_running) return;
    m_stopRequested = true;
}

void Intruder::start() {
    if (m_running) return;
    if (m_host.isEmpty() || m_template.isEmpty()) return;

    const int positions = IE::countMarkers(m_template);
    if (positions == 0) return;

    QList<QStringList> sets;
    sets.reserve(m_payloadSets.size());
    for (const QString &block : m_payloadSets) sets.append(parseSet(block));

    const QList<QStringList> combos = IE::generateCombinations(
        static_cast<IE::AttackType>(m_attackType), positions, sets);
    if (combos.isEmpty()) return;

    // Build the result rows up front so the table populates immediately and
    // each individual attack just has to fill its slot.
    beginResetModel();
    qDeleteAll(m_attacks);
    m_attacks.clear();
    m_completedCount = 0;
    for (int i = 0; i < combos.size(); ++i) {
        auto *a = new IntruderAttack(this);
        a->m_id = i + 1;
        a->m_combo = combos[i];
        a->m_payloadValues = displayValues(combos[i]);
        a->m_payload = a->m_payloadValues.join(QStringLiteral(" / "));
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
    const QList<QStringList> combosCopy = combos;
    // Effective chain = per-position rules + the global "URL-encode these
    // characters" safety net appended LAST (empty set = off). Copied for the
    // off-thread worker.
    QList<IntruderRules::Rule> rulesCopy = m_payloadRules;
    if (!m_globalEncodeChars.isEmpty())
        rulesCopy.append({ QStringLiteral("url-encode-chars"), m_globalEncodeChars });
    const QStringList grepMatchCopy = m_grepMatch;                 // copy: scanned off-thread
    const IntruderGrep::ExtractSpec grepExtractCopy = m_grepExtract;
    const bool grepReflectionCopy = m_grepPayloadReflection;
    const int concurrencyCopy = m_maxConcurrency;
    const int throttleCopy = m_throttleMs;

    m_worker = QtConcurrent::run([this, combosCopy, templateCopy, hostCopy,
                                  portCopy, tlsCopy, rulesCopy,
                                  grepMatchCopy, grepReflectionCopy, grepExtractCopy,
                                  concurrencyCopy, throttleCopy]() {
        runWorker(combosCopy, templateCopy, hostCopy, portCopy, tlsCopy,
                  rulesCopy, grepMatchCopy, grepReflectionCopy, grepExtractCopy,
                  concurrencyCopy, throttleCopy);
    });
}

void Intruder::runWorker(const QList<QStringList> &combos,
                         const QString &templateCopy,
                         const QString &host, int port, bool useTls,
                         const QList<IntruderRules::Rule> &rules,
                         const QStringList &grepMatch,
                         bool grepReflection,
                         const IntruderGrep::ExtractSpec &grepExtract,
                         int concurrency, int throttleMs) {
    // Defensive re-clamp (the setters clamp, but never trust a raw int here) and
    // size the owned pool. `concurrency` is the max number of requests in flight
    // at once; `throttleMs` an optional pause between dispatches (rate limit).
    concurrency = IntruderPool::clampConcurrency(concurrency);
    m_pool.setMaxThreadCount(concurrency);

    // The semaphore bounds queued+running work to `concurrency`: the dispatcher
    // acquires a permit before each submit and the task releases it when its
    // request completes. So even a 100k-combo run never queues more than
    // `concurrency` tasks, and the pool queue can't blow up memory.
    QSemaphore inFlight(concurrency);

    // Fire one request. Runs on a POOL THREAD with its OWN HttpClient --
    // HttpClient is not thread-safe, so a concurrent attack must never share
    // one instance across tasks. Grep runs here (bounded, off the GUI thread);
    // the queued callback only assigns the finished values.
    auto fireOne = [this, &inFlight, templateCopy, host, port, useTls, rules,
                    grepMatch, grepReflection, grepExtract](int row, const QStringList &combo) {
        HttpClient client;

        QString req = IE::applyPayloads(templateCopy, applyRulesToCombo(combo, rules));
        // Normalize line endings for the wire.
        req.replace("\r\n", "\n");
        req.replace("\n", "\r\n");
        if (!req.contains("\r\n\r\n")) req += "\r\n\r\n";

        QElapsedTimer t;
        t.start();
        // Session rules scoped to Intruder (only rewrites when a rule fires).
        QByteArray reqBytes = req.toUtf8();
        if (m_sessionRules)
            m_sessionRules->applyToRequestBytes(reqBytes, host, SessionRulesLogic::ToolIntruder);
        const auto result = client.send(host, static_cast<quint16>(port),
                                        useTls, reqBytes);
        const qint64 elapsedMs = t.elapsed();

        const int statusCode = result.ok ? result.parsed.statusCode : 0;
        // Rate-limit awareness. On 429, this task pauses for Retry-After (capped
        // at 60s so a malicious header can't park the run). Only this task's
        // pool thread sleeps -- the other in-flight requests keep going, which
        // is correct: one 429'd request shouldn't stall the whole pool.
        if (statusCode == 429) {
            int waitMs = 1000;
            for (const auto &h : result.parsed.headers) {
                if (h.first.compare("Retry-After", Qt::CaseInsensitive) != 0) continue;
                bool ok = false;
                const int secs = h.second.toInt(&ok);
                if (ok && secs > 0 && secs < 60) waitMs = secs * 1000;
                break;
            }
            // Interruptible: a 429 back-off is up to 59s and there is one per
            // in-flight request, so an uninterruptible wait here held up
            // m_pool.waitForDone() -- and therefore stop() and the dtor -- for
            // that long, per request.
            interruptibleSleep(waitMs, m_stopRequested);
        }
        const int size       = result.parsed.body.size();
        const QString errMsg = result.ok ? QString() : result.errorMessage;

        bool matched = false;
        bool reflected = false;
        QString extracted;
        if (result.ok)
            computeGrep(result.parsed, grepMatch, combo, grepReflection, grepExtract,
                        matched, reflected, extracted);

        QMetaObject::invokeMethod(this, [this, row, statusCode, size, elapsedMs,
                                         errMsg, matched, reflected, extracted]() {
            if (row < 0 || row >= m_attacks.size()) return;
            auto *a = m_attacks[row];
            a->m_statusCode = statusCode;
            a->m_responseSize = size;
            a->m_elapsedMs = static_cast<int>(elapsedMs);
            a->m_errorMessage = errMsg;
            a->m_matched = matched;
            a->m_reflected = reflected;
            a->m_extracted = extracted;
            a->m_complete = true;
            emit a->changed();
            const QModelIndex idx = index(row);
            emit dataChanged(idx, idx);
            attackFinished(row);
        }, Qt::QueuedConnection);

        inFlight.release();
    };

    // Dispatch loop. Stop is checked before AND after the (possibly blocking)
    // acquire so a stop() request lands promptly even when the pool is saturated.
    // Row index i maps 1:1 to m_attacks[i] regardless of completion order.
    for (int i = 0; i < combos.size(); ++i) {
        if (m_stopRequested) break;
        inFlight.acquire();
        if (m_stopRequested) { inFlight.release(); break; }
        const QStringList combo = combos[i];
        QtConcurrent::run(&m_pool, [fireOne, i, combo]() { fireOne(i, combo); });
        if (throttleMs > 0) interruptibleSleep(throttleMs, m_stopRequested);
    }

    // Join every submitted task before returning. The dtor's wait on m_worker
    // then transitively guarantees no request task outlives m_attacks.
    m_pool.waitForDone();

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

bool Intruder::resend(int row) {
    if (m_running) return false;
    if (row < 0 || row >= m_attacks.size()) return false;
    if (m_host.isEmpty() || m_template.isEmpty()) return false;

    // Reset the target row so the UI shows it as pending again.
    auto *a = m_attacks[row];
    // Apply the same payload-processing rules as a full run (safe to read
    // m_payloadRules here -- we're on the GUI thread; the worker captures the
    // already-transformed combo). Include the global URL-encode-these-chars
    // safety net as the final step, exactly as a full run does.
    QList<IntruderRules::Rule> resendRules = m_payloadRules;
    if (!m_globalEncodeChars.isEmpty())
        resendRules.append({ QStringLiteral("url-encode-chars"), m_globalEncodeChars });
    const QStringList combo = applyRulesToCombo(a->m_combo, resendRules);
    a->m_statusCode   = 0;
    a->m_responseSize = 0;
    a->m_elapsedMs    = 0;
    a->m_errorMessage.clear();
    a->m_matched      = false;
    a->m_extracted.clear();
    a->m_complete     = false;
    emit a->changed();
    const QModelIndex idx = index(row);
    emit dataChanged(idx, idx);

    const QString templateCopy = m_template;
    const QString hostCopy = m_host;
    const int     portCopy = m_port;
    const bool    tlsCopy  = m_useTls;
    const QStringList grepMatchCopy = m_grepMatch;                 // read on GUI thread, scanned off-thread
    const bool grepReflectionCopy = m_grepPayloadReflection;
    const IntruderGrep::ExtractSpec grepExtractCopy = m_grepExtract;

    m_resendWorker = QtConcurrent::run([this, row, combo, templateCopy, hostCopy,
                             portCopy, tlsCopy, grepMatchCopy, grepReflectionCopy,
                             grepExtractCopy]() {
        HttpClient client;
        QString req = IE::applyPayloads(templateCopy, combo);
        req.replace("\r\n", "\n");
        req.replace("\n", "\r\n");
        if (!req.contains("\r\n\r\n")) req += "\r\n\r\n";

        QElapsedTimer t; t.start();
        QByteArray reqBytes = req.toUtf8();
        if (m_sessionRules)
            m_sessionRules->applyToRequestBytes(reqBytes, hostCopy, SessionRulesLogic::ToolIntruder);
        const auto result = client.send(hostCopy, static_cast<quint16>(portCopy),
                                        tlsCopy, reqBytes);
        const qint64 elapsedMs = t.elapsed();
        const int statusCode = result.ok ? result.parsed.statusCode : 0;
        const int size       = result.parsed.body.size();
        const QString errMsg = result.ok ? QString() : result.errorMessage;

        bool matched = false;
        bool reflected = false;
        QString extracted;
        if (result.ok)
            computeGrep(result.parsed, grepMatchCopy, combo, grepReflectionCopy,
                        grepExtractCopy, matched, reflected, extracted);

        QMetaObject::invokeMethod(this, [this, row, statusCode, size, elapsedMs,
                                         errMsg, matched, reflected, extracted]() {
            if (row < 0 || row >= m_attacks.size()) return;
            auto *a = m_attacks[row];
            a->m_statusCode   = statusCode;
            a->m_responseSize = size;
            a->m_elapsedMs    = static_cast<int>(elapsedMs);
            a->m_errorMessage = errMsg;
            a->m_matched      = matched;
            a->m_reflected    = reflected;
            a->m_extracted    = extracted;
            a->m_complete     = true;
            emit a->changed();
            const QModelIndex idx = index(row);
            emit dataChanged(idx, idx);
            // resend doesn't bump completedCount -- the row was already
            // completed once, so progress stays at N/N.
        }, Qt::QueuedConnection);
    });
    return true;
}

} // namespace Nullock::Core

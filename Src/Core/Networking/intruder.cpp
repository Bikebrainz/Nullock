#include "intruder.hpp"

#include "intruder_engine.hpp"
#include "Proxy/proxy_model.hpp"

#include <QElapsedTimer>
#include <QMetaObject>
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
                 const IntruderGrep::ExtractSpec &spec,
                 bool &matchedOut, QString &extractedOut) {
    const bool wantMatch = !needles.isEmpty();
    const bool wantExtract =
        !spec.regex.isEmpty() || !spec.start.isEmpty() || !spec.end.isEmpty();
    matchedOut = false;
    extractedOut.clear();
    if (!wantMatch && !wantExtract) return;
    const QString scan = grepScanText(resp);
    if (wantMatch)   matchedOut   = IntruderGrep::grepMatch(scan, needles);
    if (wantExtract) extractedOut = IntruderGrep::grepExtract(scan, spec);
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

void Intruder::setGrepMatch(const QStringList &needles) {
    m_grepMatch = needles;
}

void Intruder::setGrepExtract(const IntruderGrep::ExtractSpec &spec) {
    m_grepExtract = spec;
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
    const QList<IntruderRules::Rule> rulesCopy = m_payloadRules;   // copy: worker reads it off-thread
    const QStringList grepMatchCopy = m_grepMatch;                 // copy: scanned off-thread
    const IntruderGrep::ExtractSpec grepExtractCopy = m_grepExtract;

    m_worker = QtConcurrent::run([this, combosCopy, templateCopy, hostCopy,
                                  portCopy, tlsCopy, rulesCopy,
                                  grepMatchCopy, grepExtractCopy]() {
        runWorker(combosCopy, templateCopy, hostCopy, portCopy, tlsCopy,
                  rulesCopy, grepMatchCopy, grepExtractCopy);
    });
}

void Intruder::runWorker(const QList<QStringList> &combos,
                         const QString &templateCopy,
                         const QString &host, int port, bool useTls,
                         const QList<IntruderRules::Rule> &rules,
                         const QStringList &grepMatch,
                         const IntruderGrep::ExtractSpec &grepExtract) {
    HttpClient client;

    for (int i = 0; i < combos.size(); ++i) {
        if (m_stopRequested) break;

        // Payload-processing: transform each value through the rule chain before
        // it goes into the request (the results table still shows the original).
        QString req = IE::applyPayloads(templateCopy, applyRulesToCombo(combos[i], rules));
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
        // Rate-limit awareness. If the target returns 429, pause for
        // Retry-After (capped at 60s so a malicious header can't park
        // the whole fuzz run). Without this, intruder runs against
        // production-grade WAFs hit a wall of 429s the moment they
        // exceed the per-source limit, and the entire payload set
        // returns as 429 noise.
        if (statusCode == 429) {
            int waitMs = 1000;
            for (const auto &h : result.parsed.headers) {
                if (h.first.compare("Retry-After", Qt::CaseInsensitive) != 0) continue;
                bool ok = false;
                const int secs = h.second.toInt(&ok);
                if (ok && secs > 0 && secs < 60) waitMs = secs * 1000;
                break;
            }
            QThread::msleep(waitMs);
        }
        const int size       = result.parsed.body.size();
        const QString errMsg = result.ok ? QString() : result.errorMessage;

        // Grep the response HERE on the worker thread (bounded + safe) so the
        // GUI-thread callback below only assigns the finished bool/string --
        // never runs a regex over a huge body on the UI thread.
        bool matched = false;
        QString extracted;
        if (result.ok)
            computeGrep(result.parsed, grepMatch, grepExtract, matched, extracted);

        QMetaObject::invokeMethod(this, [this, row, statusCode, size, elapsedMs,
                                         errMsg, matched, extracted]() {
            if (row < 0 || row >= m_attacks.size()) return;
            auto *a = m_attacks[row];
            a->m_statusCode = statusCode;
            a->m_responseSize = size;
            a->m_elapsedMs = static_cast<int>(elapsedMs);
            a->m_errorMessage = errMsg;
            a->m_matched = matched;
            a->m_extracted = extracted;
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

bool Intruder::resend(int row) {
    if (m_running) return false;
    if (row < 0 || row >= m_attacks.size()) return false;
    if (m_host.isEmpty() || m_template.isEmpty()) return false;

    // Reset the target row so the UI shows it as pending again.
    auto *a = m_attacks[row];
    // Apply the same payload-processing rules as a full run (safe to read
    // m_payloadRules here -- we're on the GUI thread; the worker captures the
    // already-transformed combo).
    const QStringList combo = applyRulesToCombo(a->m_combo, m_payloadRules);
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
    const IntruderGrep::ExtractSpec grepExtractCopy = m_grepExtract;

    m_resendWorker = QtConcurrent::run([this, row, combo, templateCopy, hostCopy,
                             portCopy, tlsCopy, grepMatchCopy, grepExtractCopy]() {
        HttpClient client;
        QString req = IE::applyPayloads(templateCopy, combo);
        req.replace("\r\n", "\n");
        req.replace("\n", "\r\n");
        if (!req.contains("\r\n\r\n")) req += "\r\n\r\n";

        QElapsedTimer t; t.start();
        const auto result = client.send(hostCopy, static_cast<quint16>(portCopy),
                                        tlsCopy, req.toUtf8());
        const qint64 elapsedMs = t.elapsed();
        const int statusCode = result.ok ? result.parsed.statusCode : 0;
        const int size       = result.parsed.body.size();
        const QString errMsg = result.ok ? QString() : result.errorMessage;

        bool matched = false;
        QString extracted;
        if (result.ok)
            computeGrep(result.parsed, grepMatchCopy, grepExtractCopy, matched, extracted);

        QMetaObject::invokeMethod(this, [this, row, statusCode, size, elapsedMs,
                                         errMsg, matched, extracted]() {
            if (row < 0 || row >= m_attacks.size()) return;
            auto *a = m_attacks[row];
            a->m_statusCode   = statusCode;
            a->m_responseSize = size;
            a->m_elapsedMs    = static_cast<int>(elapsedMs);
            a->m_errorMessage = errMsg;
            a->m_matched      = matched;
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

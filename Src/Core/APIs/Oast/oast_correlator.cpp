#include "oast_correlator.hpp"
#include "finding_sink.hpp"
#include "oast_logic.hpp"

#include <QJsonDocument>
#include <QMutexLocker>
#include <QSaveFile>
#include <QFile>

namespace Nullock::Core {

void OastCorrelator::setPersistPath(const QString &path) {
    QMutexLocker lk(&m_mutex);
    m_persistPath = path;
    if (m_persistPath.isEmpty()) return;
    // Load any state a prior run saved, so a callback arriving after a restart
    // still correlates and an already-reported hit is not re-reported. A missing
    // or corrupt file simply starts empty (never crash / half-load).
    QFile f(m_persistPath);
    if (!f.open(QIODevice::ReadOnly)) return;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (doc.isObject())
        OastLogic::deserializeState(doc.object(), m_tokens, m_confirmed);
}

void OastCorrelator::saveLocked() const {
    if (m_persistPath.isEmpty()) return;
    // Atomic write (temp-then-rename) so a crash mid-save never leaves a
    // truncated/corrupt registry.
    QSaveFile f(m_persistPath);
    if (!f.open(QIODevice::WriteOnly)) return;
    f.write(QJsonDocument(OastLogic::serializeState(m_tokens, m_confirmed)).toJson(QJsonDocument::Compact));
    f.commit();
}

void OastCorrelator::registerToken(const QString &token, const OastOrigin &origin) {
    if (token.isEmpty()) return;
    QMutexLocker lk(&m_mutex);
    m_tokens.insert(token, origin);
    // Bound the registry so a long fuzzing run doesn't grow it forever.
    // 50k tokens is far more than any real engagement fires.
    if (m_tokens.size() > 50000) {
        m_tokens.clear();
        m_confirmed.clear();
    }
    saveLocked();
}

int OastCorrelator::registeredCount() const {
    QMutexLocker lk(&m_mutex);
    return m_tokens.size();
}

int OastCorrelator::confirmedCount() const {
    QMutexLocker lk(&m_mutex);
    return m_confirmed.size();
}

void OastCorrelator::onHit(const OastHit &hit) {
    if (hit.token.isEmpty()) return;

    OastOrigin origin;
    bool known = false, alreadyDone = false;
    {
        QMutexLocker lk(&m_mutex);
        auto it = m_tokens.constFind(hit.token);
        if (it != m_tokens.constEnd()) {
            origin = *it;
            known = true;
            if (m_confirmed.contains(hit.token)) alreadyDone = true;
            else { m_confirmed.insert(hit.token); saveLocked(); }
        }
    }
    // Unknown token = someone hit the sink directly (or a token we never
    // registered). Nothing to correlate; the raw hit is still in the log.
    if (!known || alreadyDone || !m_scanner) return;

    // Build a confirmed finding. A registered token arriving out-of-band
    // means the target actually performed the server-side request -- this
    // is a true positive by construction. The finding kind is derived
    // from the registered probe kind so a Log4Shell callback reads as
    // log4shell-oast-confirmed, an XXE callback as xxe-oast-confirmed,
    // etc. (each has its own CWE/CVSS in the enricher).
    const QString baseKind = origin.kind.isEmpty() ? QStringLiteral("ssrf-oast")
                                                   : origin.kind;
    const QString kind = baseKind + "-confirmed";
    const QString summary =
        QString("Confirmed out-of-band interaction: target reached our OAST sink"
                "%1%2")
            .arg(origin.param.isEmpty() ? QString() : QString(" via '%1'").arg(origin.param),
                 origin.note.isEmpty()  ? QString() : QString(" [%1]").arg(origin.note));

    const QString evidence =
        QString("token=%1 · callback from %2 (%3 %4) · UA=%5 · embedded-url=%6")
            .arg(hit.token,
                 hit.sourceIp,
                 hit.method,
                 hit.hostHeader + hit.path,
                 hit.userAgent.left(80),
                 origin.url);

    // A confirmed OOB callback is at least "high"; code-execution classes
    // (Log4Shell) are critical. Impact still depends on what's reachable,
    // but the interaction itself is proven.
    const QString severity =
        baseKind.startsWith("log4shell") || baseKind.startsWith("rce")
            ? QStringLiteral("critical") : QStringLiteral("high");

    m_scanner->reportFinding(origin.rowId, severity, kind,
                             summary, evidence, origin.host, origin.url);
}

} // namespace Nullock::Core

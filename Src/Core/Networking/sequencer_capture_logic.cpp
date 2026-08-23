// Pure Sequencer live-capture logic (see sequencer_capture_logic.hpp). Qt6::Core
// only; reuses the same extraction primitives as the session/chain paths.

#include "sequencer_capture_logic.hpp"

#include "session_rules_logic.hpp"   // findHeader / findCookieValue / jsonPathGet

#include <QRegularExpression>

namespace Nullock::Core::SequencerCaptureLogic {

using namespace Nullock::Core::SessionRulesLogic;

ExtractFrom parseExtractFrom(const QString &s) {
    const QString t = s.trimmed().toLower();
    if (t == "cookie") return FromCookie;
    if (t == "json")   return FromJson;
    if (t == "regex")  return FromRegex;
    if (t == "status") return FromStatus;
    return FromHeader;   // unknown/empty -> header, matching ChainRunner's default
}

QString extractToken(int from, const QString &key, int statusCode,
                     const QList<QPair<QString, QString>> &headers,
                     const QByteArray &body) {
    switch (from) {
        case FromHeader:
            return findHeader(headers, key);
        case FromCookie:
            for (const auto &h : headers) {
                if (h.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) continue;
                const QString v = findCookieValue(h.second, key);
                if (!v.isEmpty()) return v;
            }
            return {};
        case FromJson:
            return jsonPathGet(body, key);
        case FromRegex: {
            QRegularExpression rx(key, QRegularExpression::DotMatchesEverythingOption);
            if (!rx.isValid()) return {};
            const QByteArray buf = body.left(1 * 1024 * 1024);
            const auto m = rx.match(QString::fromUtf8(buf));
            if (!m.hasMatch()) return {};
            return m.lastCapturedIndex() >= 1 ? m.captured(1) : m.captured(0);
        }
        case FromStatus:
            return QString::number(statusCode);
    }
    return {};
}

QString cookieNameFromSetCookie(const QString &raw) {
    const QList<QString> segs = raw.split(';');
    if (segs.isEmpty()) return {};
    const QString s = segs.first().trimmed();
    const int eq = s.indexOf('=');
    if (eq <= 0) return {};
    return s.left(eq).trimmed();
}

int clampCaptureCount(int requested, int maxCap) {
    if (maxCap < 0) maxCap = 0;
    if (requested < 0) return 0;
    return requested > maxCap ? maxCap : requested;
}

int clampThrottleMs(int requestedMs) {
    if (requestedMs < 0) return 0;
    constexpr int kMaxThrottleMs = 60000;
    return requestedMs > kMaxThrottleMs ? kMaxThrottleMs : requestedMs;
}

ShotClass classifyShot(bool ok, int statusCode, bool tokenEmpty) {
    if (!ok) return ShotTransportError;
    if (!tokenEmpty) return ShotToken;   // a token on ANY status is a capture
    const bool statusOk = statusCode >= 200 && statusCode < 400;
    return statusOk ? ShotEmptyExtract : ShotHttpError;
}

bool shotYieldsToken(ShotClass c) { return c == ShotToken; }

int retryAfterMs(const QString &retryAfterHeader, int capMs) {
    if (capMs < 0) capMs = 0;
    bool ok = false;
    const long long secs = retryAfterHeader.trimmed().toLongLong(&ok);
    if (!ok || secs < 0) return 0;             // HTTP-date form / garbage -> no wait
    const long long ms = secs * 1000;
    return ms > capMs ? capMs : static_cast<int>(ms);
}

bool circuitTripped(int consecutiveFailures, int threshold) {
    if (threshold <= 0) return false;          // breaker disabled
    return consecutiveFailures >= threshold;
}

CorpusVerdict corpusGuard(int total, int distinct) {
    if (total <= 0)   return CorpusNoData;
    if (total < 2)    return CorpusTooFew;
    if (distinct <= 1) return CorpusConstant;
    return CorpusOk;
}

QString corpusVerdictMessage(CorpusVerdict v, int total, int distinct) {
    switch (v) {
        case CorpusOk:
            return {};
        case CorpusNoData:
            return QStringLiteral("no tokens captured -- check the extract rule and that the request succeeds");
        case CorpusTooFew:
            return QStringLiteral("only %1 token captured -- randomness analysis needs at least 2").arg(total);
        case CorpusConstant:
            return QStringLiteral("captured value is constant across %1 samples (%2 distinct) -- this is not a "
                                  "rotating token; check the extractor, or the field genuinely never changes")
                       .arg(total).arg(distinct);
    }
    return {};
}

bool scopeAllows(bool inScopeEmpty, bool hostInScope) {
    return !inScopeEmpty && hostInScope;
}

} // namespace Nullock::Core::SequencerCaptureLogic

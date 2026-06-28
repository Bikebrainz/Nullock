#include "h2_logic.hpp"

namespace Nullock::Proxy::H2Logic {

int capStreamSummaries(QMap<QString, H2StreamSummary> &streams, int maxStreams) {
    if (maxStreams <= 0) return 0;   // defensive: treat as "no cap", evict nothing
    int evicted = 0;
    while (streams.size() > maxStreams) {
        auto victim = streams.end();
        bool victimClosed = false;
        qint64 victimAge = 0;
        for (auto it = streams.begin(); it != streams.end(); ++it) {
            const bool   closed = it->closed;
            const qint64 age    = it->openedAtMs;
            if (victim == streams.end()) {
                victim = it; victimClosed = closed; victimAge = age;
                continue;
            }
            // Prefer a closed stream over an open one.
            if (closed && !victimClosed) {
                victim = it; victimClosed = closed; victimAge = age;
                continue;
            }
            // Within the same closed-ness, prefer the older (smaller openedAtMs).
            if (closed == victimClosed && age < victimAge) {
                victim = it; victimAge = age;
            }
        }
        if (victim == streams.end()) break;   // unreachable while size > maxStreams > 0
        streams.erase(victim);
        ++evicted;
    }
    return evicted;
}

QString clampTelemetryField(const QString &s, int maxLen) {
    if (maxLen < 0 || s.size() <= maxLen) return s;
    return s.left(maxLen);
}

} // namespace Nullock::Proxy::H2Logic

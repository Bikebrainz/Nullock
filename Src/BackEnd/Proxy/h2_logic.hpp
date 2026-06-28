#pragma once

#include "h2_events.hpp"   // for H2StreamSummary

#include <QMap>
#include <QString>

// Pure bounding logic for the H2EventLog telemetry sink, split out of
// h2_events.cpp so a unit test can link it against Qt6::Core alone. The data fed
// to the sink (stream ids, byte counts, :method / :path, status, RST codes) comes
// from PROXIED HTTP/2 traffic and is NOT trusted, so the per-stream map and the
// stored string fields must be bounded -- the header's own "attacker bytes can't
// pin RAM" promise was previously honoured only for the event ring, not the
// per-stream map.
namespace Nullock::Proxy::H2Logic {

// Hard cap on retained per-stream summaries. A proxied connection cycles through
// many stream ids over its life and closed streams were never evicted, so an
// unbounded QMap grew for the whole session. 4096 comfortably exceeds any real
// concurrent-stream count (SETTINGS_MAX_CONCURRENT_STREAMS is typically ~100-1000)
// so steady-state never evicts a live stream.
inline constexpr int kMaxStreams = 4096;

// Cap on a single telemetry string field (:method / :path). A malicious upstream
// could send a multi-MB :path pseudo-header; we only need a human-readable gist.
inline constexpr int kMaxTelemetryFieldLen = 4096;

// Evict summaries until streams.size() <= maxStreams. Victim selection prefers a
// CLOSED stream (terminal -- it will never receive another frame), breaking ties
// by the oldest openedAtMs; if none are closed, the oldest OPEN stream is evicted.
// Orphan entries auto-created by a status/RST/close for a never-seen stream carry
// openedAtMs==0, so they sort oldest and are shed first (desired). Returns the
// number evicted. maxStreams <= 0 is treated as "no cap" (defensive: a 0 cap
// wiping all telemetry is worse than leaving it) and evicts nothing.
int capStreamSummaries(QMap<QString, H2StreamSummary> &streams, int maxStreams);

// Truncate an untrusted telemetry string to maxLen (returns it unchanged when
// already within bounds, or when maxLen < 0).
QString clampTelemetryField(const QString &s, int maxLen);

} // namespace Nullock::Proxy::H2Logic

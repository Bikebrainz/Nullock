#pragma once

// Intruder payload generators (Burp "Payloads > Payload type" gap): expand a
// compact spec into a concrete payload list -- numbers, brute-force strings, or
// dates. Every generator is HARD-CAPPED at kMaxCount so a huge range or a big
// charset^length can never OOM or hang; callers get a truncated set, never a
// crash. PURE: no I/O -- links against Qt6::Core alone.

#include <QString>
#include <QStringList>

namespace Nullock::Core::IntruderGenerators {

// Upper bound on generated payloads. A generator that would produce more stops
// at exactly this many (truncated). Bounds memory + wall-clock deterministically.
constexpr int kMaxCount = 100000;

// from..to stepping by step. step sign sets direction (step > 0 ascends,
// step < 0 descends; step == 0 -> empty). width > 0 zero-pads to that many
// digits; hex renders lowercase hex. Overflow-safe (never wraps past INT64).
QStringList numbers(qint64 from, qint64 to, qint64 step, int width = 0, bool hex = false);

// Every string over `charset` with length in [minLen, maxLen], odometer order.
// Degenerate args are clamped/rejected: empty charset -> empty; minLen < 1 -> 1;
// maxLen < minLen -> empty. Output capped at kMaxCount (truncated, never OOM).
QStringList brute(const QString &charset, int minLen, int maxLen);

// ISO dates fromIso..toIso stepping stepDays, each formatted by `format` (Qt date
// format). Invalid dates / from > to / stepDays <= 0 -> empty. Capped.
QStringList dates(const QString &fromIso, const QString &toIso, int stepDays,
                  const QString &format = QStringLiteral("yyyy-MM-dd"));

// Generator type names this module understands (for UI discovery).
QStringList types();

} // namespace Nullock::Core::IntruderGenerators

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

// Burp "Character frobber": walk the base one position at a time, emitting one
// payload per position that is the whole base with exactly THAT position's
// character incremented by +1 and every other character unchanged (output count
// == base length in code points). Increments by CODE POINT (toUcs4), not UTF-16
// unit, and keeps the result a valid Unicode scalar -- a bump into the surrogate
// range 0xD800..0xDFFF skips to 0xE000, past 0x10FFFF wraps to 0 -- so a non-BMP
// base char is never split into lone surrogates. Empty base -> empty. Bounded in
// BOTH count (kMaxCount) and total emitted chars, so a huge base can't OOM.
QStringList frob(const QString &base);

// Burp "Null payloads": emit `count` EMPTY payloads, so a position is filled
// with nothing and the base request is re-sent unchanged `count` times (rate-limit
// probing, race conditions, observing non-deterministic responses). count < 1 ->
// empty; capped at kMaxCount (truncated, never OOM).
QStringList nullPayloads(int count);

// Generator type names this module understands (for UI discovery).
QStringList types();

} // namespace Nullock::Core::IntruderGenerators

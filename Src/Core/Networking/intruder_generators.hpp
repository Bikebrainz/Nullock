#pragma once

// Intruder payload generators (Burp "Payloads > Payload type" gap): expand a
// compact spec into a concrete payload list -- numbers, brute-force strings, or
// dates. Every generator is HARD-CAPPED at kMaxCount so a huge range or a big
// charset^length can never OOM or hang; callers get a truncated set, never a
// crash. PURE: no I/O -- links against Qt6::Core alone.

#include <QHash>
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

// Burp "Bit flipper": for EACH byte of the base (its UTF-8 encoding), emit one
// payload per bit position 0..7 with that single bit XOR-flipped -- byte order
// left-to-right, bit order LEAST-significant (0x01) to most-significant (0x80),
// matching Burp's output exactly (e.g. "ab" -> `b, cb, eb, ib, qb, Ab, !b, áb,
// ac, a`, af, aj, ar, aB, a", aâ). Flipped bytes are rendered via Latin-1 so a
// high byte (0xE1 -> 'á') matches Burp's display. base empty -> empty; capped at
// kMaxCount. NOTE: a most-significant-bit flip yields a >=0x80 byte that a
// string payload re-encodes to two UTF-8 bytes on the wire; the 7 lower-bit
// flips per byte are byte-exact.
QStringList bitFlip(const QString &base);

// Burp "Character substitution" (leetspeak): for EACH item, emit one payload for
// every combination of applying-or-not each substitutable position, i.e. all 2^k
// permutations where k = the number of characters in the item that have a
// substitution in `subs`. Enumerated as a binary counter with the LEFTMOST
// substitutable position as the least-significant bit -- so e.g. "peter" with
// {e:3, t:7} yields peter, p3ter, pe7er, p37er, pet3r, p3t3r, pe73r, p373r.
// Empty `subs` -> empty. Bounded at kMaxCount (large k is truncated, never OOM).
QStringList charSub(const QStringList &items, const QHash<QChar, QChar> &subs);

// Burp "Case modification" options (bit flags -- combine with |). The bit order
// below IS the canonical generation order.
enum CaseMode : unsigned {
    CaseNoChange   = 1u << 0,   // item verbatim
    CaseLower      = 1u << 1,   // all letters -> lower
    CaseUpper      = 1u << 2,   // all letters -> upper
    CaseProper     = 1u << 3,   // "To Propername": first code point upper, rest LOWER
    CaseProperKeep = 1u << 4,   // "To ProperName": first code point upper, rest UNCHANGED
};

// Burp "Case modification": for EACH item emit one payload per ENABLED CaseMode
// in canonical order, ITEM-MAJOR (all enabled variants of item[0], then item[1],
// ...). One payload per (item, enabled mode) -- NO dedup, so two options that
// coincide on an item still yield two payloads (faithful to "one payload per
// option"). The Proper/ProperKeep first character is uppercased by CODE POINT
// (toUcs4), so a leading non-BMP glyph is never split into surrogates. modes == 0
// or empty items -> empty. Capped at kMaxCount.
QStringList caseMod(const QStringList &items, unsigned modes);

// Burp "Character blocks": repeat `base` a multiplier of times, from minMult to
// maxMult stepping by `step` -- one payload per multiplier (base x k). E.g.
// charBlocks("A",1,3,1) -> {"A","AA","AAA"}; charBlocks("AB",1,3,1) ->
// {"AB","ABAB","ABABAB"}. It multiplies (repeats) the WHOLE base, it does NOT
// truncate to a length. base empty / step < 1 / maxMult < minMult -> empty;
// minMult < 1 is clamped to 1. Bounded in count (kMaxCount) AND total emitted
// chars, and refuses to build a block that would breach the char cap, so a huge
// multiplier can't OOM.
QStringList charBlocks(const QString &base, int minMult, int maxMult, int step);

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

// Burp "Username generator": derive candidate usernames from a full name or an
// email address using common schemes -- first/last, concatenations, dot/underscore
// separated, reversed order, and first/last-initial combinations. An email uses
// its local part (before '@'); tokens are split on whitespace / . _ - and stripped
// to [a-z0-9]. Output is lower-cased, DEDUPED (first-seen order), and capped at
// kMaxCount. Empty / token-less input -> empty.
QStringList usernameGen(const QString &nameOrEmail);

// Generator type names this module understands (for UI discovery).
QStringList types();

} // namespace Nullock::Core::IntruderGenerators

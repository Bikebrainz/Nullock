#pragma once

// Compare: the two-blob diff behind the COMPARER tab -- Nullock's answer to
// Burp's Comparer. Produces a word/line/char-level LCS diff of two inputs so an
// operator can see exactly what changed between, say, two responses.
//
// PURE: QString in, structured segments out; no I/O / clock / randomness, links
// against Qt6::Core alone and is fully unit-testable. The diff is bounded (a
// fixed cell budget) because the control handler that calls it runs synchronously
// on the GUI thread -- an unbounded O(n*m) LCS on a huge input would freeze it.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::Compare {

// Cell budget (n*m) for the LCS DP: the diff clips its inputs so the table never
// exceeds this many cells, which bounds both memory (~4 bytes/cell) and wall-clock
// on the synchronous handler. ~4000x4000 == 16M cells ~= 64 MB, ~100 ms.
constexpr long long kMaxCells = 16000000LL;

// Clip (n,m) so n*m <= kMaxCells while keeping as MUCH of each side as possible:
// a side that already fits is preserved WHOLE and only the oversized side is
// clipped (so a short blob vs a long one compares the long one nearly in full);
// when BOTH are oversized each is clipped to floor(sqrt(kMaxCells)). This replaces
// the old flat per-side cap, which needlessly truncated a large side even when the
// other side was tiny. Pure; exposed for unit testing. Result sizes are <= inputs.
QPair<qsizetype, qsizetype> budgetedSizes(qsizetype n, qsizetype m);

// One run of tokens sharing an edit op. op is "eq" (in both), "del" (only in A),
// or "ins" (only in B). text is the original token text, reassembled.
struct Segment {
    QString op;
    QString text;
};

struct DiffResult {
    QList<Segment> segments;
    int  added     = 0;    // tokens present only in B
    int  removed   = 0;    // tokens present only in A
    int  common    = 0;    // tokens in both (the LCS length)
    bool identical = false;
    bool truncated = false;   // an input exceeded the cell budget and was clipped
};

// Supported diff granularities.
QStringList modes();

// Diff `a` vs `b` at the given granularity ("words" | "lines" | "chars"; an
// unknown mode falls back to "words").
DiffResult diff(const QString &mode, const QString &a, const QString &b);

// EXACT byte-level diff of two raw byte buffers -- Burp's Comparer "Bytes" mode.
// Unlike the QString-based diff (which transcodes through UTF-16 and would mangle
// non-UTF-8 / binary content), this compares the raw octets, so binary session
// tokens, serialized objects and images diff faithfully. Each Segment's `text` is
// the run rendered as lowercase hex (two chars per byte). Same cell budget and
// truncation semantics as diff().
DiffResult diffBytes(const QByteArray &a, const QByteArray &b);

} // namespace Nullock::Core::Compare

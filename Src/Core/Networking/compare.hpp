#pragma once

// Compare: the two-blob diff behind the COMPARER tab -- Nullock's answer to
// Burp's Comparer. Produces a word/line/char-level LCS diff of two inputs so an
// operator can see exactly what changed between, say, two responses.
//
// PURE: QString in, structured segments out; no I/O / clock / randomness, links
// against Qt6::Core alone and is fully unit-testable. The diff is bounded (a
// fixed cell budget) because the control handler that calls it runs synchronously
// on the GUI thread -- an unbounded O(n*m) LCS on a huge input would freeze it.

#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::Compare {

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

} // namespace Nullock::Core::Compare

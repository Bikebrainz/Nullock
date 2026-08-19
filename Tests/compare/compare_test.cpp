// Regression corpus for the Compare workbench (pure LCS word/line/char diff).
// Locks: identical detection, pure insert/delete, mixed edits, the eq/del/ins
// segment ops + coalescing, exact reassembly (segments rejoin to the inputs),
// per-mode tokenization, add/remove counts, and the cell-budget truncation.
//
// Run via:  ctest -R compare -V

#include "compare.hpp"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::Compare;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// Rejoin a side of the diff: side 'a' = eq+del segments, side 'b' = eq+ins.
QString rebuild(const DiffResult &d, char side) {
    QString out;
    for (const auto &s : d.segments) {
        if (s.op == "eq") out += s.text;
        else if (side == 'a' && s.op == "del") out += s.text;
        else if (side == 'b' && s.op == "ins") out += s.text;
    }
    return out;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    chk("modes: three", modes().size() == 3);

    // ===== identical ===================================================
    {
        const auto d = diff("words", "the quick brown fox", "the quick brown fox");
        chk("identical: flagged", d.identical);
        chk("identical: no adds/removes", d.added == 0 && d.removed == 0);
        chk("identical: all eq", d.segments.size() == 1 && d.segments.first().op == "eq");
    }

    // ===== pure insertion ==============================================
    {
        const auto d = diff("words", "a c", "a b c");
        chk("insert: one add token counted", d.added == 1);
        chk("insert: nothing removed", d.removed == 0);
        chk("insert: not identical", !d.identical);
        chk("insert: side A rebuilds original", rebuild(d, 'a') == "a c");
        chk("insert: side B rebuilds original", rebuild(d, 'b') == "a b c");
    }

    // ===== pure deletion ===============================================
    {
        const auto d = diff("words", "a b c", "a c");
        chk("delete: one removed token counted", d.removed == 1);
        chk("delete: nothing added", d.added == 0);
        chk("delete: side A rebuilds", rebuild(d, 'a') == "a b c");
        chk("delete: side B rebuilds", rebuild(d, 'b') == "a c");
    }

    // ===== mixed edit + exact reassembly ===============================
    {
        const QString a = "GET /admin HTTP/1.1\nHost: x\nCookie: sess=abc";
        const QString b = "GET /admin HTTP/1.1\nHost: x\nCookie: sess=xyz";
        const auto d = diff("lines", a, b);
        chk("mixed(lines): not identical", !d.identical);
        chk("mixed(lines): has an insert and a delete", d.added >= 1 && d.removed >= 1);
        chk("mixed(lines): side A reassembles exactly", rebuild(d, 'a') == a);
        chk("mixed(lines): side B reassembles exactly", rebuild(d, 'b') == b);
        // common lines (the two unchanged header lines) survive as eq
        int eqLines = 0;
        for (const auto &s : d.segments) if (s.op == "eq") eqLines += s.text.count('\n');
        chk("mixed(lines): shared header lines kept as eq", eqLines >= 2);
    }

    // ===== char mode ===================================================
    {
        const auto d = diff("chars", "password123", "password124");
        chk("chars: one char changed -> 1 add + 1 remove", d.added == 1 && d.removed == 1);
        chk("chars: common prefix preserved", d.common == 10);
        chk("chars: side A rebuilds", rebuild(d, 'a') == "password123");
        chk("chars: side B rebuilds", rebuild(d, 'b') == "password124");
    }

    // ===== ops are only eq/del/ins + coalesced =========================
    {
        const auto d = diff("words", "one two three", "one four three");
        bool validOps = true, coalesced = true;
        QString prev;
        for (const auto &s : d.segments) {
            if (s.op != "eq" && s.op != "del" && s.op != "ins") validOps = false;
            if (s.op == prev) coalesced = false;   // no two adjacent same-op segments
            prev = s.op;
        }
        chk("ops: only eq/del/ins", validOps);
        chk("ops: adjacent same-op runs are coalesced", coalesced);
    }

    // ===== empty inputs ================================================
    {
        const auto d = diff("words", "", "");
        chk("empty vs empty: identical", d.identical && d.added == 0 && d.removed == 0);
        const auto d2 = diff("words", "", "hello world");
        chk("empty vs text: all inserts, rebuild B", rebuild(d2, 'b') == "hello world" && d2.removed == 0);
    }

    // ===== truncation (cell budget) ====================================
    {
        QString big;
        for (int i = 0; i < 5000; ++i) big += "x ";   // 10000 tokens > 2000 cap
        const auto d = diff("words", big, big + "y");
        chk("truncate: flagged when over the token cap", d.truncated);
        // audit-9: a truncated diff compared only the clipped prefix, so it must
        // NOT report two inputs (that differ past the cap) as identical.
        chk("truncate: NOT identical (differs past the cap)", !d.identical);
    }

    // ===== adaptive cell budget: a SHORT side vs a LONG side is NOT needlessly
    // truncated. The old flat 2000/side cap clipped the long side even when the
    // other side was tiny; the budget keeps a small side whole. ==============
    {
        QString longB;
        for (int i = 0; i < 3000; ++i) longB += "w" + QString::number(i) + " ";  // 3000 distinct tokens
        const auto d = diff("words", "q ", longB);
        chk("budget: short vs 3000-token long side is NOT truncated", !d.truncated);
        chk("budget: the full long side is diffed (3000 inserts)", d.added == 3000);
    }

    // ===== budgetedSizes: keep a fitting side whole, clip only the oversized one;
    // clip both when both exceed sqrt(budget) =================================
    {
        auto p0 = budgetedSizes(100, 100);
        chk("budget: both small -> unchanged", p0.first == 100 && p0.second == 100);
        auto p = budgetedSizes(200, 200000);   // 40M > 16M; 200 fits -> clip only the long side
        chk("budget: short side preserved, long clipped to budget/short",
            p.first == 200 && p.second == kMaxCells / 200);
        auto p2 = budgetedSizes(200000, 200);   // symmetric to the above
        chk("budget: (long, short) also clips only the long side",
            p2.first == kMaxCells / 200 && p2.second == 200);
        auto q = budgetedSizes(100000, 100000);  // both huge -> floor(sqrt(16M)) = 4000 each
        chk("budget: both large -> sqrt(budget) each (4000)", q.first == 4000 && q.second == 4000);
        auto r = budgetedSizes(4000, 4000);      // exactly at budget -> unchanged
        chk("budget: product == budget -> unchanged", r.first == 4000 && r.second == 4000);
        auto z = budgetedSizes(0, 5);
        chk("budget: zero side -> unchanged", z.first == 0 && z.second == 5);
    }

    // ===== chars mode is code-point aware (audit-9) ====================
    {
        const char32_t a1[] = { 0x1F600 }, b1[] = { 0x1F601 };   // grinning vs beaming face
        const auto d = diff("chars", QString::fromUcs4(a1, 1), QString::fromUcs4(b1, 1));
        chk("chars: distinct non-BMP glyphs share no whole char (no surrogate split)",
            d.common == 0);
    }

    // ===== unknown mode falls back to words ============================
    {
        const auto d = diff("bogus", "a b", "a c");
        chk("unknown mode -> words fallback works", d.added == 1 && d.removed == 1);
    }

    std::fprintf(stderr, "compare_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

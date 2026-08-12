// Tests for the Intruder payload generators
// (Src/Core/Networking/intruder_generators.cpp). The load-bearing invariant is
// the HARD COUNT CAP: a huge numeric range or a big charset^length must produce
// at most kMaxCount payloads -- never OOM, never hang, never crash on degenerate
// args (step 0, from>to, maxLen<minLen, empty charset, invalid dates).
//
// Run via:  ctest -R intruder_generators -V

#include "intruder_generators.hpp"

#include <QCoreApplication>

#include <algorithm>
#include <cstdio>
#include <limits>

using namespace Nullock::Core::IntruderGenerators;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- numbers -----
    chk("numbers 1..5 step1", numbers(1, 5, 1) == (QStringList{ "1", "2", "3", "4", "5" }));
    chk("numbers 0..10 step5", numbers(0, 10, 5) == (QStringList{ "0", "5", "10" }));
    chk("numbers descending 5..1 step-1", numbers(5, 1, -1) == (QStringList{ "5", "4", "3", "2", "1" }));
    chk("numbers step 0 -> empty",        numbers(1, 5, 0).isEmpty());
    chk("numbers from>to step+ -> empty", numbers(5, 1, 1).isEmpty());
    chk("numbers from<to step- -> empty", numbers(1, 5, -1).isEmpty());
    chk("numbers zero-pad width 3",       numbers(8, 10, 1, 3) == (QStringList{ "008", "009", "010" }));
    chk("numbers hex",                    numbers(10, 12, 1, 0, true) == (QStringList{ "a", "b", "c" }));
    chk("numbers negative range",         numbers(-2, 2, 1) == (QStringList{ "-2", "-1", "0", "1", "2" }));
    chk("numbers zero-pad keeps sign",    numbers(-1, -1, 1, 3) == (QStringList{ "-001" }));

    // numbers: cap + overflow safety (step 1 over the whole int64 range would be
    // astronomically large; must stop at kMaxCount, fast, no overflow/UB).
    {
        const QStringList r = numbers(std::numeric_limits<qint64>::min(),
                                      std::numeric_limits<qint64>::max(), 1);
        chk("numbers huge range capped at kMaxCount", r.size() == kMaxCount);
    }

    // ----- brute -----
    chk("brute ab len1..2",
        brute("ab", 1, 2) == (QStringList{ "a", "b", "aa", "ab", "ba", "bb" }));
    chk("brute single char len1..1", brute("x", 1, 1) == (QStringList{ "x" }));
    chk("brute empty charset -> empty",  brute("", 1, 3).isEmpty());
    chk("brute maxLen<minLen -> empty",  brute("ab", 3, 2).isEmpty());
    chk("brute minLen<1 clamps to 1",    brute("a", 0, 1) == (QStringList{ "a" }));
    // cap: 10 digits, length 1..6 -> 10 + 100 + ... + 1e6 >> kMaxCount. Must cap.
    {
        const QStringList r = brute("0123456789", 1, 6);
        chk("brute huge combinatorial capped at kMaxCount", r.size() == kMaxCount);
    }
    // audit-6: a single-char charset caps by CHAR VOLUME, not just string count --
    // the old code let total length grow O(maxLen^2) into a multi-GB OOM.
    {
        const QStringList r = brute("A", 1, 100000);
        qint64 chars = 0;
        for (const QString &s : r) chars += s.size();
        chk("brute single-char large maxLen -> bounded char volume (no OOM)",
            chars < 10 * 1000 * 1000);
    }
    // audit-6: a non-BMP charset symbol is emitted WHOLE (enumerate code points),
    // not split into two lone surrogates.
    {
        const QString smile = QString::fromUcs4(U"\U0001F600");   // U+1F600
        chk("brute keeps a non-BMP charset glyph intact",
            brute(smile, 1, 1) == (QStringList{ smile }));
    }

    // ----- dates -----
    chk("dates range step1",
        dates("2026-01-01", "2026-01-03", 1)
            == (QStringList{ "2026-01-01", "2026-01-02", "2026-01-03" }));
    chk("dates step 2 days",
        dates("2026-01-01", "2026-01-05", 2)
            == (QStringList{ "2026-01-01", "2026-01-03", "2026-01-05" }));
    chk("dates custom format", dates("2026-01-01", "2026-01-01", 1, "dd/MM/yyyy") == (QStringList{ "01/01/2026" }));
    chk("dates invalid -> empty",   dates("nope", "2026-01-01", 1).isEmpty());
    chk("dates from>to -> empty",   dates("2026-02-01", "2026-01-01", 1).isEmpty());
    chk("dates step<=0 -> empty",   dates("2026-01-01", "2026-01-05", 0).isEmpty());

    // ----- nullPayloads (Burp "Null payloads") -----
    chk("null: count 3 -> 3 empty strings",
        nullPayloads(3) == (QStringList{ QString(), QString(), QString() }));
    { const QStringList np = nullPayloads(5);
      chk("null: every element is empty",
          np.size() == 5 && std::all_of(np.cbegin(), np.cend(),
                                        [](const QString &s){ return s.isEmpty(); })); }
    chk("null: count 0 -> empty list",   nullPayloads(0).isEmpty());
    chk("null: negative count -> empty", nullPayloads(-4).isEmpty());
    chk("null: count 1 -> exactly one empty payload", nullPayloads(1).size() == 1);
    // capped at kMaxCount (truncated, never OOM) -- ask for more than the cap.
    chk("null: over-cap request truncates to kMaxCount",
        nullPayloads(kMaxCount + 500).size() == kMaxCount);

    // ----- charBlocks (Burp "Character blocks") -----
    chk("blocks: A x1..3 -> A,AA,AAA", charBlocks("A", 1, 3, 1) == (QStringList{ "A", "AA", "AAA" }));
    // THE key lock: multiply (whole-repeat) the base, NOT truncate to a length.
    chk("blocks: AB x1..3 -> whole-repeat not truncate",
        charBlocks("AB", 1, 3, 1) == (QStringList{ "AB", "ABAB", "ABABAB" }));
    chk("blocks: step 2 (x2,x4,x6)", charBlocks("x", 2, 6, 2) == (QStringList{ "xx", "xxxx", "xxxxxx" }));
    chk("blocks: empty base -> empty",     charBlocks(QString(), 1, 3, 1).isEmpty());
    chk("blocks: maxMult<minMult -> empty", charBlocks("A", 3, 1, 1).isEmpty());
    chk("blocks: step<1 -> empty",         charBlocks("A", 1, 3, 0).isEmpty());
    chk("blocks: minMult<1 clamps to 1",   charBlocks("A", -5, 2, 1) == (QStringList{ "A", "AA" }));
    // volume-capped: a huge multiplier range is bounded, and never builds a monster block.
    {
        const QStringList r = charBlocks(QString(1000, QChar('a')), 1, 1000000, 1);
        chk("blocks: huge range is volume-capped", !r.isEmpty() && r.size() < 1000000 && r.size() <= kMaxCount);
    }

    // ----- frob (Burp "Character frobber") -----
    chk("frob: abc -> per-position +1", frob("abc") == (QStringList{ "bbc", "acc", "abd" }));
    chk("frob: az -> z bumps to '{'",   frob("az")  == (QStringList{ "bz", "a{" }));
    chk("frob: single char a -> {b}",   frob("a")   == (QStringList{ "b" }));
    chk("frob: empty -> empty",         frob(QString()).isEmpty());
    // code-point safe: a non-BMP base char is bumped whole, never split into surrogates.
    {
        const char32_t emoji = 0x1F600;
        const QString base = QString::fromUcs4(&emoji, 1) + QStringLiteral("x");
        const QStringList r = frob(base);
        chk("frob: non-BMP base -> one payload per code point (2)", r.size() == 2);
        const QList<uint> c0 = r.at(0).toUcs4();
        chk("frob: non-BMP first glyph bumped whole (no surrogate split)",
            c0.size() == 2 && c0.at(0) == 0x1F601u && c0.at(1) == uint('x'));
    }
    // a bump landing in the surrogate range is skipped to keep the string valid.
    {
        const QStringList r = frob(QString(QChar(0xD7FF)));   // +1 = 0xD800 (surrogate) -> 0xE000
        chk("frob: surrogate-range bump skips to 0xE000",
            r.size() == 1 && r.at(0).toUcs4() == (QList<uint>{ 0xE000u }));
    }
    // volume-capped: an L-char base is O(L^2) chars; a large base must be bounded.
    {
        const QStringList r = frob(QString(20000, QChar('a')));
        chk("frob: long base is volume-capped (not all positions emitted)",
            !r.isEmpty() && r.size() < 20000 && r.size() <= kMaxCount);
    }

    // ----- types() -----
    chk("types lists numbers+brute+dates+null+frobber+blocks",
        types().contains("numbers") && types().contains("brute")
        && types().contains("dates") && types().contains("null")
        && types().contains("frobber") && types().contains("blocks"));

    std::fprintf(stderr, "intruder_generators_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

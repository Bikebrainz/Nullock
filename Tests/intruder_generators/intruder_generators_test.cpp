// Tests for the Intruder payload generators
// (Src/Core/Networking/intruder_generators.cpp). The load-bearing invariant is
// the HARD COUNT CAP: a huge numeric range or a big charset^length must produce
// at most kMaxCount payloads -- never OOM, never hang, never crash on degenerate
// args (step 0, from>to, maxLen<minLen, empty charset, invalid dates).
//
// Run via:  ctest -R intruder_generators -V

#include "intruder_generators.hpp"

#include <QCoreApplication>

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

    // ----- types() -----
    chk("types lists numbers+brute+dates",
        types().contains("numbers") && types().contains("brute") && types().contains("dates"));

    std::fprintf(stderr, "intruder_generators_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

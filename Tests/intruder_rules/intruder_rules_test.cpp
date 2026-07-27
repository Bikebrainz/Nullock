// Tests for the Intruder payload-processing rule engine
// (Src/Core/Networking/intruder_rules.cpp). Locks: each local op, delegation to
// the Transcode encode/hash ops, chaining order, and the no-op safety contract
// (an unknown/malformed rule must leave the payload UNCHANGED, never drop it).
//
// Run via:  ctest -R intruder_rules -V

#include "intruder_rules.hpp"

#include <QChar>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::IntruderRules;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
Rule rule(const char *op, const QString &arg = QString()) { return Rule{ QString::fromLatin1(op), arg }; }
const QChar US(0x1f);   // match-replace field delimiter
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- local ops -----
    chk("prefix",            applyRule("val", rule("prefix", "id=")) == "id=val");
    chk("suffix",            applyRule("val", rule("suffix", "!"))   == "val!");
    chk("uppercase",         applyRule("aBc", rule("uppercase"))     == "ABC");
    chk("lowercase",         applyRule("aBc", rule("lowercase"))     == "abc");
    chk("reverse",           applyRule("abc", rule("reverse"))       == "cba");
    {
        // audit-6: reverse operates on CODE POINTS -- a non-BMP glyph must survive
        // (a naive std::reverse over QChars swaps the surrogate pair -> U+FFFD).
        const QString smile = QString::fromUcs4(U"\U0001F600");   // U+1F600
        chk("reverse preserves a non-BMP glyph", applyRule(smile, rule("reverse")) == smile);
    }
    chk("op name is case-insensitive", applyRule("aBc", rule("UPPERCASE")) == "ABC");
    chk("op name trimmed",   applyRule("aBc", rule("  uppercase  ")) == "ABC");

    // ----- no-op safety: a payload must never silently vanish -----
    chk("unknown op -> unchanged", applyRule("val", rule("nonsense")) == "val");
    chk("empty op -> unchanged",   applyRule("val", rule(""))         == "val");

    // ----- match-replace (US-delimited find/replace) -----
    chk("match-replace all occurrences", applyRule("a b a", rule("match-replace", "a" + QString(US) + "X")) == "X b X");
    chk("match-replace to empty",        applyRule("axbxc", rule("match-replace", "x" + QString(US)))       == "abc");
    chk("match-replace no separator -> unchanged", applyRule("val", rule("match-replace", "nofind")) == "val");
    chk("match-replace empty find -> unchanged",   applyRule("val", rule("match-replace", QString(US) + "X")) == "val");

    // ----- delegation to the Transcode workbench -----
    chk("base64-encode delegates", applyRule("abc", rule("base64-encode")) == "YWJj");  // standard base64
    { const QString h = applyRule("abc", rule("sha256")); chk("sha256 -> 64 hex chars", h.size() == 64); }
    { const QString h = applyRule("abc", rule("md5"));    chk("md5 -> 32 hex chars",    h.size() == 32); }
    {
        const QString e = applyRule("a b", rule("url-encode"));
        chk("url-encode delegates (space encoded away)", !e.contains(' ') && e != "a b");
    }

    // ----- chaining: each rule threads into the next, in order -----
    {
        const QString out = applyRules("a b", { rule("url-encode"), rule("prefix", "q=") });
        chk("chain: url-encode THEN prefix", out.startsWith("q=") && !out.contains(' '));
    }
    chk("chain: empty rule list -> unchanged", applyRules("val", {}) == "val");
    chk("chain: order matters",
        applyRules("ab", { rule("prefix", "x"), rule("reverse") }) == "bax");   // "xab" -> "bax"

    // ----- operations() discovery -----
    chk("operations non-empty", !operations().isEmpty());
    chk("operations exclude DECODE ops (payloads are authored, not received)",
        !operations().contains("base64-decode") && !operations().contains("url-decode")
        && !operations().contains("jwt-decode"));
    chk("operations include the local + encode/hash ops",
        operations().contains("prefix") && operations().contains("match-replace")
        && operations().contains("base64-encode") && operations().contains("sha256"));

    std::fprintf(stderr, "intruder_rules_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

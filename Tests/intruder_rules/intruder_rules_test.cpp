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
    // propername: upper-case first, LOWER the rest (Titlecase).
    chk("propername Titlecases + lowers rest",
        applyRule("hELLO wORLD", rule("propername")) == "Hello world");
    chk("propername on lower input",  applyRule("hello", rule("propername")) == "Hello");
    // propername-keep: upper-case first, KEEP the rest.
    chk("propername-keep upper-firsts + keeps rest",
        applyRule("hELLO wORLD", rule("propername-keep")) == "HELLO wORLD");
    chk("propername-keep on lower input", applyRule("hELLO", rule("propername-keep")) == "HELLO");
    {
        // Code-point safe: a leading non-BMP glyph is upper-cased/copied WHOLE.
        const QString smile = QString::fromUcs4(U"\U0001F600");
        chk("propername keeps a leading non-BMP glyph intact (+ lowers rest)",
            applyRule(smile + "ABC", rule("propername")) == smile + "abc");
    }
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

    // ----- regex-replace (Burp match/replace: regex + $-backreferences) -----
    chk("regex-replace basic",
        applyRule("hello123world", rule("regex-replace", "[0-9]+" + QString(US) + "#")) == "hello#world");
    chk("regex-replace ALL occurrences (global)",
        applyRule("a1b2c3", rule("regex-replace", "[0-9]" + QString(US) + "_")) == "a_b_c_");
    chk("regex-replace back-references $1/$2/$3",
        applyRule("2026-08-12",
                  rule("regex-replace", "(\\d+)-(\\d+)-(\\d+)" + QString(US) + "$3/$2/$1")) == "12/08/2026");
    chk("regex-replace $0 = whole match",
        applyRule("abc", rule("regex-replace", "b" + QString(US) + "[$0]")) == "a[b]c");
    chk("regex-replace $$ -> literal dollar",
        applyRule("x", rule("regex-replace", "x" + QString(US) + "$$")) == "$");
    chk("regex-replace invalid regex -> unchanged (fail-safe)",
        applyRule("val", rule("regex-replace", "[unclosed" + QString(US) + "X")) == "val");
    chk("regex-replace no separator -> unchanged",
        applyRule("val", rule("regex-replace", "nopat")) == "val");
    chk("regex-replace empty pattern -> unchanged",
        applyRule("val", rule("regex-replace", QString(US) + "X")) == "val");
    chk("regex-replace is advertised in operations()", operations().contains("regex-replace"));

    // ----- substring / reverse-substring (Burp payload-processing) -----
    // substring: START offset (0-indexed) + optional length.
    chk("substring offset+length",  applyRule("abcdefgh", rule("substring", "2,3")) == "cde");
    chk("substring offset to end",   applyRule("abcdefgh", rule("substring", "2"))   == "cdefgh");
    chk("substring offset 0",        applyRule("abcdefgh", rule("substring", "0,3")) == "abc");
    // reverse-substring: END offset from the end, length back from that end offset.
    chk("reverse-substring mid",     applyRule("abcdefgh", rule("reverse-substring", "2,3")) == "def");
    chk("reverse-substring last-N",  applyRule("abcdefgh", rule("reverse-substring", "0,2")) == "gh");
    // Fail-safe: out-of-range / malformed leaves the payload UNCHANGED (never vanish).
    chk("substring out-of-range -> unchanged",  applyRule("abc", rule("substring", "100,5")) == "abc");
    chk("substring no numeric offset -> unchanged", applyRule("abc", rule("substring", "x")) == "abc");
    chk("substring negative offset -> unchanged", applyRule("abc", rule("substring", "-1,2")) == "abc");
    chk("reverse-substring out-of-range -> unchanged",
        applyRule("abc", rule("reverse-substring", "100,2")) == "abc");
    {
        // Code-point safety: a non-BMP glyph is ONE unit, never split.
        const QString smile = QString::fromUcs4(U"\U0001F600");   // U+1F600
        chk("substring extracts a whole non-BMP glyph",
            applyRule("a" + smile + "b", rule("substring", "1,1")) == smile);
        chk("substring does not split a surrogate pair",
            applyRule("a" + smile + "b", rule("substring", "0,2")) == "a" + smile);
    }
    chk("substring / reverse-substring advertised in operations()",
        operations().contains("substring") && operations().contains("reverse-substring"));

    // ----- url-encode-chars (Burp "URL-encode these characters" safety net) -----
    // Percent-encode ONLY the listed characters, leaving the rest verbatim.
    chk("url-encode-chars encodes only the listed set",
        applyRule("a=b&c", rule("url-encode-chars", "=&")) == "a%3Db%26c");
    chk("url-encode-chars leaves unlisted specials verbatim",
        applyRule("a=b#c", rule("url-encode-chars", "=")) == "a%3Db#c");
    chk("url-encode-chars encodes a space when listed",
        applyRule("a b", rule("url-encode-chars", " ")) == "a%20b");
    chk("url-encode-chars uses UPPERCASE hex",
        applyRule("=", rule("url-encode-chars", "=")) == "%3D");
    chk("url-encode-chars no listed char present -> unchanged",
        applyRule("abc", rule("url-encode-chars", "=&")) == "abc");
    chk("url-encode-chars empty set -> no-op",
        applyRule("a=b", rule("url-encode-chars", "")) == "a=b");
    {
        // Code-point-safe encoding: a multi-byte char in the set encodes ALL its
        // UTF-8 bytes; the euro sign U+20AC is E2 82 AC.
        const QString euro = QString::fromUtf8("\xE2\x82\xAC");
        chk("url-encode-chars encodes a multi-byte char's full UTF-8",
            applyRule("a" + euro + "b", rule("url-encode-chars", euro)) == "a%E2%82%ACb");
        // Code-point-safe pass-through: a non-BMP glyph NOT in the set survives
        // intact (never split into lone surrogates).
        const QString smile = QString::fromUcs4(U"\U0001F600");
        chk("url-encode-chars passes a non-target non-BMP glyph through intact",
            applyRule("x" + smile + "y", rule("url-encode-chars", "=")) == "x" + smile + "y");
    }
    chk("url-encode-chars is advertised in operations()",
        operations().contains("url-encode-chars"));
    // As the GLOBAL safety net the Intruder appends it as the FINAL chain step:
    // prove that composition here (prefix first, then encode the '=' it added).
    chk("url-encode-chars as a trailing global step encodes earlier output",
        applyRules("v", { rule("prefix", "id="), rule("url-encode-chars", "=") }) == "id%3Dv");

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

    // ----- DECODE payload rules (Burp "Decode" parity, #40) -----
    // The decode inverse of each advertised reversible encode is now offered:
    // real payload lists arrive pre-encoded. Behaviour locks -- prove the
    // advertised op actually decodes, so advertising it isn't a hollow label.
    chk("base64-decode round-trips",  applyRule("YWJj", rule("base64-decode")) == "abc");
    chk("url-decode round-trips",     applyRule("a%20b", rule("url-decode"))   == "a b");
    chk("hex-decode round-trips",     applyRule("616263", rule("hex-decode"))  == "abc");
    chk("html-decode round-trips",    applyRule("a&amp;b", rule("html-decode")) == "a&b");
    // encode->decode chain returns the original (the decode-transform workflow).
    chk("chain base64-encode THEN base64-decode is identity",
        applyRules("payload!", { rule("base64-encode"), rule("base64-decode") }) == "payload!");
    // a decode of non-decodable input is a SAFE no-op (payload never vanishes).
    chk("hex-decode of non-hex -> unchanged (fail-safe)",
        applyRule("not-hex!", rule("hex-decode")) == "not-hex!");

    // ----- operations() discovery -----
    chk("operations non-empty", !operations().isEmpty());
    chk("operations now ADVERTISE the standard decode ops (Burp Decode parity)",
        operations().contains("base64-decode") && operations().contains("base64url-decode")
        && operations().contains("url-decode") && operations().contains("hex-decode")
        && operations().contains("html-decode"));
    chk("operations still EXCLUDE jwt-decode (multi-line JSON, not a payload transform)",
        !operations().contains("jwt-decode"));
    chk("operations include the local + encode/hash ops",
        operations().contains("prefix") && operations().contains("match-replace")
        && operations().contains("base64-encode") && operations().contains("sha256"));
    chk("operations advertise the propername case rules",
        operations().contains("propername") && operations().contains("propername-keep"));

    std::fprintf(stderr, "intruder_rules_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

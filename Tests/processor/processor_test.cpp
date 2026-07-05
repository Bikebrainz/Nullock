// Regression corpus for the Payload Processor (pure filter-bypass variant gen).
// Locks each transform's exact output on a known payload, the full-process fan-
// out, and identity fallback for an unknown transform.
//
// Run via:  ctest -R processor -V

#include "processor.hpp"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::Processor;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString one(const char *id, const QString &p) { return applyOne(id, p).output; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    chk("transforms: 12 listed", transforms().size() == 12);

    // ===== per-transform exact outputs =================================
    chk("url-encode-all", one("url-encode-all", "A B") == "%41%20%42");
    chk("double-url-encode", one("double-url-encode", "A") == "%2541");
    chk("double-url-encode (space)", one("double-url-encode", "A B") == "%2541%2520%2542");
    chk("uppercase", one("uppercase", "SeLeCt") == "SELECT");
    chk("toggle-case", one("toggle-case", "select") == "SeLeCt");
    chk("toggle-case skips non-letters", one("toggle-case", "a1b2c") == "A1b2C"
                                          || one("toggle-case", "a1b2c") == "A1B2c");
    chk("html-hex-entities", one("html-hex-entities", "<") == "&#x3c;");
    chk("html-dec-entities", one("html-dec-entities", "<") == "&#60;");
    chk("unicode-escape", one("unicode-escape", "<") == "\\u003c");
    chk("sql-comment-space", one("sql-comment-space", "OR 1=1") == "OR/**/1=1");
    chk("tab-for-space", one("tab-for-space", "a b") == "a%09b");
    chk("newline-for-space", one("newline-for-space", "a b") == "a%0ab");
    chk("plus-for-space", one("plus-for-space", "a b") == "a+b");
    chk("append-nullbyte", one("append-nullbyte", "file.php") == "file.php%00");

    // ===== unknown -> identity =========================================
    {
        const Variant v = applyOne("bogus-transform", "keepme");
        chk("unknown transform -> identity name", v.name == "identity");
        chk("unknown transform -> payload unchanged", v.output == "keepme");
    }

    // ===== process() fan-out ===========================================
    {
        const auto vs = process("' OR 1=1");
        chk("process: one variant per transform", vs.size() == 12);
        // each variant carries a non-empty name + note
        bool allLabeled = true;
        for (const auto &v : vs) if (v.name.isEmpty() || v.note.isEmpty()) allLabeled = false;
        chk("process: all variants labeled", allLabeled);
        // the sql-comment-space variant is present with the expected output
        bool found = false;
        for (const auto &v : vs)
            if (v.name == "sql-comment-space" && v.output == "'/**/OR/**/1=1") found = true;
        chk("process: contains the sql-comment variant", found);
    }

    // ===== round-trip sanity: url-encode-all is reversible =============
    {
        const QString enc = one("url-encode-all", "a=b&c=<script>");
        // every char became %XX -> length is 3x the utf8 byte length
        chk("url-encode-all: 3x byte length", enc.size() == QString("a=b&c=<script>").toUtf8().size() * 3);
    }

    std::fprintf(stderr, "processor_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

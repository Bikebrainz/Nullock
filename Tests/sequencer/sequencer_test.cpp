// Regression corpus for the token-randomness sequencer's pure logic. An
// adversarial audit confirmed 11 gaps; this locks the fixes:
//   FN fixes:
//     - a SHORT token (8-hex ~32 bits) is brute-forceable however flat its
//       characters -> NOT "looks-random" (effective-keyspace scoring; the
//       canonical statistical-randomness != unpredictability miss);
//     - a decimal counter crossing a units-9 carry (97,98,99,100) is detected
//       (base is auto-detected, no longer hex-first);
//     - a strictly-monotonic non-constant-delta sequence (timestamps) is flagged.
//   FP fixes:
//     - 3 numeric tokens with one matching delta and an unrelated third are NOT
//       flagged sequential (the (n-2)*3/4 -> 0 truncation);
//     - a constant fixed prefix doesn't inflate the longest-common-substring;
//     - a long strong token (40-hex ~160 bits) IS "looks-random" (no alphabet
//       penalty).
//
// Run via:  ctest -R sequencer -V

#include "sequencer.hpp"

#include <QCoreApplication>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <cstdio>

using namespace Nullock::Core;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QStringList L(std::initializer_list<const char *> l) {
    QStringList s; for (const char *c : l) s << QString::fromLatin1(c); return s;
}
// Call the free analyzeTokens() (not the Sequencer QObject) so the test links
// only sequencer_logic.obj against Qt6::Core -- referencing the QObject would
// drag in Networking's shared moc compilation and the FrontEndGUI chain.
QJsonObject analyze(const QStringList &t) { return analyzeTokens(t); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== #1 effective keyspace: short token = brute-forceable ===========
    {
        // 12 distinct 8-hex tokens (~32 effective bits) -- flat per byte but
        // recoverable. Must NOT be graded looks-random.
        const QJsonObject r = analyze(L({
            "1a2b3c4d","9f8e7d6c","00112233","deadbeef","cafe1234","5566aabb",
            "0f1e2d3c","98765432","abcdef01","13579bdf","2468ace0","f0e1d2c3"}));
        chk("8-hex corpus (~32 effective bits) -> NOT looks-random",
            r["verdict"].toString() != "looks-random" && r["score"].toInt() < 80);
        chk("8-hex corpus exposes a low effectiveBitsPerToken (<64)",
            r["shannon"].toObject()["effectiveBitsPerToken"].toDouble() < 64.0);
    }

    // ===== #4 long strong token is NOT alphabet-penalized =================
    {
        // 40-hex tokens (~160 effective bits) in non-sorted order.
        const QJsonObject r = analyze(L({
            "a3f19c4b7e2d8061f5a9c3e7b1d4082f6c9a1e35",
            "5e1d9a7c3f0b6248e9d1a4c7f2b8053196e4d7a0",
            "0c7b2e9f4a1d6385c0e9b2f7a4d18305e6c1b9f2",
            "f29a4d7c1e0b58369c2f7a4d1e8b0537a6c9f1e4",
            "7b1e4c9a2f8d05637e1c4a9f2d6b80531a7e4c92",
            "2d8f1a4c7e9b06352f8d1a4c7e0b9536a2f8d1c4",
            "9e2c7f4a1d8b06539c2e7f4a1d0b8536e9c2f7a4",
            "4a1d7c9e2f8b0635a4d1c7e9f2b8053640a1d7ce",
            "c7e2f9a4d1b08536c7e2f9a4d1b0853607c2e9f4",
            "1f8a4c7e2d9b06351f8a4c7e2d0b9536f1a8c4e7"}));
        chk("40-hex corpus (~160 effective bits) -> looks-random (no alphabet penalty)",
            r["verdict"].toString() == "looks-random" && r["score"].toInt() >= 80);
        chk("strong random corpus is NOT flagged monotonic",
            r["sequential"].toObject()["looksMonotonic"].toBool() == false);
    }

    // ===== 64-bit boundary: a genuine 16-hex (NIST-min) token passes ======
    {
        // 16-hex = exactly 64 bits (the NIST SP 800-63B minimum). Measured
        // Shannon undershoots 4.0 bits/char, so the cutoff must absorb that or
        // a real minimum-strength token gets false-flagged predictable.
        const QJsonObject r = analyze(L({
            "9f3a1c7e2d8b4056","1e7c4a9f2d6b8035","c4a91f7e2d3b8056",
            "7e2d9c4a1f8b6035","a1f7c4e92d8b3056","3b8d1a4c7e2f9056",
            "f2d8a1c4e97b3056","4c7e2d9a1f8b6035","8b1f4a7c2e9d3056",
            "2e9d4a7c1f8b6035","d4a91f7c2e8b3056","6035c4a91f7e2d8b"}));
        chk("16-hex (~64-bit, NIST min) corpus -> looks-random (no finite-sample FP)",
            r["verdict"].toString() == "looks-random");
    }

    // ===== #5 base detection: decimal counters (incl. the 9->0 carry) =====
    chk("decimal counter 18..23 -> sequential",
        analyze(L({"18","19","20","21","22","23"}))["sequential"].toObject()["looksSequential"].toBool());
    chk("decimal counter crossing 99->100 -> sequential (base auto-detect)",
        analyze(L({"97","98","99","100","101","102"}))["sequential"].toObject()["looksSequential"].toBool());

    // ===== #2 n=3 threshold: unrelated third token is NOT sequential ======
    chk("3 tokens 5,10,9999 (unrelated third) -> NOT sequential (FP fix)",
        !analyze(L({"5","10","9999"}))["sequential"].toObject()["looksSequential"].toBool());
    chk("3 tokens 100,101,102 (real counter) -> sequential",
        analyze(L({"100","101","102"}))["sequential"].toObject()["looksSequential"].toBool());

    // ===== #6 monotonic (non-constant-delta) detection ====================
    {
        const QJsonObject r = analyze(L({
            "1700000001","1700000007","1700000010","1700000022",
            "1700000035","1700000050","1700000061","1700000099"}));
        chk("monotonic timestamps -> looksMonotonic true",
            r["sequential"].toObject()["looksMonotonic"].toBool());
        chk("monotonic timestamps -> NOT looksSequential (deltas vary)",
            !r["sequential"].toObject()["looksSequential"].toBool());
    }

    // ===== #3/#8 LCS strips a constant prefix =============================
    {
        const QJsonObject r = analyze(L({"REL_5f3a","REL_9c1d","REL_2e8b","REL_7a4f"}));
        chk("constant 'REL_' prefix is stripped -> lcs shorter than the prefix",
            r["lcs"].toObject()["length"].toInt() < 4);
    }

    // ===== #7 entropy sanity: single-symbol corpus -> 0 bits/byte =========
    {
        const QJsonObject r = analyze(L({"aaaaaaaa","aaaaaaaa","aaaaaaaa"}));
        chk("all-same-char corpus -> 0 bits/byte and predictable",
            r["shannon"].toObject()["bitsPerByte"].toDouble() == 0.0
            && r["verdict"].toString() == "predictable");
    }

    // ===== no crash on empty / tiny =======================================
    chk("empty corpus -> no-data", analyze(QStringList())["verdict"].toString() == "no-data");
    chk("single token -> does not crash, scores",
        analyze(L({"abc123"}))["n"].toInt() == 1);

    std::fprintf(stderr, "sequencer_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

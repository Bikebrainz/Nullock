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
// Deeper tests (statistical flatness != cryptographic unpredictability), gated
// behind a >= 20-token corpus so they never perturb the legacy small-corpus
// grades above:
//     - a per-position-leaky corpus (high char entropy / high effective keyspace
//       but biased columns) -> positional.biased -> flagged;
//     - a linear/LCG-shaped byte generator (flat per-byte, recoverable) ->
//       bitLevel serial-correlation -> flagged;
//     - a strong MT random corpus -> NONE of the deeper sub-tests fire (these
//       tests cannot, and do not claim to, catch MT) -> stays looks-random.
//
// Run via:  ctest -R sequencer -V

#include "sequencer.hpp"

#include <QCoreApplication>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

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
    // A DESCENDING counter (delta -1) is as predictable as an ascending one.
    chk("descending decimal counter 102..97 -> sequential (negative delta)",
        analyze(L({"102","101","100","99","98","97"}))["sequential"].toObject()["looksSequential"].toBool());
    // A HEX-base counter (unambiguous hex tokens) -> sequential via base auto-detect.
    chk("hex counter aa..b0 -> sequential (hex base auto-detect)",
        analyze(L({"aa","ab","ac","ad","ae","af","b0"}))["sequential"].toObject()["looksSequential"].toBool());

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

    // ===== audit-11: cross-sample VARIETY (the fail-open) =================
    {
        // Only TWO distinct values, alternating. Every per-byte/entropy test passes
        // (both are long and hex-ish) and nothing else looks at DISTINCTNESS, so this
        // scored 100/"looks-random" -- a catastrophic fail-open for session tokens.
        const QString A = "a3f19c4b7e2d8061.f5a9c3e7b1d4082f6c9a1e35";
        const QString B = "5e1d9a7c3f0b6248.e9d1a4c7f2b8053196e4d7a0";
        QStringList two;
        for (int i = 0; i < 10; ++i) { two << A << B; }
        const QJsonObject r = analyze(two);
        chk("2-distinct-value corpus -> NOT looks-random (variety fail-open fix)",
            r["verdict"].toString() != "looks-random");
        chk("2-distinct-value corpus reports distinctTokens == 2",
            r["distinctTokens"].toInt() == 2);
    }
    {
        // A single repeat in an otherwise-strong corpus is still a red flag.
        const QJsonObject r = analyze(L({
            "9f3a1c7e2d8b4056","1e7c4a9f2d6b8035","c4a91f7e2d3b8056",
            "7e2d9c4a1f8b6035","a1f7c4e92d8b3056","3b8d1a4c7e2f9056",
            "f2d8a1c4e97b3056","4c7e2d9a1f8b6035","8b1f4a7c2e9d3056",
            "2e9d4a7c1f8b6035","d4a91f7c2e8b3056","9f3a1c7e2d8b4056"}));  // last == first
        chk("a duplicate token in a strong corpus is penalized",
            r["distinctTokens"].toInt() == 11 && r["score"].toInt() < 100);
    }

    // ===== audit-11: effective keyspace ignores a CONSTANT affix ==========
    {
        // 32 constant hex chars + 8 varying: the real keyspace is the 8 hex chars
        // (~32 bits), but multiplying bits/symbol by the FULL 40-char length credited
        // the dead prefix and scored it like a ~160-bit token.
        const QString P = "0123456789abcdef0123456789abcdef";
        QStringList affix;
        for (const char *tail : { "1a2b3c4d", "9f8e7d6c", "00112233", "deadbeef",
                                  "cafe1234", "5566aabb", "0f1e2d3c", "98765432",
                                  "abcdef01", "13579bdf", "2468ace0", "f0e1d2c3" })
            affix << P + QString::fromLatin1(tail);
        const QJsonObject r = analyze(affix);
        chk("constant-prefix corpus: variableLen is the varying region only",
            r["shannon"].toObject()["variableLen"].toInt() == 8);
        chk("constant-prefix corpus -> NOT looks-random (affix credits no keyspace)",
            r["verdict"].toString() != "looks-random");
    }

    // ===== audit-11: LCS on a fully-constant corpus =======================
    {
        // pre and suf both spanned the whole token, zeroing every variable region and
        // returning an EMPTY lcs exactly when the structure is TOTAL.
        QStringList same;
        for (int i = 0; i < 20; ++i) same << "a3f19c4b7e2d8061f5a9c3e7b1d4082f6c9a1e35";
        const QJsonObject r = analyze(same);
        chk("fully-constant corpus reports a non-empty LCS (was empty)",
            r["lcs"].toObject()["length"].toInt() > 0);
        chk("fully-constant corpus is predictable", r["verdict"].toString() == "predictable");
    }

    // ===== audit-11: looksSequential anchors on the MEDIAN delta ==========
    {
        // A counter with ONE gap at the head: the first delta (0x1000) was taken as
        // the reference, matched nothing, and the whole counter went undetected.
        const QJsonObject r = analyze(L({
            "deadbe001000","deadbe002000","deadbe002001","deadbe002002",
            "deadbe002003","deadbe002004"}));
        chk("counter with a head outlier -> still sequential (median delta)",
            r["sequential"].toObject()["looksSequential"].toBool());
    }

    // ===== no crash on empty / tiny =======================================
    chk("empty corpus -> no-data", analyze(QStringList())["verdict"].toString() == "no-data");
    chk("single token -> does not crash, scores",
        analyze(L({"abc123"}))["n"].toInt() == 1);

    // ===== deeper tests: statistical flatness != unpredictability ==========
    // These activate only on a corpus of >= 20 tokens (so every legacy corpus
    // above keeps its grade), hence they are exercised with freshly-built
    // 32-token corpora rather than hand-typed literals.
    {
        auto hexOf = [](const std::vector<uint8_t> &b) {
            static const char *H = "0123456789abcdef";
            QString s; s.reserve(int(b.size()) * 2);
            for (uint8_t x : b) { s += QChar(H[x >> 4]); s += QChar(H[x & 0xF]); }
            return s;
        };

        // --- negative: a strong random corpus (mt19937_64). MT passes monobit /
        // serial / per-position by design (these tests CANNOT catch MT), so it
        // must trip none of the deeper sub-tests and stay looks-random.
        {
            std::mt19937_64 rng(0xC0FFEEULL);
            QStringList strong;
            for (int i = 0; i < 32; ++i) {
                std::vector<uint8_t> b(16);
                for (auto &x : b) x = uint8_t(rng());
                strong << hexOf(b);
            }
            const QJsonObject r  = analyze(strong);
            const QJsonObject p  = r["positional"].toObject();
            const QJsonObject bl = r["bitLevel"].toObject();
            chk("strong 32x16B random -> deeper tests are applicable",
                p["applicable"].toBool() && bl["applicable"].toBool());
            chk("strong random -> positional NOT biased", !p["biased"].toBool());
            chk("strong random -> bitLevel NOT failed",   !bl["anyFailed"].toBool());
            chk("strong random -> still looks-random",
                r["verdict"].toString() == "looks-random");
        }

        // --- positive A: per-position leak. 32 tokens x 32 hex chars; columns
        // 0..25 are full hex, the last 6 columns carry only {0,f}. Char entropy
        // and effective keyspace stay high (the LEGACY score would pass it), but
        // six columns leak structure -> positional.biased -> flagged.
        {
            std::mt19937_64 rng(0x0BADC0DEULL);
            QStringList leaky;
            for (int i = 0; i < 32; ++i) {
                QString s;
                for (int c = 0; c < 32; ++c) {
                    if (c < 26) s += QChar("0123456789abcdef"[rng() & 0xF]);
                    else        s += QChar((rng() & 1) ? 'f' : '0');
                }
                leaky << s;
            }
            const QJsonObject r = analyze(leaky);
            chk("per-position-leaky corpus -> positional.biased",
                r["positional"].toObject()["biased"].toBool());
            chk("per-position-leaky corpus -> NOT looks-random",
                r["verdict"].toString() != "looks-random" && r["score"].toInt() < 80);
            chk("per-position-leaky corpus -> high effective keyspace (legacy would pass)",
                r["shannon"].toObject()["effectiveBitsPerToken"].toDouble() > 64.0);
        }

        // --- positive B: a linear/LCG-shaped byte generator. Each token's 16
        // bytes are an arithmetic walk b[k]=b[k-1]+1 from a per-token random seed:
        // per-byte values span the range (high char entropy, high effective
        // keyspace, balanced bits -> passes monobit, per-position fine) -- the
        // ONLY tell is a strong lag-1 byte correlation. The canonical "flat
        // statistics, fully recoverable generator" case.
        {
            std::mt19937_64 rng(0x5EED1234ULL);
            QStringList lin;
            for (int i = 0; i < 32; ++i) {
                std::vector<uint8_t> b(16);
                uint8_t cur = uint8_t(rng());
                for (int k = 0; k < 16; ++k) { b[k] = cur; cur = uint8_t(cur + 1); }
                lin << hexOf(b);
            }
            const QJsonObject r  = analyze(lin);
            const QJsonObject bl = r["bitLevel"].toObject();
            chk("linear/LCG byte corpus -> serial-correlation failed",
                bl["serialCorrelation"].toObject()["failed"].toBool());
            chk("linear/LCG byte corpus -> NOT looks-random",
                r["verdict"].toString() != "looks-random" && r["score"].toInt() < 80);
            chk("linear/LCG byte corpus -> NOT caught by legacy sequential/monotonic",
                !r["sequential"].toObject()["looksSequential"].toBool()
                && !r["sequential"].toObject()["looksMonotonic"].toBool());
        }
    }

    // ===== FIPS 140-2 bit-level tests (poker / runs / long-runs) =========
    // Pure helpers over a byte stream, tested directly with deterministic
    // inputs (no RNG -> no flake). These are the tests the Sequencer was
    // missing; they now feed bitLevelTests + the analysis JSON.
    {
        // longest run of identical bits
        chk("longRun: 4x 0xFF -> 32", longestBitRun(QByteArray(4, char(0xFF))) == 32);
        chk("longRun: 0xAA alternating -> 1", longestBitRun(QByteArray::fromHex("AAAAAAAA")) == 1);
        chk("longRun: 0x00 0xFF -> 8", longestBitRun(QByteArray::fromHex("00FF")) == 8);
        // poker chi-square (15 dof): perfectly uniform nibbles -> 0; all-zero
        // -> every nibble in one bin -> huge; too short -> -1 sentinel.
        QByteArray uniform;
        for (int i = 0; i < 10; ++i) uniform += QByteArray::fromHex("0123456789abcdef");
        chk("poker: uniform nibbles -> chi ~ 0", fipsPokerChiSquare(uniform) < 1e-6);
        chk("poker: all-zero -> chi huge (fails)", fipsPokerChiSquare(QByteArray(40, '\0')) > 30.578);
        chk("poker: too short -> -1 sentinel", fipsPokerChiSquare(QByteArray(4, '\0')) < 0.0);
        // runs z-score: perfectly alternating -> far too many runs (large +z);
        // a constant stream is degenerate (no second symbol) -> z = 0, no test.
        chk("runs: alternating 0xAA -> huge +z (fails)", fipsRunsZScore(QByteArray(20, char(0xAA))) > 2.576);
        chk("runs: constant 0xFF -> degenerate z = 0", fipsRunsZScore(QByteArray(20, char(0xFF))) == 0.0);
    }

    std::fprintf(stderr, "sequencer_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

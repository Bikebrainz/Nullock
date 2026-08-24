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

    // ===== per-position effective entropy (roadmap: sequencer) ============
    // Effective entropy = sum of log2(observed alphabet size) per column. It
    // credits a token's TRUE keyspace region-by-region, where the global
    // bits/char * length blends a reduced-alphabet region into the average.
    {
        std::mt19937 gen(24680);
        static const char HEX[] = "0123456789abcdef";
        // Structured: 8 random hex columns (4 bits each) + 24 columns drawn from
        // a 2-symbol {x,y} alphabet (1 bit each) that VARY per token (so they are
        // NOT stripped as a common affix). True keyspace = 8*4 + 24*1 = 56 bits.
        QStringList structured;
        for (int i = 0; i < 48; ++i) {
            QString t;
            for (int c = 0; c < 8;  ++c) t += QChar(QLatin1Char(HEX[gen() % 16]));
            for (int c = 0; c < 24; ++c) t += QChar((gen() & 1u) ? QLatin1Char('x') : QLatin1Char('y'));
            structured << t;
        }
        const QJsonObject rs = analyze(structured);
        const double pp   = rs["shannon"].toObject()["perPositionEffectiveBits"].toDouble();
        const double glob = rs["shannon"].toObject()["effectiveBitsPerToken"].toDouble();
        chk("perPositionEffectiveBits ~= the true 56-bit keyspace of a reduced-alphabet region",
            pp > 48.0 && pp < 62.0);
        chk("perPositionEffectiveBits is BELOW the global rate*length estimate for a structured token",
            pp < glob);

        // Uniform: every one of 32 columns is random hex -> ~128-bit keyspace,
        // and per-position should agree with the global estimate.
        QStringList uniform;
        for (int i = 0; i < 48; ++i) {
            QString t;
            for (int c = 0; c < 32; ++c) t += QChar(QLatin1Char(HEX[gen() % 16]));
            uniform << t;
        }
        const QJsonObject ru = analyze(uniform);
        const double ppu   = ru["shannon"].toObject()["perPositionEffectiveBits"].toDouble();
        const double globu = ru["shannon"].toObject()["effectiveBitsPerToken"].toDouble();
        chk("perPositionEffectiveBits ~= 128 on a uniform 32-hex corpus",
            ppu > 115.0 && ppu < 132.0);
        chk("perPositionEffectiveBits ~= the global estimate when every column is uniform",
            (ppu > globu ? ppu - globu : globu - ppu) < 0.20 * globu);
    }

    // ===== per-bit-position monobit (roadmap: sequencer) =================
    // A single stuck/biased bit is diluted 1:(width*8) in the aggregate monobit
    // but must be caught when monobit is evaluated at EVERY bit position.
    {
        std::mt19937 gen(13579);
        static const char HEX[]  = "0123456789abcdef";
        static const char HIGH[] = "89abcdef";   // hex nibbles whose top bit is 1
        // Stuck-bit corpus: 48x 32-hex tokens where the very first nibble is
        // always drawn from {8..f}, so bit position 0 (MSB of byte 0) is ALWAYS 1;
        // every other bit is random. The aggregate monobit dilutes this and passes.
        QStringList stuck;
        for (int i = 0; i < 48; ++i) {
            QString t;
            t += QChar(QLatin1Char(HIGH[gen() % 8]));            // nibble with fixed top bit
            for (int c = 1; c < 32; ++c) t += QChar(QLatin1Char(HEX[gen() % 16]));
            stuck << t;
        }
        const QJsonObject rb = analyze(stuck)["bitLevel"].toObject();
        chk("per-bit monobit FLAGS a single stuck bit position",
            rb["perBitMonobit"].toObject()["failed"].toBool()
            && rb["perBitMonobit"].toObject()["failures"].toInt() >= 1);
        chk("per-bit monobit catches what the diluted aggregate monobit misses",
            rb["monobit"].toObject()["failed"].toBool() == false);

        // Clean corpus: all 32 hex columns fully random -> no stuck position.
        QStringList clean;
        for (int i = 0; i < 48; ++i) {
            QString t;
            for (int c = 0; c < 32; ++c) t += QChar(QLatin1Char(HEX[gen() % 16]));
            clean << t;
        }
        const QJsonObject rc = analyze(clean)["bitLevel"].toObject();
        chk("per-bit monobit does NOT flag a clean random corpus",
            rc["perBitMonobit"].toObject()["failed"].toBool() == false
            && rc["perBitMonobit"].toObject()["failures"].toInt() == 0);
    }

    // ===== chi-square survival p-value (backs the per-position char test) =
    // Verified against standard chi-square upper-tail critical values.
    {
        auto near = [](double a, double b, double tol) { return (a > b ? a - b : b - a) < tol; };
        chk("chiSq survival: dof=1  chi=3.841  ~= 0.05", near(chiSquareSurvival(3.841, 1), 0.05, 0.003));
        chk("chiSq survival: dof=1  chi=6.635  ~= 0.01", near(chiSquareSurvival(6.635, 1), 0.01, 0.002));
        chk("chiSq survival: dof=3  chi=11.345 ~= 0.01", near(chiSquareSurvival(11.345, 3), 0.01, 0.002));
        chk("chiSq survival: dof=10 chi=18.307 ~= 0.05", near(chiSquareSurvival(18.307, 10), 0.05, 0.003));
        chk("chiSq survival: dof=15 chi=30.578 ~= 0.01", near(chiSquareSurvival(30.578, 15), 0.01, 0.002));
        // Small chi relative to dof exercises the SERIES branch (x < a+1).
        chk("chiSq survival: dof=10 chi=3.940 ~= 0.95 (series branch)", near(chiSquareSurvival(3.940, 10), 0.95, 0.004));
        chk("chiSq survival: extremes (1.0 at chi=0, ~0 for a huge chi)",
            chiSquareSurvival(0.0, 5) == 1.0 && chiSquareSurvival(500.0, 5) < 1e-9);
    }

    // ===== per-position character chi-square (roadmap: sequencer) =========
    {
        std::mt19937 gen(97531);
        static const char HEX[] = "0123456789abcdef";
        // 48x 32-hex tokens, but column 8 is 'a' ~75% of the time (rest random) --
        // a per-column distribution skew the global char frequency hides. Only
        // that column should fail the per-position chi-square.
        QStringList biased;
        for (int i = 0; i < 48; ++i) {
            QString t;
            for (int c = 0; c < 32; ++c) {
                if (c == 8) t += ((gen() % 4u) ? QChar(QLatin1Char('a')) : QChar(QLatin1Char(HEX[gen() % 16])));
                else        t += QChar(QLatin1Char(HEX[gen() % 16]));
            }
            biased << t;
        }
        const QJsonObject cb = analyze(biased)["positional"].toObject()["charChiSquare"].toObject();
        chk("per-position char chi-square FLAGS a biased column",
            cb["biased"].toBool() && cb["failures"].toInt() >= 1);

        QStringList clean;
        for (int i = 0; i < 48; ++i) {
            QString t; for (int c = 0; c < 32; ++c) t += QChar(QLatin1Char(HEX[gen() % 16]));
            clean << t;
        }
        const QJsonObject cc = analyze(clean)["positional"].toObject()["charChiSquare"].toObject();
        chk("per-position char chi-square does NOT flag a clean corpus",
            cc["biased"].toBool() == false && cc["failures"].toInt() == 0);
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

    // ===== the recovered STEP value (seqObj["delta"]) is surfaced to consumers
    // but only the boolean was ever pinned. Lock the VALUE so a detector that
    // flags "sequential" yet reports the wrong step (sign or magnitude) fails.
    chk("sequential delta value: 18..23 -> delta == +1",
        analyze(L({"18","19","20","21","22","23"}))["sequential"].toObject()["delta"].toDouble() == 1.0);
    chk("sequential delta value: descending 102..97 -> delta == -1",
        analyze(L({"102","101","100","99","98","97"}))["sequential"].toObject()["delta"].toDouble() == -1.0);
    // A step-2 counter proves delta is the MEASURED step, not hardcoded to +/-1.
    chk("sequential delta value: step-2 counter 10..20 -> delta == +2",
        analyze(L({"10","12","14","16","18","20"}))["sequential"].toObject()["delta"].toDouble() == 2.0);

    // ===== #153: WRAPPED counters (prefix/suffix). parseToken rejects the whole
    // token, so before wrapper-stripping these were looksSequential:false -- a
    // false negative Burp's low-entropy inference still caught. Now detected, and
    // the recovered delta is the TRUE step (only the constant wrapper is stripped).
    {
        const QJsonObject a = analyze(L({"sess_1001","sess_1002","sess_1003","sess_1004","sess_1005"}));
        chk("prefixed counter sess_1001.. -> sequential", a["sequential"].toObject()["looksSequential"].toBool());
        chk("prefixed counter sess_1001.. -> delta == +1", a["sequential"].toObject()["delta"].toDouble() == 1.0);

        const QJsonObject b = analyze(L({"42_tok","43_tok","44_tok","45_tok","46_tok","47_tok"}));
        chk("suffixed counter NN_tok -> sequential", b["sequential"].toObject()["looksSequential"].toBool());
        chk("suffixed counter NN_tok -> delta == +1", b["sequential"].toObject()["delta"].toDouble() == 1.0);

        // zero-padded, wrapped: "id_007".."id_012" -> the '0' padding stays in the
        // number (leading zeros parse base-10), delta is the true +1.
        const QJsonObject c = analyze(L({"id_007","id_008","id_009","id_010","id_011","id_012"}));
        chk("zero-padded wrapped counter id_007.. -> sequential", c["sequential"].toObject()["looksSequential"].toBool());
        chk("zero-padded wrapped counter id_007.. -> delta == +1", c["sequential"].toObject()["delta"].toDouble() == 1.0);
    }

    // ===== #153 REGRESSION guards: wrapper-stripping must NOT corrupt the delta of
    // a bare stepped counter (its step lives in trailing digits, an all-DIGIT common
    // suffix that must be kept), and must NOT invent a counter from wrapped noise.
    chk("stepped counter 100,200,300 -> delta stays +100 (all-digit suffix NOT stripped)",
        analyze(L({"100","200","300","400","500"}))["sequential"].toObject()["delta"].toDouble() == 100.0);
    chk("wrapped NON-counter node_{88,12,57,31,90} -> NOT sequential (no false positive)",
        !analyze(L({"node_88","node_12","node_57","node_31","node_90"}))["sequential"].toObject()["looksSequential"].toBool());

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

    // ===== #144: positional length-tolerance diagnostics ==================
    // A skipped positional test must be DISTINGUISHABLE: report the modal width,
    // the count at it, the off-width (excluded) count, and WHY it was skipped --
    // not a bare applicable:false that could mean length variance OR too few.
    {
        std::mt19937_64 rng(0x00144144ULL);
        auto hx = [&](int n) { QString s; for (int i = 0; i < n; ++i) s += QChar("0123456789abcdef"[rng() & 0xF]); return s; };

        // (a) no dominant width -> "length-variance", not applicable, off-width counted.
        {
            QStringList mixed;
            for (int i = 0; i < 9; ++i) mixed << hx(8);
            for (int i = 0; i < 8; ++i) mixed << hx(11);
            for (int i = 0; i < 8; ++i) mixed << hx(14);   // 25 tokens; width 8 leads with 9 (no majority)
            const QJsonObject p = analyze(mixed)["positional"].toObject();
            chk("positional #144: variable lengths -> skipped as length-variance (not a bare false)",
                !p["applicable"].toBool() && p["skipReason"].toString() == "length-variance");
            chk("positional #144: variable lengths -> modal + off-width reported",
                p["modalWidth"].toInt() == 8 && p["atModalWidth"].toInt() == 9 && p["offWidth"].toInt() == 16);
        }
        // (b) fixed width -> applicable, nothing excluded.
        {
            QStringList fixed;
            for (int i = 0; i < 24; ++i) fixed << hx(16);
            const QJsonObject p = analyze(fixed)["positional"].toObject();
            chk("positional #144: fixed width -> applicable, offWidth 0",
                p["applicable"].toBool() && p["offWidth"].toInt() == 0
                && p["modalWidth"].toInt() == 16 && p["atModalWidth"].toInt() == 24);
        }
        // (c) dominant width WITH a few outliers -> applicable AND the excluded
        // count is surfaced (the key #144 signal: tokens WERE dropped, and we say so).
        {
            QStringList dom;
            for (int i = 0; i < 22; ++i) dom << hx(16);
            for (int i = 0; i < 3; ++i)  dom << hx(20);
            const QJsonObject p = analyze(dom)["positional"].toObject();
            chk("positional #144: dominant width + outliers -> applicable, offWidth==3",
                p["applicable"].toBool() && p["offWidth"].toInt() == 3
                && p["modalWidth"].toInt() == 16 && p["atModalWidth"].toInt() == 22);
        }
    }

    // ===== #152: decodeCorpusBytes scheme selection + non-conformer tolerance =
    {
        std::mt19937_64 rng(0x00C0FFEEULL);
        auto hex16 = [&]() { QByteArray b(16, '\0'); for (char &c : b) c = char(uint8_t(rng())); return QString::fromLatin1(b.toHex()); };

        // (a) an ODD-length hex corpus is HEX, not base64. The old even-length
        // gate failed, fell through, and mislabelled the scheme "base64".
        {
            QStringList odd;
            for (int i = 0; i < 24; ++i) { QString h = hex16(); h.chop(1); odd << h; }  // 31 hex chars = odd
            const QJsonObject bl = analyze(odd)["bitLevel"].toObject();
            chk("odd-length hex corpus -> scheme 'hex' (not mislabelled base64)",
                bl["applicable"].toBool() && bl["scheme"].toString() == "hex");
        }

        // (c) ONE non-conforming token (a JWT-shaped 'a.b.c') no longer zeroes the
        // whole analysis -- the hex majority is decoded, the stray is SKIPPED and
        // COUNTED. Old code broke on it and returned applicable:false.
        {
            QStringList mostlyHex;
            for (int i = 0; i < 23; ++i) mostlyHex << hex16();
            mostlyHex << "aaaa.bbbb.cccc";                       // '.' -> neither hex nor base64 charset
            const QJsonObject bl = analyze(mostlyHex)["bitLevel"].toObject();
            chk("one non-conforming token -> still applicable (not zeroed)", bl["applicable"].toBool());
            chk("one non-conforming token -> skipped == 1 (signalled, not silently dropped)",
                bl["skipped"].toInt() == 1);
            chk("mostly-hex corpus -> scheme 'hex'", bl["scheme"].toString() == "hex");
        }

        // regression: a clean even-hex corpus still decodes fully -> hex, 0 skipped.
        {
            QStringList clean;
            for (int i = 0; i < 24; ++i) clean << hex16();
            const QJsonObject bl = analyze(clean)["bitLevel"].toObject();
            chk("clean even-hex corpus -> scheme hex, skipped 0",
                bl["applicable"].toBool() && bl["scheme"].toString() == "hex" && bl["skipped"].toInt() == 0);
        }

        // majority guard: a corpus MOSTLY outside both charsets (JWT-shaped) has no
        // majority scheme -> not applicable (silence beats decoding garbage).
        {
            QStringList mixed;
            for (int i = 0; i < 16; ++i) mixed << (QStringLiteral("aa.bb.cc") + QString::number(i));  // '.' -> neither charset
            for (int i = 0; i < 8; ++i)  mixed << hex16();
            const QJsonObject bl = analyze(mixed)["bitLevel"].toObject();
            chk("mostly non-charset corpus -> not applicable (no majority scheme)",
                !bl["applicable"].toBool());
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
        // FIPS length-bucketed runs: alternating -> all length-1 runs -> huge
        // chi; all-zero -> a single run -> too few to judge -> sentinel.
        chk("runLen: alternating 0xAA -> chi huge (fails)", fipsRunsBucketChi(QByteArray(30, char(0xAA))) > 15.086);
        chk("runLen: all-zero -> < 30 runs -> -1 sentinel", fipsRunsBucketChi(QByteArray(30, '\0')) < 0.0);
        // compression: a constant stream compresses to almost nothing; a tiny
        // input is not judged (returns 1.0).
        chk("compress: all-zero 1KB -> ratio << 0.85 (fails)", compressionRatio(QByteArray(1024, '\0')) < 0.85);
        chk("compress: 64B input -> 1.0 (not judged)", compressionRatio(QByteArray(64, '\0')) == 1.0);
        // reliability rating scales with sample size.
        chk("reliability: 10 -> insufficient", reliabilityRating(10) == "insufficient");
        chk("reliability: 50 -> low", reliabilityRating(50) == "low");
        chk("reliability: 500 -> medium", reliabilityRating(500) == "medium");
        chk("reliability: 2000 -> high", reliabilityRating(2000) == "high");
        chk("reliability: 10000 -> very-high", reliabilityRating(10000) == "very-high");
        // Per-position character-transition (Cramer's V). A "+1 shift" corpus
        // has uniform per-position marginals but a deterministic transition ->
        // strong association; too few tokens -> sentinel.
        {
            QStringList shift;
            for (int k = 0; k < 48; ++k) {
                const char c = "0123456789abcdef"[k % 16];
                shift << QString(2, QChar(c));      // "00","11",...,"ff","00",...
            }
            chk("transition: +1 shift corpus -> V > 0.5", maxPositionalTransitionV(shift) > 0.5);
            chk("transition: < 40 tokens -> -1 sentinel",
                maxPositionalTransitionV(QStringList() << "aa" << "bb" << "cc") < 0.0);
        }
    }

    // ===== sampleSizeGuidance: sample-size + FIPS 140-2 threshold advice =====
    // Locks the two documented thresholds (Burp's ~100-token warn floor and the
    // 20,000-bit FIPS 140-2 power-up sample) and the deep-test floor (kDeepMinN).
    {
        const SampleSizeGuidance z = sampleSizeGuidance(0, 0);
        chk("ssg: zero tokens -> tooFew + not estimable + no FIPS",
            z.sampleCount == 0 && z.tooFew && !z.estimable && !z.fipsBitsMet);
        chk("ssg: zero tokens -> 'No tokens captured.' note", z.note == "No tokens captured.");
        chk("ssg: negative inputs clamp to zero",
            sampleSizeGuidance(-5, -9).sampleCount == 0
            && sampleSizeGuidance(-5, -9).decodedBits == 0);

        chk("ssg: thresholds exposed (100 tokens / 20000 bits)",
            z.recommendedMinTokens == 100 && z.fipsBitThreshold == 20000);

        // estimable floor is kDeepMinN (20): 19 below, 20 at.
        chk("ssg: 19 tokens -> not estimable", !sampleSizeGuidance(19, 0).estimable);
        chk("ssg: 20 tokens -> estimable",      sampleSizeGuidance(20, 0).estimable);
        chk("ssg: 10 tokens -> 'far below' note",
            sampleSizeGuidance(10, 0).note.contains("far below"));
        chk("ssg: 50 tokens -> estimable but tooFew (indicative)",
            sampleSizeGuidance(50, 0).estimable && sampleSizeGuidance(50, 0).tooFew
            && sampleSizeGuidance(50, 0).note.contains("indicative"));

        // tooFew floor is 100 tokens: 99 below, 100 at.
        chk("ssg: 99 tokens -> tooFew",  sampleSizeGuidance(99, 0).tooFew);
        chk("ssg: 100 tokens -> not tooFew", !sampleSizeGuidance(100, 0).tooFew);

        // FIPS bit threshold is 20000: 19999 under, 20000 met.
        const SampleSizeGuidance under = sampleSizeGuidance(100, 19999);
        const SampleSizeGuidance met   = sampleSizeGuidance(100, 20000);
        chk("ssg: 19999 bits -> FIPS not met", !under.fipsBitsMet);
        chk("ssg: 20000 bits -> FIPS met",      met.fipsBitsMet);
        chk("ssg: adequate + under-FIPS note wording",
            !under.tooFew && under.note.contains("under the 20,000-bit"));
        chk("ssg: adequate + FIPS-met note wording",
            met.note.contains("meet the 20,000-bit"));
        // 0 decoded bits (corpus not bit-testable) never spuriously reports FIPS met.
        chk("ssg: 500 tokens, 0 bits -> adequate tokens but FIPS not met",
            !sampleSizeGuidance(500, 0).tooFew && !sampleSizeGuidance(500, 0).fipsBitsMet);
    }

    std::fprintf(stderr, "sequencer_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

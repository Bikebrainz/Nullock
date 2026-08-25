#pragma once

// Token randomness analyzer. Burp's "Sequencer" equivalent.
//
// Given a corpus of N captured tokens (session cookies, CSRF tokens,
// password-reset URLs, ...), score how predictable they look. Returns
// per-test scores plus a verdict. Used to flag tokens that are
// brute-forceable, sequential, or low-entropy.
//
// Tests we run:
//   1. Shannon entropy per byte (bits) + effective per-token keyspace
//   2. Character class entropy (alpha / digit / special / case)
//   3. Hamming distance distribution between consecutive tokens
//   4. Longest common substring across the corpus
//   5. Sequential-counter detection (parse hex/dec, look at deltas)
//   6. Per-character-position Shannon entropy (fixed-width corpora) -- catches a
//      generator that leaks structure in a specific column
//   7. Bit-level NIST monobit + two-bit serial chi-square on the decoded bytes
//   8. Byte-level lag-1 serial correlation -- the LCG / linear-congruential and
//      java.util.Random low-bit signature
//
// Tests 6-8 address the deeper "statistical flatness != cryptographic
// unpredictability" miss: a LONG token with high char entropy AND high effective
// keyspace whose bytes still come from a predictable generator. They only
// activate on corpora of >= 20 tokens and use standard significance thresholds,
// so small or genuinely-random captures are never false-flagged. (A Mersenne
// Twister stream passes 6-8; flagging MT needs a matrix-rank / state-recovery
// test, left as future work.)
//
// All tests are O(N * len). The whole analyze() call returns in
// under 50ms for typical corpora of 100 tokens.

#include <QByteArray>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

// The pure analysis (exposed for the unit test; defined in sequencer_logic.cpp).
// Sequencer::analyze() is a thin Q_INVOKABLE wrapper around this. Returns the
// JSON shape documented on Sequencer::analyze below.
// `alpha` is the significance level every bit-level statistical test is graded
// at (Bonferroni-corrected tests use alpha/N). 0.01 is the FIPS/NIST default and
// reproduces the historical hard-coded critical values; a caller can pass 0.05 /
// 0.001 to re-grade the whole suite looser/stricter. Clamped to [1e-6, 0.2].
QJsonObject analyzeTokens(const QStringList &tokens, double alpha = 0.01);

// FIPS 140-2-style bit-level randomness tests over a decoded byte stream
// (exposed for direct unit testing; used by the bit-level analysis). The
// monobit/serial tests already lived in sequencer_logic; these add the poker,
// runs, and long-runs tests the Sequencer was missing.
//   fipsPokerChiSquare: chi-square (15 dof) over non-overlapping 4-bit groups.
//     A flat stream spreads the 16 nibble values evenly (~0); a biased or
//     structured stream concentrates them (large). < 0 sentinel if too short.
//   fipsRunsZScore: Wald-Wolfowitz total-runs z-score. ~0 for random; large
//     positive = too many runs (over-alternating), large negative = too few
//     (sticky/clumped). 0 if degenerate (all one symbol / too short).
//   longestBitRun: length of the longest run of identical bits.
// Upper tail P(X > chi) of the chi-square distribution with `dof` degrees of
// freedom (regularized upper incomplete gamma). Turns a chi-square statistic
// into a p-value; used by the per-position character test. Exposed for testing.
double chiSquareSurvival(double chi, int dof);
double fipsPokerChiSquare(const QByteArray &bytes);
double fipsRunsZScore(const QByteArray &bytes);
qint64 longestBitRun(const QByteArray &bytes);
// fipsRunsBucketChi: the FIPS-shaped runs test -- chi-square (5 dof) of the
//   run-LENGTH distribution (buckets 1,2,3,4,5,6+) against the geometric
//   expectation (P(len=k)=2^-k). < 0 sentinel when too few runs to judge.
// compressionRatio: zlib-compressed size / original size of the byte stream.
//   Random data barely compresses (~1); structure/repetition compresses (<1).
double fipsRunsBucketChi(const QByteArray &bytes);
double compressionRatio(const QByteArray &bytes);
// reliabilityRating: how far to trust the estimate given the sample size (the
//   number of tokens). Statistical randomness tests need a corpus to converge;
//   Burp's Sequencer likewise gates confidence on sample count. Returns one of
//   "insufficient" / "low" / "medium" / "high" / "very-high".
QString reliabilityRating(int sampleCount);

// Sample-size guidance for a Sequencer run: is the corpus large enough to trust
// the estimate, and does the decoded bit-stream reach the FIPS 140-2 power-up
// test sample size (a 20,000-bit stream)? Burp surfaces the same advice (it
// warns under ~100 tokens and cites the FIPS sample requirement) but only
// implicitly through the confidence label; this makes the two thresholds
// explicit and machine-readable so a report/CI gate can act on them. Distinct
// from reliabilityRating(), which is a single qualitative label with no FIPS
// dimension. Pure: derived only from the two counts, so it is unit-tested.
struct SampleSizeGuidance {
    int  sampleCount          = 0;      // tokens captured
    int  decodedBits          = 0;      // bits in the decoded byte-stream (0 if not bit-testable)
    bool tooFew               = true;   // sampleCount < recommendedMinTokens
    bool estimable            = false;  // sampleCount >= the deep-test floor (kDeepMinN)
    bool fipsBitsMet          = false;  // decodedBits >= fipsBitThreshold
    int  recommendedMinTokens = 100;    // Burp's ~100-token warn floor
    int  fipsBitThreshold     = 20000;  // FIPS 140-2 power-up RNG test sample (bits)
    QString note;                       // one-line human-readable guidance
};
SampleSizeGuidance sampleSizeGuidance(int sampleCount, int decodedBits);

// maxPositionalTransitionV: the strongest per-position serial dependence across
//   consecutive tokens, as Cramer's V (0 = the character at a position is
//   independent of the same position in the previous token; 1 = fully
//   determined). Catches a generator whose successive outputs are correlated
//   per-position even when each position's marginal distribution looks uniform
//   -- the exact blind spot of per-position entropy. < 0 when too few tokens.
double maxPositionalTransitionV(const QStringList &tokens);

class Sequencer : public QObject {
    Q_OBJECT
public:
    explicit Sequencer(QObject *parent = nullptr) : QObject(parent) {}

    // Returns a JSON object with the shape:
    //   {
    //     "n":         <count>,
    //     "avgLen":    <int>,
    //     "shannon":   { "bitsPerByte": <double>, "verdict": "..." },
    //     "charClass": { "alphaRatio": ..., "digitRatio": ..., ... },
    //     "hamming":   { "avg": <int>, "min": <int>, "max": <int> },
    //     "lcs":       { "longest": "<chars>", "length": <int> },
    //     "sequential":{ "looksSequential": <bool>, "delta": <int> },
    //     "positional":{ "applicable": <bool>, "width": <int>, "n": <int>,
    //                    "columnEntropy": [<double>...], "reference": <double>,
    //                    "weakColumns": <int>, "biased": <bool> },
    //     "significanceLevel": <double>,   // alpha every bit test was graded at
    //     "bitLevel":  { "applicable": <bool>, "scheme": "hex"|"base64",
    //                    "bits": <int>,
    //                    "monobit": { "pValue": <double>, "failed": <bool> },
    //                    "twoBit":  { "chiSquare": <double>, "pValue": <double>, "failed": <bool> },
    //                    "serialCorrelation": { "r": <double>, "pValue": <double>, "failed": <bool> },
    //                    "poker":   { "chiSquare": <double>, "pValue": <double>, "failed": <bool> },
    //                    "runs":    { "z": <double>, "pValue": <double>, "failed": <bool> },
    //                    "runLengths": { "chiSquare": <double>, "pValue": <double>, "failed": <bool> },
    //                    "anyFailed": <bool> },
    //     "verdict":   "looks-random" | "may-be-predictable" | "predictable",
    //     "score":     <0-100>
    //   }
    // `significanceLevel` grades every bit-level test (see analyzeTokens); default 0.01.
    Q_INVOKABLE QJsonObject analyze(const QStringList &tokens,
                                    double significanceLevel = 0.01) const;
};

} // namespace Nullock::Core

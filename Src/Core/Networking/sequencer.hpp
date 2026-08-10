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
QJsonObject analyzeTokens(const QStringList &tokens);

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
    //     "bitLevel":  { "applicable": <bool>, "scheme": "hex"|"base64",
    //                    "bits": <int>,
    //                    "monobit": { "pValue": <double>, "failed": <bool> },
    //                    "twoBit":  { "chiSquare": <double>, "failed": <bool> },
    //                    "serialCorrelation": { "r": <double>, "failed": <bool> },
    //                    "anyFailed": <bool> },
    //     "verdict":   "looks-random" | "may-be-predictable" | "predictable",
    //     "score":     <0-100>
    //   }
    Q_INVOKABLE QJsonObject analyze(const QStringList &tokens) const;
};

} // namespace Nullock::Core

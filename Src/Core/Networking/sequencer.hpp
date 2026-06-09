#pragma once

// Token randomness analyzer. Burp's "Sequencer" equivalent.
//
// Given a corpus of N captured tokens (session cookies, CSRF tokens,
// password-reset URLs, ...), score how predictable they look. Returns
// per-test scores plus a verdict. Used to flag tokens that are
// brute-forceable, sequential, or low-entropy.
//
// Tests we run:
//   1. Shannon entropy per byte (bits)
//   2. Character class entropy (alpha / digit / special / case)
//   3. Hamming distance distribution between consecutive tokens
//   4. Longest common substring across the corpus
//   5. Sequential-counter detection (parse hex/dec, look at deltas)
//
// All tests are O(N * len). The whole analyze() call returns in
// under 50ms for typical corpora of 100 tokens.

#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

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
    //     "verdict":   "looks-random" | "may-be-predictable" | "predictable",
    //     "score":     <0-100>
    //   }
    Q_INVOKABLE QJsonObject analyze(const QStringList &tokens) const;
};

} // namespace Nullock::Core

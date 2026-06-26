#include "sequencer.hpp"

#include <QHash>
#include <QJsonObject>
#include <QRegularExpression>
#include <QVector>
#include <cmath>

namespace Nullock::Core {

namespace {

double shannonEntropy(const QString &s) {
    if (s.isEmpty()) return 0.0;
    // Count over ALL code units (a previous version dropped unicode >= 256 from
    // both the histogram AND the total, skewing bits/symbol for multibyte input).
    QHash<char16_t, int> counts;
    for (QChar c : s) counts[c.unicode()]++;
    const double total = double(s.size());
    double h = 0.0;
    for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
        const double p = double(it.value()) / total;
        h -= p * std::log2(p);
    }
    return h;
}

// Parse a token as an integer, detecting the base: a purely-decimal string is
// base 10, a string with a hex letter (or 0x prefix) is base 16. Returns false
// (skip) on anything else or on overflow. Detecting the base avoids the bug
// where every decimal token was parsed as hex -- so a decimal counter crossing
// a units-9 carry (19->20: 0x19=25, 0x20=32) broke delta consistency.
bool parseToken(const QString &tok, qint64 &out) {
    const QString t = tok.trimmed();
    if (t.isEmpty()) return false;
    static const QRegularExpression decRe("^[0-9]+$");
    static const QRegularExpression hexRe("^(0[xX])?[0-9a-fA-F]+$");
    bool ok = false;
    if (decRe.match(t).hasMatch()) {
        out = t.toLongLong(&ok, 10);
        return ok;
    }
    if (hexRe.match(t).hasMatch()) {
        QString h = t;
        if (h.startsWith("0x", Qt::CaseInsensitive)) h = h.mid(2);
        out = h.toLongLong(&ok, 16);
        return ok;
    }
    return false;
}

// Decode the parseable tokens (skipping garbage) into integers; require a
// numeric majority so a stray label doesn't masquerade as a counter corpus.
QList<qint64> decodeNumeric(const QStringList &tokens) {
    QList<qint64> nums;
    for (const QString &t : tokens) {
        qint64 v = 0;
        if (parseToken(t, v)) nums.append(v);
    }
    if (nums.size() < 3 || nums.size() * 2 < tokens.size()) return {};
    return nums;
}

int hammingDistance(const QString &a, const QString &b) {
    const int n = qMin(a.size(), b.size());
    int d = qAbs(a.size() - b.size());
    for (int i = 0; i < n; ++i)
        if (a[i] != b[i]) ++d;
    return d;
}

int commonAffixLen(const QStringList &t, bool prefix) {
    if (t.size() < 2) return 0;
    int n = t.first().size();
    for (const QString &s : t) n = qMin(n, s.size());
    int k = 0;
    for (; k < n; ++k) {
        const QChar c = prefix ? t.first()[k] : t.first()[t.first().size() - 1 - k];
        bool same = true;
        for (const QString &s : t) {
            const QChar d = prefix ? s[k] : s[s.size() - 1 - k];
            if (d != c) { same = false; break; }
        }
        if (!same) break;
    }
    return k;
}

static QString lcsPair(const QString &a, const QString &b) {
    const int n = a.size(), m = b.size();
    if (n == 0 || m == 0) return {};
    QVector<int> prev(m + 1, 0), cur(m + 1, 0);
    int bestLen = 0, bestEnd = 0;
    for (int i = 1; i <= n; ++i) {
        for (int k = 1; k <= m; ++k) {
            if (a[i-1] == b[k-1]) {
                cur[k] = prev[k-1] + 1;
                if (cur[k] > bestLen) { bestLen = cur[k]; bestEnd = i; }
            } else cur[k] = 0;
        }
        std::swap(prev, cur);
        std::fill(cur.begin(), cur.end(), 0);
    }
    return a.mid(bestEnd - bestLen, bestLen);
}

// Longest common substring across CONSECUTIVE token pairs (capped), measured on
// the VARIABLE region only: a corpus-wide fixed prefix/suffix (a version tag or
// constant header) is structure, not a randomness flaw, so stripping it stops a
// false "high LCS" deduction on otherwise-random tokens.
QString longestCommonSubstring(const QStringList &tokens) {
    if (tokens.size() < 2) return {};
    const int pre = commonAffixLen(tokens, true);
    const int suf = commonAffixLen(tokens, false);
    QStringList var;
    for (const QString &t : tokens) {
        const int keep = t.size() - pre - suf;
        var << (keep > 0 ? t.mid(pre, keep) : QString());
    }
    QString best;
    for (int i = 0; i + 1 < var.size() && i < 50; ++i) {
        const QString cand = lcsPair(var[i], var[i + 1]);
        if (cand.size() > best.size()) best = cand;
    }
    return best;
}

// If the tokens decode to integers AND the deltas are consistent, that's a
// sequential counter (common for auto-incrementing session IDs).
bool looksSequential(const QStringList &tokens, qint64 &outDelta) {
    const QList<qint64> nums = decodeNumeric(tokens);
    if (nums.size() < 3) return false;
    const qint64 delta = nums[1] - nums[0];
    if (delta == 0) return false;
    int matches = 0;
    for (int i = 2; i < nums.size(); ++i)
        if (nums[i] - nums[i-1] == delta) ++matches;
    // Delta-consistency fraction WITHOUT integer-division truncation (the old
    // (n-2)*3/4 collapsed to 0 at n=3, flagging any two-distinct triple), and
    // require at least one confirming delta so a 3-token corpus needs its single
    // remaining delta to actually agree.
    const int need = nums.size() - 2;          // deltas to verify beyond the first
    if (matches >= 1 && matches * 4 >= need * 3) {
        outDelta = delta;
        return true;
    }
    return false;
}

// A strictly-monotonic numeric sequence that ISN'T a constant-delta counter
// (timestamps, an affine/multiplier counter, prefix+counter) is still highly
// predictable. Conservative: require a sizable corpus and EVERY consecutive step
// in the same direction, so a random corpus (P(all same direction) ~ 2^-(n-1))
// won't trip it.
bool looksMonotonic(const QStringList &tokens) {
    const QList<qint64> nums = decodeNumeric(tokens);
    if (nums.size() < 8) return false;
    int inc = 0, dec = 0;
    for (int i = 1; i < nums.size(); ++i) {
        if (nums[i] > nums[i-1]) ++inc;
        else if (nums[i] < nums[i-1]) ++dec;
    }
    const int steps = nums.size() - 1;
    return inc == steps || dec == steps;       // strictly monotonic
}

} // namespace

QJsonObject analyzeTokens(const QStringList &tokens) {
    QJsonObject result;
    result["n"] = tokens.size();
    if (tokens.isEmpty()) {
        result["verdict"] = "no-data";
        result["score"]   = 0;
        return result;
    }

    // Average length.
    qint64 totalLen = 0;
    for (const QString &t : tokens) totalLen += t.size();
    const int avgLen = int(totalLen / tokens.size());
    result["avgLen"] = avgLen;

    // Shannon entropy: combined corpus + average per-token.
    QString combined;
    combined.reserve(int(totalLen));
    for (const QString &t : tokens) combined.append(t);
    const double combinedBits = shannonEntropy(combined);
    // Effective per-token keyspace: a token's resistance to brute force /
    // recovery is its TOTAL entropy (bits/symbol * length), NOT its alphabet
    // flatness. This is what separates an 8-hex LCG token (~32 bits, recoverable)
    // from a 32-hex CSPRNG token (~128 bits) -- both look "flat" per byte.
    const double effectiveBits = combinedBits * avgLen;
    QJsonObject shannon;
    shannon["bitsPerByte"] = combinedBits;
    shannon["totalBits"]   = combinedBits * combined.size();
    shannon["effectiveBitsPerToken"] = effectiveBits;
    // Thresholds account for common token alphabets:
    //   full byte range:  ~8 bits/byte
    //   base64:           ~5.7 bits/byte
    //   base32 / alpha:   ~5.0 bits/byte
    //   hex:              ~4.0 bits/byte
    //   purely numeric:   ~3.3 bits/byte
    // We label as "good" anything >= base32-shape, "ok" hex-shape,
    // "low" numeric-only, "very-low" obvious low-entropy strings.
    QString shanVerdict;
    if (combinedBits >= 5.0)      shanVerdict = "good";
    else if (combinedBits >= 3.9) shanVerdict = "ok";
    else if (combinedBits >= 3.0) shanVerdict = "low";
    else                          shanVerdict = "very-low";
    shannon["verdict"] = shanVerdict;
    result["shannon"] = shannon;

    // Character class breakdown.
    qint64 alpha = 0, digit = 0, hex = 0, special = 0, upper = 0, lower = 0;
    for (QChar c : combined) {
        if (c.isLetter())           ++alpha;
        if (c.isDigit())             ++digit;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F')) ++hex;
        if (c.isUpper())             ++upper;
        if (c.isLower())             ++lower;
        if (!c.isLetterOrNumber())   ++special;
    }
    QJsonObject cls;
    if (totalLen > 0) {
        cls["alphaRatio"]   = double(alpha)   / double(totalLen);
        cls["digitRatio"]   = double(digit)   / double(totalLen);
        cls["hexRatio"]     = double(hex)     / double(totalLen);
        cls["upperRatio"]   = double(upper)   / double(totalLen);
        cls["lowerRatio"]   = double(lower)   / double(totalLen);
        cls["specialRatio"] = double(special) / double(totalLen);
    }
    result["charClass"] = cls;

    // Hamming distance distribution between consecutive tokens.
    if (tokens.size() >= 2) {
        int minH = INT_MAX, maxH = 0, sumH = 0;
        for (int i = 1; i < tokens.size(); ++i) {
            const int h = hammingDistance(tokens[i-1], tokens[i]);
            if (h < minH) minH = h;
            if (h > maxH) maxH = h;
            sumH += h;
        }
        QJsonObject ham;
        ham["min"] = minH;
        ham["max"] = maxH;
        ham["avg"] = sumH / (tokens.size() - 1);
        result["hamming"] = ham;
    }

    // Longest common substring.
    const QString lcs = longestCommonSubstring(tokens);
    QJsonObject lcsObj;
    lcsObj["longest"] = lcs;
    lcsObj["length"]  = lcs.size();
    result["lcs"] = lcsObj;

    // Sequential / monotonic counter detection.
    qint64 delta = 0;
    const bool seq = looksSequential(tokens, delta);
    const bool mono = looksMonotonic(tokens);
    QJsonObject seqObj;
    seqObj["looksSequential"] = seq;
    seqObj["looksMonotonic"]  = mono;
    seqObj["delta"] = static_cast<double>(delta);
    result["sequential"] = seqObj;

    // Final verdict. The PRIMARY axis is the effective keyspace (total entropy
    // per token), not per-byte alphabet flatness -- a short token is brute-
    // forceable however uniform its characters, while a long hex/base64 token is
    // strong despite a sub-byte alphabet. NIST SP 800-63B wants >= 64 bits; 128
    // is the modern target. Structural red flags subtract on top.
    int score = 100;
    // The cutoffs sit just BELOW the round 64/128-bit marks on purpose: the
    // MEASURED Shannon entropy of a finite random sample undershoots the
    // alphabet's theoretical bits/symbol (random hex measures ~3.94 at a dozen
    // tokens, not 4.0), so a genuine 64-bit (16-hex) / 128-bit (32-hex) token
    // computes just under the round number. 60/124 absorb that undershoot so a
    // real minimum-strength token isn't false-flagged, while a 32-bit (8-hex) or
    // short-numeric token still lands well under.
    if      (effectiveBits < 60)  score -= 55;   // brute-forceable keyspace
    else if (effectiveBits < 124) score -= 15;   // below the 128-bit target
    // A near-zero per-symbol entropy (repetition/tiny alphabet) is a separate
    // red flag the length-based keyspace can under-count on long tokens.
    if (combinedBits < 2.0) score -= 25;
    if (seq) score -= 50;
    else if (mono) score -= 25;                  // monotonic but not constant-delta
    if (lcs.size() > avgLen / 2 && avgLen > 8) score -= 30;
    score = qBound(0, score, 100);
    result["score"] = score;
    QString verdict;
    if      (score >= 80) verdict = "looks-random";
    else if (score >= 50) verdict = "may-be-predictable";
    else                  verdict = "predictable";
    result["verdict"] = verdict;
    return result;
}

} // namespace Nullock::Core

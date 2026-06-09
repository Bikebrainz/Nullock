#include "sequencer.hpp"

#include <QJsonObject>
#include <cmath>

namespace Nullock::Core {

namespace {

double shannonEntropy(const QString &s) {
    if (s.isEmpty()) return 0.0;
    int counts[256] = {0};
    int total = 0;
    for (QChar c : s) {
        const ushort u = c.unicode();
        if (u >= 256) continue;
        counts[u]++;
        ++total;
    }
    if (total == 0) return 0.0;
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        const double p = double(counts[i]) / double(total);
        h -= p * std::log2(p);
    }
    return h;
}

int hammingDistance(const QString &a, const QString &b) {
    const int n = qMin(a.size(), b.size());
    int d = qAbs(a.size() - b.size());
    for (int i = 0; i < n; ++i)
        if (a[i] != b[i]) ++d;
    return d;
}

QString longestCommonSubstring(const QStringList &tokens) {
    if (tokens.size() < 2) return {};
    // Compare each pair, return the longest common substring across
    // ANY two of them. For larger corpora we cap at 50 random pairs.
    const QString &a = tokens.first();
    QString best;
    for (int j = 1; j < tokens.size() && j < 30; ++j) {
        const QString &b = tokens[j];
        const int n = a.size(), m = b.size();
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
        if (bestLen > best.size())
            best = a.mid(bestEnd - bestLen, bestLen);
    }
    return best;
}

// If the tokens parse as hex / dec integers AND the deltas are
// consistent, that's a sequential counter (common for auto-incrementing
// session IDs).
bool looksSequential(const QStringList &tokens, qint64 &outDelta) {
    if (tokens.size() < 3) return false;
    QList<qint64> nums;
    nums.reserve(tokens.size());
    for (const QString &t : tokens) {
        bool ok = false;
        qint64 v = t.toLongLong(&ok, 16);
        if (!ok) v = t.toLongLong(&ok, 10);
        if (!ok) return false;
        nums.append(v);
    }
    if (nums.size() < 3) return false;
    const qint64 delta = nums[1] - nums[0];
    if (delta == 0) return false;
    int matches = 0;
    for (int i = 2; i < nums.size(); ++i)
        if (nums[i] - nums[i-1] == delta) ++matches;
    if (matches >= (nums.size() - 2) * 3 / 4) {
        outDelta = delta;
        return true;
    }
    return false;
}

} // namespace

QJsonObject Sequencer::analyze(const QStringList &tokens) const {
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
    QJsonObject shannon;
    shannon["bitsPerByte"] = combinedBits;
    shannon["totalBits"]   = combinedBits * combined.size();
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

    // Sequential counter detection.
    qint64 delta = 0;
    const bool seq = looksSequential(tokens, delta);
    QJsonObject seqObj;
    seqObj["looksSequential"] = seq;
    seqObj["delta"] = static_cast<double>(delta);
    result["sequential"] = seqObj;

    // Final verdict. Weighted average of the individual scores.
    int score = 100;
    if (shanVerdict == "very-low") score -= 60;
    else if (shanVerdict == "low") score -= 35;
    else if (shanVerdict == "ok")  score -= 10;
    if (seq) score -= 50;
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

#include "sequencer.hpp"

#include <QByteArray>
#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QVector>
#include <algorithm>
#include <cmath>

namespace Nullock::Core {

namespace {

// Minimum corpus size before ANY deeper cross-sample test runs (per-position
// entropy/char-chi-square, bit-level). Below this they are noise. Set well above
// every existing small regression corpus so the deeper tests only ADD signal on
// real (larger) captures -- they never perturb the legacy small-corpus grades.
constexpr int kDeepMinN = 20;

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

// Effective entropy from per-POSITION observed alphabet sizes: over the modal-
// width cohort, credit each column log2(distinct characters observed at that
// column) bits and sum across columns. Unlike a global bits/char * length, this
// credits a token that is hex in columns 0-7 (16 symbols -> 4 bits each) and
// FIXED in columns 8-31 (1 symbol -> 0 bits each) exactly ~32 bits, not the
// blended average the global rate assigns to both regions. It is a LOWER bound
// that tightens with more samples (a column's full alphabet only shows up once
// enough tokens are seen), which is the conservative direction for a keyspace
// estimate. Returns 0 for too few / variable-width samples (the caller reports
// it alongside the global estimate; the deeper positional tests own the verdict).
double positionalEffectiveBits(const QStringList &tokens) {
    if (tokens.size() < 2) return 0.0;
    // Modal (most common) token width -- the analyzable fixed-width cohort.
    QHash<int, int> widths;
    for (const QString &t : tokens) if (!t.isEmpty()) widths[t.size()]++;
    int width = 0, best = 0;
    for (auto it = widths.cbegin(); it != widths.cend(); ++it)
        if (it.value() > best) { best = it.value(); width = it.key(); }
    if (width <= 0) return 0.0;
    QStringList cohort;
    for (const QString &t : tokens) if (t.size() == width) cohort << t;
    if (cohort.size() < 2) return 0.0;
    double bits = 0.0;
    for (int col = 0; col < width; ++col) {
        QSet<QChar> seen;
        for (const QString &t : cohort) seen.insert(t.at(col));
        if (seen.size() > 1) bits += std::log2(double(seen.size()));  // 1-symbol col -> 0
    }
    return bits;
}

// Per-character-POSITION chi-square: over the modal-width cohort, test each
// column's observed character distribution against a uniform distribution over
// that column's observed alphabet (dof = distinct-1). A column biased toward a
// subset of its alphabet (a counter digit, a fixed-ish nibble) yields a large
// chi-square / small p-value even when the GLOBAL character frequency looks flat.
// A Bonferroni-corrected threshold (0.01/columns) holds the family-wise false-
// positive rate ~1%. Returns the number of failing columns + the worst p-value.
struct PositionalCharChi {
    bool   applicable = false;
    int    columns = 0;
    int    failures = 0;
    double minPValue = 1.0;
};
PositionalCharChi positionalCharChiSquare(const QStringList &tokens) {
    PositionalCharChi r;
    if (tokens.size() < kDeepMinN) return r;
    QHash<int, int> widths;
    for (const QString &t : tokens) if (!t.isEmpty()) widths[t.size()]++;
    int width = 0, best = 0;
    for (auto it = widths.cbegin(); it != widths.cend(); ++it)
        if (it.value() > best) { best = it.value(); width = it.key(); }
    QStringList cohort;
    for (const QString &t : tokens) if (t.size() == width) cohort << t;
    const int n = cohort.size();
    if (width <= 0 || n < kDeepMinN) return r;
    r.applicable = true;
    r.columns = width;
    const double alpha = 0.01 / double(width);   // Bonferroni over the columns
    for (int col = 0; col < width; ++col) {
        QHash<char16_t, int> hist;
        for (const QString &t : cohort) hist[t.at(col).unicode()]++;
        const int k = hist.size();
        if (k < 2) continue;                     // a constant column carries no distribution
        const double expected = double(n) / double(k);
        double chi = 0.0;
        for (auto it = hist.cbegin(); it != hist.cend(); ++it) {
            const double dlt = double(it.value()) - expected;
            chi += dlt * dlt / expected;
        }
        const double p = chiSquareSurvival(chi, k - 1);
        if (p < r.minPValue) r.minPValue = p;
        if (p < alpha) ++r.failures;
    }
    return r;
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

// Strip a shared NON-NUMERIC wrapper so a WRAPPED counter -- "sess_1001",
// "user-42", an id with a constant tag -- exposes its numeric core to the
// counter tests. parseToken otherwise rejects the whole token, so a
// prefixed/suffixed counter was reported looksSequential:false while Burp's
// encoding-agnostic low-entropy inference still flagged it (the concrete #153
// gap). The shared prefix is removed up to and INCLUDING its last non-digit,
// and the shared suffix from its first non-digit to the end -- so only constant
// wrapper characters are dropped, never a varying digit. A bare numeric/hex
// counter (no wrapper) and a stepped counter whose step lives in trailing
// digits ("100","200","300" -> common suffix "00" is all-digit) are returned
// UNCHANGED, so the recovered delta stays the TRUE step. Base64-wrapped counters
// are out of scope (their wrapper is not a constant affix).
QStringList stripCommonNumericWrapper(const QStringList &tokens) {
    if (tokens.size() < 2) return tokens;
    const QString first = tokens.first();
    const int p = commonAffixLen(tokens, true);
    const int s = commonAffixLen(tokens, false);
    int stripPre = 0;
    for (int i = 0; i < p; ++i)
        if (!first[i].isDigit()) stripPre = i + 1;                 // last non-digit of the shared prefix
    int stripSuf = 0;
    for (int j = 0; j < s; ++j)
        if (!first[first.size() - s + j].isDigit()) { stripSuf = s - j; break; }  // first non-digit of the shared suffix
    if (stripPre == 0 && stripSuf == 0) return tokens;             // no non-numeric wrapper
    QStringList out;
    out.reserve(tokens.size());
    for (const QString &t : tokens) {
        const int keep = t.size() - stripPre - stripSuf;
        out << (keep > 0 ? t.mid(stripPre, keep) : QString());     // over-strip -> empty -> skipped downstream
    }
    return out;
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
    int pre = commonAffixLen(tokens, true);
    int suf = commonAffixLen(tokens, false);
    // The prefix and suffix scans run independently, so on a (near-)CONSTANT corpus
    // they both span the whole token and pre+suf zeroes every variable region --
    // returning an EMPTY lcs exactly when the structure is total, which then let the
    // structural deduction below never fire. Clamp the overlap: a fully-constant
    // corpus IS its own longest common substring.
    int minLen = tokens.first().size();
    for (const QString &t : tokens) minLen = qMin(minLen, int(t.size()));
    if (pre >= minLen) return tokens.first();
    if (pre + suf > minLen) suf = minLen - pre;
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
    const QList<qint64> nums = decodeNumeric(stripCommonNumericWrapper(tokens));
    if (nums.size() < 3) return false;
    // Anchor the reference delta on the MEDIAN step, not the FIRST pair: a single
    // outlier at the HEAD of the capture (a gap before the counter settles) made the
    // first delta unrepresentative and defeated counter detection entirely -- e.g.
    // deltas {4096,1,1,1,1} scored 0 matches and the run was graded non-sequential.
    QList<qint64> deltas;
    deltas.reserve(nums.size() - 1);
    for (int i = 1; i < nums.size(); ++i) deltas << (nums[i] - nums[i-1]);
    QList<qint64> sorted = deltas;
    std::sort(sorted.begin(), sorted.end());
    const qint64 delta = sorted[sorted.size() / 2];
    if (delta == 0) return false;
    int matches = 0;
    for (const qint64 d : deltas) if (d == delta) ++matches;
    // Delta-consistency fraction WITHOUT integer-division truncation (the old
    // (n-2)*3/4 collapsed to 0 at n=3, flagging any two-distinct triple), and
    // require at least one confirming delta so a 3-token corpus needs its single
    // remaining delta to actually agree.
    // `matches` now counts ALL deltas agreeing with the median (not just those after
    // the first pair), so require at least TWO agreeing steps -- that keeps the n=3
    // strictness the old "matches >= 1 beyond the first delta" rule provided.
    const int need = deltas.size();
    if (matches >= 2 && matches * 4 >= need * 3) {
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
    const QList<qint64> nums = decodeNumeric(stripCommonNumericWrapper(tokens));
    if (nums.size() < 8) return false;
    int inc = 0, dec = 0;
    for (int i = 1; i < nums.size(); ++i) {
        if (nums[i] > nums[i-1]) ++inc;
        else if (nums[i] < nums[i-1]) ++dec;
    }
    const int steps = nums.size() - 1;
    return inc == steps || dec == steps;       // strictly monotonic
}

// ===================================================================
// Deeper randomness tests: statistical flatness != unpredictability.
//
// The effective-keyspace score above flags SHORT weak tokens (an 8-hex/32-bit
// LCG is brute-forceable however flat its characters). It cannot see the deeper
// miss: a LONG token whose characters are individually uniform AND whose total
// keyspace looks large, yet whose underlying bytes come from a statistically-
// flat-but-PREDICTABLE generator (a 32-bit-seeded LCG, java.util.Random, ...)
// rendered to hex/base64 -- high char entropy, high effective keyspace, but
// recoverable from a handful of samples.
//
// Three positional/bit-level tests over the corpus pick up that structure:
//   * per-CHARACTER-POSITION Shannon entropy   -> a column that leaks structure
//   * NIST-style monobit + two-bit serial test -> a biased decoded bitstream
//   * byte-level lag-1 serial correlation       -> the LCG/linear-congruential
//                                                  lattice (and java.util.Random
//                                                  low-bit) signature
//
// Scope / honesty: monobit + serial + lag-1 correlation catch the LCG / linear-
// congruential family and gross per-position leaks. A *Mersenne Twister* stream
// passes all of these (that is precisely why MT is popular) -- catching MT needs
// a binary-matrix-rank or 624-word state-recovery test, which is deliberately
// out of scope here (a future test). We do NOT claim to flag MT; we flag the
// linear/low-bit-weak generators and structural leaks these tests can prove.
//
// Everything is conservative on purpose (the analyst acts on a flag): each test
// is gated behind a minimum corpus size and uses a standard significance
// threshold, so a small or genuinely-random corpus is never false-flagged.
// ===================================================================


struct PositionalResult {
    bool   applicable = false;   // fixed-width corpus with enough samples?
    int    width = 0;
    int    n = 0;                // count of modal-width tokens analyzed
    QList<double> columnEntropy; // per-column Shannon entropy (bits)
    double reference = 0.0;      // the strongest variable column (healthy baseline)
    int    weakColumns = 0;
    bool   biased = false;
    // Length-tolerance diagnostics (Burp "Ignore token length differences", #144):
    // ALWAYS populated, so a skipped positional test is DISTINGUISHABLE (a bare
    // applicable:false hid whether the cause was length variance or too few
    // tokens). modalWidth/atModalWidth describe the width the cross-sample test
    // uses; offWidth is how many tokens were excluded for not matching it.
    int    modalWidth = 0;
    int    atModalWidth = 0;
    int    offWidth = 0;
    QString skipReason;          // set only when !applicable: why it didn't run
};

// Per-character-position Shannon entropy across the fixed-width tokens. A
// healthy random token draws every column from the same alphabet uniformly, so
// EVERY column's entropy should sit near the alphabet's bits/symbol. A generator
// that leaks structure per position (a constant-ish nibble, a low-order LCG bit
// rendered to a fixed column, an embedded counter) shows columns whose entropy
// is anomalously low relative to their siblings.
//
// FP guards: we judge only VARIABLE columns (distinct >= 2). A fully-constant
// column is corpus format -- a fixed prefix/suffix, a UUID dash, a version
// nibble -- not a generator flaw, so it is reported but never counted as bias
// (this is also what keeps UUIDv4, whose lone low-entropy variant nibble is a
// single column, from tripping the flag). We require >= 2 weak columns, a
// healthy reference alphabet (>= 2 bits) and the modal width to be a real
// majority before flagging.
PositionalResult positionalEntropy(const QStringList &tokens) {
    PositionalResult r;

    // Modal token width -- computed ALWAYS (even when the test can't run) so the
    // caller can report WHY it was skipped instead of a bare applicable:false.
    QHash<int, int> widthCount;
    for (const QString &t : tokens) widthCount[t.size()]++;
    int modeW = 0, modeC = 0;
    for (auto it = widthCount.cbegin(); it != widthCount.cend(); ++it)
        if (it.value() > modeC) { modeC = it.value(); modeW = it.key(); }
    r.modalWidth   = modeW;
    r.atModalWidth = modeC;
    r.offWidth     = tokens.size() - modeC;

    // Same gate as before (unchanged applicable outcome), split so each failure
    // reports a distinct, actionable reason. Order most-specific first.
    if (tokens.size() < kDeepMinN) { r.skipReason = QStringLiteral("too-few-tokens");   return r; }
    if (modeC * 2 < tokens.size()) { r.skipReason = QStringLiteral("length-variance");  return r; }
    if (modeC < kDeepMinN)         { r.skipReason = QStringLiteral("too-few-at-width");  return r; }
    if (modeW < 8)                 { r.skipReason = QStringLiteral("tokens-too-short");  return r; }

    QStringList fw;
    for (const QString &t : tokens) if (t.size() == modeW) fw << t;
    r.applicable = true;
    r.width = modeW;
    r.n = fw.size();

    const double tot = double(fw.size());
    QList<double> varH;                         // entropies of variable columns
    for (int c = 0; c < modeW; ++c) {
        QHash<char16_t, int> cnt;
        for (const QString &t : fw) cnt[t[c].unicode()]++;
        double H = 0.0;
        for (auto it = cnt.cbegin(); it != cnt.cend(); ++it) {
            const double p = double(it.value()) / tot;
            H -= p * std::log2(p);
        }
        r.columnEntropy << H;
        if (cnt.size() >= 2) varH << H;         // skip constant (format) columns
    }

    double ref = 0.0;
    for (double h : varH) ref = qMax(ref, h);
    r.reference = ref;

    // Need enough variable columns and a meaningful alphabet for per-position
    // entropy to discriminate (a 2-symbol/numeric corpus is judged elsewhere).
    if (varH.size() >= 4 && ref >= 2.0) {
        int weak = 0;
        for (double h : varH)
            if (h < 0.5 * ref && (ref - h) >= 1.0) ++weak;
        r.weakColumns = weak;
        r.biased = (weak >= 2);
    }
    return r;
}

// Decode the corpus to bytes for the bit-level tests, picking the scheme by
// charset MAJORITY. Two silent-wrong paths the naive "all-or-nothing, hex only
// if EVEN length, else fall through to base64" version had (roadmap #152):
//   (a) an ODD-length hex corpus failed the even-length gate, fell through, and
//       was decoded + labelled "base64" -- wrong bytes AND wrong scheme. Now a
//       hex-charset corpus is HEX at any length; an odd token is left-padded with
//       a leading '0' so its half-byte is preserved, not reinterpreted.
//   (c) a SINGLE non-conforming token (a truncated sample, a JWT's '.') set
//       all-hex=all-b64=false via `break` and returned empty -> the ENTIRE corpus
//       got applicable:false and ZERO bit-level analysis. Now non-conformers are
//       SKIPPED (not fatal) as long as a scheme still holds a majority, and the
//       skipped count is reported to the caller (via `skipped`) rather than
//       silently dropped. Requires a >=50% majority so a truly mixed corpus still
//       reports not-applicable instead of decoding garbage.
// Known residual: a base32/base36/alphanumeric corpus matches the base64 charset
// and is decoded + labelled "base64" -- the bytes are still analysed correctly,
// only the label is imprecise (Qt ships no base32 decoder); tracked, not fatal.
QList<QByteArray> decodeCorpusBytes(const QStringList &tokens, QString &scheme,
                                    int *skipped = nullptr) {
    scheme.clear();
    if (skipped) *skipped = 0;
    if (tokens.isEmpty()) return {};
    static const QRegularExpression hexRe("^[0-9a-fA-F]+$");
    static const QRegularExpression b64Re("^[A-Za-z0-9+/_-]+={0,2}$");

    // Count charset conformers to choose the scheme by majority.
    int hexN = 0, b64N = 0;
    for (const QString &t : tokens) {
        if (!t.isEmpty() && hexRe.match(t).hasMatch()) ++hexN;      // hex charset, any length
        if (t.size() >= 4 && b64Re.match(t).hasMatch())  ++b64N;    // base64 charset
    }
    const int n = tokens.size();

    // Prefer hex when it holds a majority (hex is the more specific charset --
    // every hex token is also base64-charset, so ties go to hex).
    if (hexN * 2 >= n && hexN >= b64N) {
        QList<QByteArray> out;
        int skip = 0;
        for (const QString &t : tokens) {
            if (t.isEmpty() || !hexRe.match(t).hasMatch()) { ++skip; continue; }
            const QString even = (t.size() % 2) ? (QStringLiteral("0") + t) : t;   // preserve the half-byte
            out << QByteArray::fromHex(even.toLatin1());
        }
        if (out.isEmpty()) return {};
        scheme = "hex";
        if (skipped) *skipped = skip;
        return out;
    }

    if (b64N * 2 >= n) {
        QList<QByteArray> out;
        int skip = 0;
        for (const QString &t : tokens) {
            QByteArray b;
            if (t.size() >= 4 && b64Re.match(t).hasMatch()) {
                b = QByteArray::fromBase64(
                    t.toLatin1(), QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
                if (b.isEmpty())
                    b = QByteArray::fromBase64(
                        t.toLatin1(), QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
            }
            if (b.isEmpty()) { ++skip; continue; }
            out << b;
        }
        if (out.isEmpty()) return {};
        scheme = "base64";
        if (skipped) *skipped = skip;
        return out;
    }
    return {};   // no majority scheme -> genuinely mixed, not applicable
}

struct BitLevelResult {
    bool   applicable = false;
    QString scheme;
    int    skipped = 0;         // tokens skipped as non-conforming to the chosen scheme
    qint64 bits = 0;
    double monobitP = 1.0;      // NIST SP 800-22 frequency (monobit) p-value
    bool   monobitFail = false;
    double twoBitChi = 0.0;     // chi-square (3 dof) over non-overlapping bit pairs
    bool   twoBitFail = false;
    double serialR = 0.0;       // byte-level lag-1 serial correlation coefficient
    bool   serialFail = false;
    double pokerChi = -1.0;     // FIPS poker chi-square (15 dof); <0 = not computed
    bool   pokerFail = false;
    double runsZ = 0.0;         // Wald-Wolfowitz total-runs z-score
    bool   runsFail = false;
    qint64 longestRun = 0;      // longest run of identical bits
    bool   longRunFail = false;
    double runsBucketChi = -1.0;// FIPS run-length (1..6+) chi-square; <0 = not computed
    bool   runsBucketFail = false;
    double compRatio = 1.0;     // zlib compressed/original size
    bool   compFail = false;
    // Per-bit-position monobit: the global monobit dilutes a single stuck/biased
    // bit 1:(token bit-width). Evaluating monobit at EVERY bit position across the
    // fixed-width cohort catches a lone position the aggregate test never reaches.
    int    perBitPositions = 0; // positions evaluated (0 = not applicable)
    int    perBitFails = 0;     // positions with monobit p < 0.01
    double perBitMinP = 1.0;    // the worst (smallest) per-position p-value
    bool   perBitFail = false;  // >= 1 position failed
    // Inter-bit-position correlation: a pair of bit positions that move together
    // across tokens (one bit derivable from another -> reduced real keyspace),
    // which no single-position test sees. Pairwise phi/chi-square, Bonferroni over
    // all pairs (the "significance adjusted for interdependence").
    qint64 bitCorrPairs = 0;    // pairs evaluated (0 = not applicable)
    qint64 bitCorrFails = 0;    // pairs correlated past the corrected threshold
    double bitCorrMinP = 1.0;   // the most-correlated pair's p-value
    bool   bitCorrFail = false;
    bool   anyFail = false;
};

// Bit/byte-level tests on the decoded byte stream:
//   monobit : NIST frequency test -- proportion of 1-bits; p < 0.01 -> biased.
//   twoBit  : chi-square over the four non-overlapping 2-bit blocks (3 dof);
//             a flat stream spreads 00/01/10/11 evenly. Critical 11.345 (p<0.01).
//   serial  : lag-1 Pearson correlation of consecutive bytes -- the classic LCG
//             lattice / java.util.Random low-bit tell. A CSPRNG stream gives
//             r ~ 0; |r| past max(0.08, 3/sqrt(m)) (a generous ~3-sigma floor)
//             flags a linear dependency.
} // anonymous namespace boundary marker (functions below are exported)

// Upper tail of the chi-square distribution: P(X > chi) for `dof` degrees of
// freedom = the regularized upper incomplete gamma Q(dof/2, chi/2). Standard
// series (x < a+1) / Lentz continued-fraction (else) split; std::lgamma supplies
// the normaliser. Turns a chi-square statistic into a p-value. Exported so the
// per-position character test and the unit test can both use it.
double chiSquareSurvival(double chi, int dof) {
    if (dof <= 0 || chi <= 0.0) return 1.0;
    const double a = double(dof) / 2.0;
    const double x = chi / 2.0;
    const double gln = std::lgamma(a);
    if (x < a + 1.0) {
        // Series for the regularized LOWER incomplete gamma P(a,x); return 1-P.
        double ap = a, sum = 1.0 / a, del = sum;
        for (int i = 0; i < 300; ++i) {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if (std::fabs(del) < std::fabs(sum) * 1e-14) break;
        }
        const double P = sum * std::exp(-x + a * std::log(x) - gln);
        return 1.0 - P;
    }
    // Lentz continued fraction for the regularized UPPER incomplete gamma Q(a,x).
    const double tiny = 1e-300;
    double b = x + 1.0 - a, c = 1.0 / tiny, d = 1.0 / b, h = d;
    for (int i = 1; i < 300; ++i) {
        const double an = -double(i) * (double(i) - a);
        b += 2.0;
        d = an * d + b; if (std::fabs(d) < tiny) d = tiny;
        c = b + an / c; if (std::fabs(c) < tiny) c = tiny;
        d = 1.0 / d;
        const double delc = d * c;
        h *= delc;
        if (std::fabs(delc - 1.0) < 1e-14) break;
    }
    return std::exp(-x + a * std::log(x) - gln) * h;
}

double fipsPokerChiSquare(const QByteArray &bytes) {
    const qint64 bits = qint64(bytes.size()) * 8;
    const qint64 blocks = bits / 4;
    if (blocks < 80) return -1.0;              // too short for a meaningful chi-square
    long long f[16] = {0};
    qint64 idx = 0; int acc = 0;
    for (unsigned char ch : bytes)
        for (int i = 7; i >= 0; --i) {
            acc = (acc << 1) | ((ch >> i) & 1);
            if ((++idx & 3) == 0) { f[acc & 0xF]++; acc = 0; }
        }
    double sum = 0.0;
    for (int k = 0; k < 16; ++k) sum += double(f[k]) * double(f[k]);
    return (16.0 / double(blocks)) * sum - double(blocks);
}

double fipsRunsZScore(const QByteArray &bytes) {
    const qint64 total = qint64(bytes.size()) * 8;
    if (total < 100) return 0.0;
    qint64 ones = 0, runs = 0; int prev = -1; qint64 seen = 0;
    for (unsigned char ch : bytes)
        for (int i = 7; i >= 0; --i) {
            const int bit = (ch >> i) & 1;
            ones += bit;
            if (seen == 0 || bit != prev) ++runs;
            prev = bit; ++seen;
        }
    const double n1 = double(ones), n0 = double(total - ones), N = double(total);
    if (n1 <= 0.0 || n0 <= 0.0) return 0.0;    // degenerate: all one symbol
    const double mu  = 2.0 * n1 * n0 / N + 1.0;
    const double var = 2.0 * n1 * n0 * (2.0 * n1 * n0 - N) / (N * N * (N - 1.0));
    return var > 1e-12 ? (double(runs) - mu) / std::sqrt(var) : 0.0;
}

qint64 longestBitRun(const QByteArray &bytes) {
    qint64 longest = 0, cur = 0; int prev = -1; qint64 seen = 0;
    for (unsigned char ch : bytes)
        for (int i = 7; i >= 0; --i) {
            const int bit = (ch >> i) & 1;
            cur = (seen > 0 && bit == prev) ? cur + 1 : 1;
            if (cur > longest) longest = cur;
            prev = bit; ++seen;
        }
    return longest;
}

double fipsRunsBucketChi(const QByteArray &bytes) {
    const qint64 total = qint64(bytes.size()) * 8;
    if (total < 200) return -1.0;
    long long obs[6] = {0, 0, 0, 0, 0, 0};   // run-length buckets: 1,2,3,4,5,6+
    long long runs = 0;
    int prev = -1; qint64 seen = 0, cur = 0;
    auto closeRun = [&](qint64 len) {
        if (len <= 0) return;
        obs[int(qMin(len, qint64(6))) - 1]++;
        ++runs;
    };
    for (unsigned char ch : bytes)
        for (int i = 7; i >= 0; --i) {
            const int bit = (ch >> i) & 1;
            if (seen == 0)          cur = 1;
            else if (bit == prev)   ++cur;
            else { closeRun(cur);   cur = 1; }
            prev = bit; ++seen;
        }
    closeRun(cur);                            // the final run
    if (runs < 30) return -1.0;
    // Geometric run-length model: P(len=k) = 2^-k, the 6+ bucket absorbs the
    // tail (2^-5). Sum of the six proportions is exactly 1.
    static const double prop[6] = { 1.0/2, 1.0/4, 1.0/8, 1.0/16, 1.0/32, 1.0/32 };
    double chi = 0.0;
    for (int k = 0; k < 6; ++k) {
        const double exp = double(runs) * prop[k];
        if (exp < 1.0) continue;
        const double dv = double(obs[k]) - exp;
        chi += dv * dv / exp;
    }
    return chi;
}

double compressionRatio(const QByteArray &bytes) {
    if (bytes.size() < 128) return 1.0;       // qCompress overhead dominates small inputs
    const QByteArray z = qCompress(bytes, 9);
    // qCompress prepends a 4-byte big-endian original-size header; drop it so
    // the ratio reflects the deflate stream, not Qt's framing.
    const int comp = z.size() > 4 ? z.size() - 4 : z.size();
    return double(comp) / double(bytes.size());
}

double maxPositionalTransitionV(const QStringList &tokens) {
    const int n = tokens.size();
    if (n < 40) return -1.0;
    int width = tokens[0].size();
    for (const QString &t : tokens) width = qMin(width, int(t.size()));
    if (width <= 0) return -1.0;
    const double N = double(n - 1);          // number of consecutive-token pairs
    double maxV = 0.0;
    for (int p = 0; p < width; ++p) {
        // Index the distinct "from" (prev-token) and "to" (this-token) symbols
        // at this position, then build the contingency table.
        QHash<QChar, int> rowIdx, colIdx;
        for (int k = 1; k < n; ++k) {
            const QChar a = tokens[k - 1].at(p), b = tokens[k].at(p);
            if (!rowIdx.contains(a)) rowIdx.insert(a, rowIdx.size());
            if (!colIdx.contains(b)) colIdx.insert(b, colIdx.size());
        }
        const int R = rowIdx.size(), C = colIdx.size();
        if (R < 2 || C < 2) continue;        // no variation -> entropy tests own this
        QVector<QVector<double>> obs(R, QVector<double>(C, 0.0));
        QVector<double> rowT(R, 0.0), colT(C, 0.0);
        for (int k = 1; k < n; ++k) {
            const int a = rowIdx[tokens[k - 1].at(p)], b = colIdx[tokens[k].at(p)];
            obs[a][b] += 1.0; rowT[a] += 1.0; colT[b] += 1.0;
        }
        double chi = 0.0;
        for (int a = 0; a < R; ++a)
            for (int b = 0; b < C; ++b) {
                const double e = rowT[a] * colT[b] / N;
                if (e > 0.0) { const double d = obs[a][b] - e; chi += d * d / e; }
            }
        const double v = std::sqrt(chi / (N * double(qMin(R, C) - 1)));   // Cramer's V
        if (v > maxV) maxV = v;
    }
    return maxV;
}

QString reliabilityRating(int sampleCount) {
    // Randomness estimates converge with the corpus size; below the deep-test
    // floor almost nothing can be said. Thresholds mirror common guidance
    // (Burp warns under ~100; FIPS-style suites want thousands of samples).
    if (sampleCount < kDeepMinN) return QStringLiteral("insufficient");
    if (sampleCount < 100)       return QStringLiteral("low");
    if (sampleCount < 1000)      return QStringLiteral("medium");
    if (sampleCount < 5000)      return QStringLiteral("high");
    return QStringLiteral("very-high");
}

SampleSizeGuidance sampleSizeGuidance(int sampleCount, int decodedBits) {
    SampleSizeGuidance g;
    g.sampleCount = qMax(0, sampleCount);
    g.decodedBits = qMax(0, decodedBits);
    // Order matters: estimable is the harder floor (below it not even the deep
    // tests run), tooFew is the softer ~100-token reliability warning.
    g.estimable   = g.sampleCount >= kDeepMinN;
    g.tooFew      = g.sampleCount <  g.recommendedMinTokens;
    g.fipsBitsMet = g.decodedBits >= g.fipsBitThreshold;

    if (g.sampleCount == 0) {
        g.note = QStringLiteral("No tokens captured.");
        return g;
    }
    const QString n = QString::number(g.sampleCount);
    if (!g.estimable) {
        g.note = n + QStringLiteral(" token(s): far below the ~100-token minimum -- "
                                    "collect more before trusting any estimate.");
    } else if (g.tooFew) {
        g.note = n + QStringLiteral(" tokens: below the recommended ~100-token minimum -- "
                                    "treat the estimate as indicative only.");
    } else {
        g.note = n + QStringLiteral(" tokens: adequate for the character-level estimate. ");
        const QString b = QString::number(g.decodedBits);
        g.note += g.fipsBitsMet
            ? b + QStringLiteral(" decoded bits meet the 20,000-bit FIPS 140-2 threshold.")
            : b + QStringLiteral(" decoded bits are under the 20,000-bit FIPS 140-2 threshold "
                                 "-- collect more tokens for full bit-level conformance.");
    }
    return g;
}

namespace {

BitLevelResult bitLevelTests(const QStringList &tokens) {
    BitLevelResult r;
    if (tokens.size() < kDeepMinN) return r;

    QString scheme;
    int skipped = 0;
    const QList<QByteArray> per = decodeCorpusBytes(tokens, scheme, &skipped);
    if (per.isEmpty()) return r;

    QByteArray cat;
    for (const QByteArray &b : per) cat += b;
    if (cat.size() < 32) return r;              // need >= 256 bits to be meaningful
    r.applicable = true;
    r.scheme = scheme;
    r.skipped = skipped;

    // ---- monobit ----
    qint64 ones = 0;
    for (unsigned char ch : cat)
        for (int i = 0; i < 8; ++i) ones += (ch >> i) & 1;
    const qint64 total = qint64(cat.size()) * 8;
    r.bits = total;
    {
        const double s    = double(2 * ones - total);          // (#1 - #0)
        const double sObs = std::fabs(s) / std::sqrt(double(total));
        r.monobitP    = std::erfc(sObs / std::sqrt(2.0));
        r.monobitFail = r.monobitP < 0.01;
    }

    // Shared modal decoded-byte-width cohort for the per-position bit tests.
    QList<QByteArray> cohort;
    int modalW = 0;
    {
        QHash<int, int> wcount;
        for (const QByteArray &b : per) if (!b.isEmpty()) wcount[b.size()]++;
        int bestW = 0;
        for (auto it = wcount.cbegin(); it != wcount.cend(); ++it)
            if (it.value() > bestW) { bestW = it.value(); modalW = it.key(); }
        for (const QByteArray &b : per) if (b.size() == modalW) cohort << b;
    }
    const int cohortN = cohort.size();

    // ---- per-bit-position monobit ----
    // Test EACH bit position's 1/0 balance independently. A generator with one
    // stuck/biased bit (a fixed flag bit, a low-entropy nibble rendered to a
    // fixed column) fails here even when the aggregate monobit -- which dilutes
    // it 1:(width*8) -- passes.
    if (modalW > 0 && cohortN >= kDeepMinN) {
        const int positions = modalW * 8;
        r.perBitPositions = positions;
        // Bonferroni: testing `positions` bits at a naive 0.01 would false-
        // positive ~positions*0.01 times on RANDOM data. Correct to 0.01/positions
        // so the family-wise error rate stays ~0.01 -- clean corpus passes, a
        // genuinely stuck bit (p ~ 1e-11) still fails.
        const double alpha = 0.01 / double(positions);
        for (int pos = 0; pos < positions; ++pos) {
            const int byteIdx = pos / 8;
            const int bitIdx  = 7 - (pos % 8);   // MSB-first, matches the stream tests
            qint64 onesP = 0;
            for (const QByteArray &b : cohort)
                onesP += (static_cast<unsigned char>(b.at(byteIdx)) >> bitIdx) & 1;
            const double sObs = std::fabs(double(2 * onesP - cohortN)) / std::sqrt(double(cohortN));
            const double p    = std::erfc(sObs / std::sqrt(2.0));
            if (p < r.perBitMinP) r.perBitMinP = p;
            if (p < alpha) ++r.perBitFails;
        }
        r.perBitFail = r.perBitFails > 0;
    }

    // ---- inter-bit-position correlation ----
    // A pair of bit positions that move together across tokens means one bit is
    // derivable from another -- the real keyspace is smaller than the bit count
    // implies, and no single-position test sees it. For each pair build the 2x2
    // contingency table across the cohort; chi-square (1 dof) = n*phi^2 -> p via
    // chiSquareSurvival. Bonferroni over ALL pairs is the significance adjustment
    // for the interdependence of testing every pair. Capped at 1024 positions
    // (~500k pairs) to bound the O(positions^2 * n) cost.
    {
        const int positions = modalW * 8;
        if (modalW > 0 && cohortN >= kDeepMinN && positions >= 2 && positions <= 1024) {
            QVector<QVector<uint8_t>> bitcol(positions, QVector<uint8_t>(cohortN, 0));
            QVector<int> onesAt(positions, 0);
            for (int t = 0; t < cohortN; ++t) {
                const QByteArray &b = cohort[t];
                for (int pos = 0; pos < positions; ++pos) {
                    const uint8_t bit = (static_cast<unsigned char>(b.at(pos / 8)) >> (7 - (pos % 8))) & 1;
                    bitcol[pos][t] = bit;
                    onesAt[pos]   += bit;
                }
            }
            const qint64 pairs = qint64(positions) * (positions - 1) / 2;
            r.bitCorrPairs = pairs;
            const double alpha = 0.01 / double(pairs);   // Bonferroni over all pairs
            const double N = double(cohortN);
            for (int i = 0; i < positions; ++i) {
                const int a1 = onesAt[i];
                if (a1 == 0 || a1 == cohortN) continue;  // constant position: no correlation defined
                for (int j = i + 1; j < positions; ++j) {
                    const int b1 = onesAt[j];
                    if (b1 == 0 || b1 == cohortN) continue;
                    int both = 0;
                    for (int t = 0; t < cohortN; ++t) both += bitcol[i][t] & bitcol[j][t];
                    const double den = double(a1) * double(cohortN - a1) * double(b1) * double(cohortN - b1);
                    if (den <= 0.0) continue;
                    const double num = double(both) * N - double(a1) * double(b1);
                    const double chi = (num * num) * N / den;   // = n * phi^2, 1 dof
                    const double p = chiSquareSurvival(chi, 1);
                    if (p < r.bitCorrMinP) r.bitCorrMinP = p;
                    if (p < alpha) ++r.bitCorrFails;
                }
            }
            r.bitCorrFail = r.bitCorrFails > 0;
        }
    }

    // ---- two-bit (non-overlapping) frequency chi-square ----
    {
        qint64 counts[4] = {0, 0, 0, 0};
        qint64 bitIdx = 0;
        int    first = 0;
        for (unsigned char ch : cat)
            for (int i = 7; i >= 0; --i) {
                const int bit = (ch >> i) & 1;
                if ((bitIdx & 1) == 0) first = bit;
                else counts[(first << 1) | bit]++;
                ++bitIdx;
            }
        const qint64 pairs = bitIdx / 2;
        if (pairs >= 20) {
            const double exp = double(pairs) / 4.0;
            double chi = 0.0;
            for (int k = 0; k < 4; ++k) {
                const double d = double(counts[k]) - exp;
                chi += d * d / exp;
            }
            r.twoBitChi  = chi;
            r.twoBitFail = chi > 11.345;        // 3 dof, p < 0.01
        }
    }

    // ---- byte-level lag-1 serial correlation ----
    {
        const qint64 m = qint64(cat.size()) - 1;
        if (m >= 16) {
            double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
            for (qint64 i = 0; i < m; ++i) {
                const double x = double(static_cast<unsigned char>(cat[int(i)]));
                const double y = double(static_cast<unsigned char>(cat[int(i + 1)]));
                sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y;
            }
            const double num = double(m) * sxy - sx * sy;
            const double den = std::sqrt((double(m) * sxx - sx * sx) * (double(m) * syy - sy * sy));
            r.serialR    = (den > 1e-9) ? num / den : 0.0;
            const double thr = qMax(0.08, 3.0 / std::sqrt(double(m)));
            r.serialFail = std::fabs(r.serialR) > thr;
        }
    }

    // ---- FIPS 140-2 poker / runs / long-runs (over the same byte stream) ----
    r.pokerChi = fipsPokerChiSquare(cat);
    r.pokerFail = r.pokerChi >= 0.0 && r.pokerChi > 30.578;   // 15 dof, p < 0.01
    r.runsZ = fipsRunsZScore(cat);
    r.runsFail = std::fabs(r.runsZ) > 2.576;                  // p < 0.01
    r.longestRun = longestBitRun(cat);
    {
        // Expected count of a run of length >= L is ~ total * 2^-L; flag the
        // longest run only when even ONE run that long is highly improbable
        // (<1%) for this many bits. Scales with sample size (FIPS' fixed 26 is
        // tuned for a 20k-bit sample; this generalises).
        const double thr = std::log2(double(r.bits > 0 ? r.bits : 1)) + 6.64;  // log2(bits/0.01)
        r.longRunFail = double(r.longestRun) > thr;
    }

    // ---- FIPS length-bucketed runs test + compression test ----
    r.runsBucketChi = fipsRunsBucketChi(cat);
    r.runsBucketFail = r.runsBucketChi >= 0.0 && r.runsBucketChi > 15.086;  // 5 dof, p < 0.01
    r.compRatio = compressionRatio(cat);
    r.compFail = r.compRatio < 0.85;    // meaningfully compressible -> structure/repetition

    r.anyFail = r.monobitFail || r.twoBitFail || r.serialFail
             || r.pokerFail || r.runsFail || r.longRunFail
             || r.runsBucketFail || r.compFail || r.perBitFail || r.bitCorrFail;
    return r;
}

} // namespace

QJsonObject analyzeTokens(const QStringList &tokens) {
    QJsonObject result;
    result["n"] = tokens.size();
    result["reliability"] = reliabilityRating(tokens.size());
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
    // ...measured over the VARIABLE region only. A corpus-wide constant prefix/suffix
    // (a version tag, a fixed node id) contributes ZERO brute-force resistance, yet
    // multiplying by the FULL length credited it: 32 constant chars + 8 random hex
    // scored ~160 bits instead of the real ~32.
    const int seqPre = commonAffixLen(tokens, true);
    const int seqSuf = commonAffixLen(tokens, false);
    const int varLen = qMax(0, avgLen - seqPre - seqSuf);
    const double effectiveBits = combinedBits * varLen;
    QJsonObject shannon;
    shannon["bitsPerByte"] = combinedBits;
    shannon["totalBits"]   = combinedBits * combined.size();
    shannon["variableLen"] = varLen;
    shannon["effectiveBitsPerToken"] = effectiveBits;
    // Per-position effective entropy: sum of log2(observed alphabet size) per
    // column. Unlike effectiveBitsPerToken (global rate x length), this credits
    // only the entropy each column actually carries -- a structured token
    // (random prefix + fixed suffix) scores far below the global estimate here,
    // exposing keyspace the naive length-based figure over-counts.
    shannon["perPositionEffectiveBits"] = positionalEffectiveBits(tokens);
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

    // Per-position character-transition independence (serial correlation across
    // consecutive tokens). Flags a generator that is per-position predictable
    // even when each position's marginal distribution looks uniform.
    {
        const double transV = maxPositionalTransitionV(tokens);
        QJsonObject tr;
        tr["maxCramersV"] = transV;
        tr["applicable"]  = transV >= 0.0;
        tr["failed"]      = transV >= 0.0 && transV > 0.5;   // strong association
        result["transition"] = tr;
    }

    // Sequential / monotonic counter detection.
    qint64 delta = 0;
    const bool seq = looksSequential(tokens, delta);
    const bool mono = looksMonotonic(tokens);
    QJsonObject seqObj;
    seqObj["looksSequential"] = seq;
    seqObj["looksMonotonic"]  = mono;
    seqObj["delta"] = static_cast<double>(delta);
    result["sequential"] = seqObj;

    // Deeper tests: statistical flatness != cryptographic unpredictability.
    // These only activate on a corpus of >= kDeepMinN tokens (below that they
    // are noise), so smaller captures keep exactly their legacy grade.
    const PositionalResult pos = positionalEntropy(tokens);
    QJsonObject posObj;
    posObj["applicable"] = pos.applicable;
    // Length-tolerance diagnostics (#144) -- always present. offWidth > 0 means
    // tokens of other lengths exist; when applicable it's how many the modal-width
    // cross-sample test excluded, when skipped it says whether length variance (no
    // dominant width) or sample size was the cause.
    posObj["modalWidth"]   = pos.modalWidth;
    posObj["atModalWidth"] = pos.atModalWidth;
    posObj["offWidth"]     = pos.offWidth;
    if (pos.applicable) {
        posObj["width"] = pos.width;
        posObj["n"]     = pos.n;
        QJsonArray cols;
        for (double h : pos.columnEntropy) cols.append(h);
        posObj["columnEntropy"] = cols;
        posObj["reference"]     = pos.reference;
        posObj["weakColumns"]   = pos.weakColumns;
        posObj["biased"]        = pos.biased;
    } else {
        posObj["skipReason"] = pos.skipReason;
    }
    // Per-position character chi-square (distribution flatness per column, with a
    // p-value per column and a Bonferroni-corrected pass/fail count).
    const PositionalCharChi cc = positionalCharChiSquare(tokens);
    QJsonObject ccObj;
    ccObj["applicable"] = cc.applicable;
    if (cc.applicable) {
        ccObj["columns"]   = cc.columns;
        ccObj["failures"]  = cc.failures;      // columns with p < 0.01/columns
        ccObj["minPValue"] = cc.minPValue;     // the most-biased column's p-value
        ccObj["biased"]    = cc.failures > 0;
    }
    posObj["charChiSquare"] = ccObj;
    result["positional"] = posObj;

    const BitLevelResult bit = bitLevelTests(tokens);
    QJsonObject bitObj;
    bitObj["applicable"] = bit.applicable;
    if (bit.applicable) {
        bitObj["scheme"]  = bit.scheme;
        bitObj["skipped"] = bit.skipped;   // non-conforming tokens dropped from the decode (signal, not silent)
        bitObj["bits"]    = double(bit.bits);
        QJsonObject mono;
        mono["pValue"] = bit.monobitP;
        mono["failed"] = bit.monobitFail;
        bitObj["monobit"] = mono;
        QJsonObject perBit;
        perBit["positions"] = bit.perBitPositions;   // 0 = not evaluated (variable width / too few)
        perBit["failures"]  = bit.perBitFails;       // positions with monobit p < 0.01
        perBit["minPValue"] = bit.perBitMinP;        // the worst position's p-value
        perBit["failed"]    = bit.perBitFail;
        bitObj["perBitMonobit"] = perBit;
        QJsonObject bitCorr;
        bitCorr["pairs"]     = double(bit.bitCorrPairs);   // bit-position pairs evaluated
        bitCorr["failures"]  = double(bit.bitCorrFails);   // pairs correlated past the corrected threshold
        bitCorr["minPValue"] = bit.bitCorrMinP;            // the most-correlated pair's p-value
        bitCorr["failed"]    = bit.bitCorrFail;
        bitObj["bitCorrelation"] = bitCorr;
        QJsonObject two;
        two["chiSquare"] = bit.twoBitChi;
        two["failed"]    = bit.twoBitFail;
        bitObj["twoBit"] = two;
        QJsonObject ser;
        ser["r"]      = bit.serialR;
        ser["failed"] = bit.serialFail;
        bitObj["serialCorrelation"] = ser;
        QJsonObject poker;
        poker["chiSquare"] = bit.pokerChi;
        poker["failed"]    = bit.pokerFail;
        bitObj["poker"] = poker;
        QJsonObject runs;
        runs["z"]      = bit.runsZ;
        runs["failed"] = bit.runsFail;
        bitObj["runs"] = runs;
        QJsonObject longRun;
        longRun["longest"] = double(bit.longestRun);
        longRun["failed"]  = bit.longRunFail;
        bitObj["longRun"] = longRun;
        QJsonObject runsBucket;
        runsBucket["chiSquare"] = bit.runsBucketChi;
        runsBucket["failed"]    = bit.runsBucketFail;
        bitObj["runLengths"] = runsBucket;
        QJsonObject comp;
        comp["ratio"]  = bit.compRatio;
        comp["failed"] = bit.compFail;
        bitObj["compression"] = comp;
        bitObj["anyFailed"] = bit.anyFail;
    }
    result["bitLevel"] = bitObj;

    // Sample-size guidance: warn under ~100 tokens and flag whether the decoded
    // stream reaches the 20,000-bit FIPS 140-2 sample size (bit.bits is 0 when
    // the corpus isn't bit-testable, which correctly reports FIPS not met).
    const SampleSizeGuidance ssg = sampleSizeGuidance(tokens.size(), int(bit.bits));
    QJsonObject ssgObj;
    ssgObj["sampleCount"]          = ssg.sampleCount;
    ssgObj["decodedBits"]          = ssg.decodedBits;
    ssgObj["tooFew"]               = ssg.tooFew;
    ssgObj["estimable"]            = ssg.estimable;
    ssgObj["fipsBitsMet"]          = ssg.fipsBitsMet;
    ssgObj["recommendedMinTokens"] = ssg.recommendedMinTokens;
    ssgObj["fipsBitThreshold"]     = ssg.fipsBitThreshold;
    ssgObj["note"]                 = ssg.note;
    result["sampleGuidance"] = ssgObj;

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
    // Compare the LCS against the VARIABLE length it was measured on, not the full
    // avgLen: with a large constant affix the old comparison was unreachable (a
    // 16-char variable region can never produce an LCS > half of a 40-char token).
    if (lcs.size() > varLen / 2 && varLen > 8) score -= 30;
    // Cross-sample VARIETY. There was no distinctness test at all, so a corpus of
    // just two alternating values scored 100 / "looks-random" -- the worst possible
    // fail-open for the analysis whose whole job is catching predictable tokens.
    // Genuinely random tokens essentially never repeat (birthday bound), so any
    // duplicate is a red flag and a near-constant corpus is fatal. Only meaningful
    // with something to compare against, so n >= 2.
    if (tokens.size() >= 2) {
        const int distinct = QSet<QString>(tokens.begin(), tokens.end()).size();
        result["distinctTokens"] = distinct;
        if      (distinct <= 1)                      score -= 100;  // every sample identical
        else if (distinct * 2 <= tokens.size())      score -= 60;   // <= 50% unique
        else if (distinct < tokens.size())           score -= 25;   // any repeat at all
    }
    // Deeper-test deductions. Conservative, and gated behind kDeepMinN + standard
    // significance thresholds inside each test, so they only fire on a real
    // (large) corpus that genuinely fails. They catch the case the keyspace score
    // misses: a long token with high char entropy / high effective keyspace whose
    // bytes still come from a predictable (LCG / linear / per-position-leaky)
    // generator.
    if (pos.applicable && pos.biased)   score -= 20;   // a column leaks structure
    if (bit.applicable) {
        if (bit.monobitFail) score -= 20;              // biased decoded bitstream
        if (bit.twoBitFail)  score -= 15;              // non-uniform 2-bit blocks
        if (bit.serialFail)  score -= 25;              // LCG/linear lag-1 lattice
    }
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

#include "compare.hpp"

#include <QHash>

#include <algorithm>
#include <cmath>
#include <vector>

namespace Nullock::Core::Compare {
namespace {

// Per-side HARD cap on tokenisation, so a huge paste can't build a giant token
// list before the DP budget clips it. The DP table itself is bounded by kMaxCells
// (via budgetedSizes) -- this is only the tokeniser's own stop point. Emitting one
// past the cap is a SENTINEL that tells lcsDiff the input was longer (-> truncated).
constexpr qsizetype kMaxTokensPerSide = 20000;

QStringList tokenizeWords(const QString &s) {
    // Each token is a word plus its TRAILING whitespace (or a leading-whitespace
    // run on its own), so "a b" -> ["a ", "b"] and inserting one word counts as
    // one token -- while the join of all tokens still reproduces the input.
    // Stop once we're one past the cap so a huge paste can't build a giant list
    // before lcsDiff truncates (which would freeze the GUI thread).
    QStringList out;
    // qsizetype (not int) indices: QString::size() is qsizetype, and the inner word
    // scan advances per code UNIT while the cap is only checked per emitted TOKEN --
    // so a single >2GB whitespace-free token would overflow a 32-bit index (signed
    // UB -> runaway loop / crash on the GUI thread), the very freeze the cap prevents.
    // tokenizeChars already uses qsizetype; bring words/lines in line.
    qsizetype i = 0;
    while (i < s.size() && out.size() <= kMaxTokensPerSide) {
        qsizetype j = i;
        if (s[i].isSpace()) {                                  // leading whitespace run
            while (j < s.size() && s[j].isSpace()) ++j;
        } else {                                               // word + trailing whitespace
            while (j < s.size() && !s[j].isSpace()) ++j;
            while (j < s.size() && s[j].isSpace()) ++j;
        }
        out << s.mid(i, j - i);
        i = j;
    }
    return out;
}

QStringList tokenizeLines(const QString &s) {
    QStringList out;
    qsizetype start = 0;   // qsizetype, not int: a >2GB single line would overflow (see tokenizeWords)
    for (qsizetype i = 0; i < s.size() && out.size() <= kMaxTokensPerSide; ++i) {
        if (s[i] == QLatin1Char('\n')) { out << s.mid(start, i - start + 1); start = i + 1; }
    }
    if (start < s.size() && out.size() <= kMaxTokensPerSide) out << s.mid(start);
    return out;
}

QStringList tokenizeChars(const QString &s) {
    // Cap DURING tokenization (chars mode is one token per CODE POINT). Advance by
    // whole code points so a non-BMP character is ONE token, not two lone
    // surrogates -- which render as replacement glyphs AND false-match distinct
    // emoji (each shares a high surrogate).
    QStringList out;
    out.reserve(qMin<qsizetype>(s.size(), qsizetype(kMaxTokensPerSide) + 1));
    const qsizetype size = s.size();
    for (qsizetype i = 0; i < size && out.size() <= kMaxTokensPerSide; ) {
        if (s[i].isHighSurrogate() && i + 1 < size && s[i + 1].isLowSurrogate()) {
            out << s.mid(i, 2); i += 2;
        } else {
            out << QString(s[i]); ++i;
        }
    }
    return out;
}

// Longest-common-subsequence diff over token lists, emitting coalesced segments.
DiffResult lcsDiff(QStringList a, QStringList b) {
    DiffResult res;
    if (a.size() > kMaxTokensPerSide) { a = a.mid(0, kMaxTokensPerSide); res.truncated = true; }
    if (b.size() > kMaxTokensPerSide) { b = b.mid(0, kMaxTokensPerSide); res.truncated = true; }
    // Clip to the DP cell budget, keeping as much of each side as possible (a short
    // side is preserved whole; only an oversized side is clipped).
    const QPair<qsizetype, qsizetype> bs = budgetedSizes(a.size(), b.size());
    if (bs.first  < a.size()) { a = a.mid(0, bs.first);  res.truncated = true; }
    if (bs.second < b.size()) { b = b.mid(0, bs.second); res.truncated = true; }
    const int n = a.size(), m = b.size();

    // Intern tokens to integer ids so each DP cell compares in O(1) regardless of
    // token byte-size. The count cap bounds n*m, but a raw QString== per cell would
    // make the DP O(n*m*tokenLen) -- a multi-second GUI-thread freeze on large
    // repetitive input (2000x2000 cells x multi-KB tokens). Interning restores the
    // "tens of ms" guarantee the cap is meant to provide.
    QHash<QString, int> ids;
    ids.reserve(n + m);
    auto idOf = [&ids](const QString &t) {
        const auto it = ids.constFind(t);
        if (it != ids.constEnd()) return it.value();
        const int id = ids.size();
        ids.insert(t, id);
        return id;
    };
    std::vector<int> ai(n), bi(m);
    for (int i = 0; i < n; ++i) ai[i] = idOf(a[i]);
    for (int j = 0; j < m; ++j) bi[j] = idOf(b[j]);

    // dp[i][j] = LCS length of a[i:] and b[j:]. Flat (n+1)*(m+1) table.
    std::vector<int> dp(static_cast<size_t>(n + 1) * (m + 1), 0);
    const int stride = m + 1;
    auto cell = [&dp, stride](int i, int j) -> int & { return dp[static_cast<size_t>(i) * stride + j]; };
    for (int i = n - 1; i >= 0; --i)
        for (int j = m - 1; j >= 0; --j)
            cell(i, j) = (ai[i] == bi[j]) ? cell(i + 1, j + 1) + 1
                                          : std::max(cell(i + 1, j), cell(i, j + 1));
    res.common = (n && m) ? cell(0, 0) : 0;

    auto push = [&res](const char *op, const QString &text) {
        if (!res.segments.isEmpty() && res.segments.last().op == QLatin1String(op))
            res.segments.last().text += text;
        else
            res.segments.append({ QString::fromLatin1(op), text });
    };

    int i = 0, j = 0;
    while (i < n && j < m) {
        if (ai[i] == bi[j])                        { push("eq",  a[i]); ++i; ++j; }
        else if (cell(i + 1, j) >= cell(i, j + 1)) { push("del", a[i]); ++i; ++res.removed; }
        else                                       { push("ins", b[j]); ++j; ++res.added; }
    }
    while (i < n) { push("del", a[i]); ++i; ++res.removed; }
    while (j < m) { push("ins", b[j]); ++j; ++res.added; }

    // A TRUNCATED diff compared only the clipped prefix, so it must NEVER assert
    // identity -- two inputs equal in the first kMaxTokensPerSide but differing after
    // would otherwise be wrongly reported identical.
    res.identical = (!res.truncated && res.added == 0 && res.removed == 0);
    return res;
}

} // namespace

QPair<qsizetype, qsizetype> budgetedSizes(qsizetype n, qsizetype m) {
    if (n <= 0 || m <= 0) return { n, m };
    if (static_cast<long long>(n) * m <= kMaxCells) return { n, m };   // fits whole
    const qsizetype side = static_cast<qsizetype>(std::floor(std::sqrt(static_cast<double>(kMaxCells))));
    // Preserve a side that already fits under `side`, clipping only the oversized
    // one to budget/kept; when both exceed `side`, clip both to `side`.
    if (n <= side) return { n, static_cast<qsizetype>(kMaxCells / n) };
    if (m <= side) return { static_cast<qsizetype>(kMaxCells / m), m };
    return { side, side };
}

QStringList modes() {
    return { QStringLiteral("words"), QStringLiteral("lines"), QStringLiteral("chars") };
}

DiffResult diff(const QString &mode, const QString &a, const QString &b) {
    const QString m = mode.trimmed().toLower();
    if (m == QLatin1String("lines")) return lcsDiff(tokenizeLines(a), tokenizeLines(b));
    if (m == QLatin1String("chars")) return lcsDiff(tokenizeChars(a), tokenizeChars(b));
    return lcsDiff(tokenizeWords(a), tokenizeWords(b));   // default: words
}

} // namespace Nullock::Core::Compare

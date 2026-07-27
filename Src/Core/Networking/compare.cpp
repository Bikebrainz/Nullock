#include "compare.hpp"

#include <QHash>

#include <algorithm>
#include <vector>

namespace Nullock::Core::Compare {
namespace {

// The control handler runs on the GUI thread, so bound the LCS table: with a
// 2000-token-per-side cap the DP is at most 2000*2000 = 4M cells (~16 MB, tens
// of ms) -- imperceptible, and an attacker/huge paste can't freeze the UI.
constexpr int kMaxTokens = 2000;

QStringList tokenizeWords(const QString &s) {
    // Each token is a word plus its TRAILING whitespace (or a leading-whitespace
    // run on its own), so "a b" -> ["a ", "b"] and inserting one word counts as
    // one token -- while the join of all tokens still reproduces the input.
    // Stop once we're one past the cap so a huge paste can't build a giant list
    // before lcsDiff truncates (which would freeze the GUI thread).
    QStringList out;
    int i = 0;
    while (i < s.size() && out.size() <= kMaxTokens) {
        int j = i;
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
    int start = 0;
    for (int i = 0; i < s.size() && out.size() <= kMaxTokens; ++i) {
        if (s[i] == QLatin1Char('\n')) { out << s.mid(start, i - start + 1); start = i + 1; }
    }
    if (start < s.size() && out.size() <= kMaxTokens) out << s.mid(start);
    return out;
}

QStringList tokenizeChars(const QString &s) {
    // Cap DURING tokenization (chars mode is one token per CODE POINT). Advance by
    // whole code points so a non-BMP character is ONE token, not two lone
    // surrogates -- which render as replacement glyphs AND false-match distinct
    // emoji (each shares a high surrogate).
    QStringList out;
    out.reserve(qMin<qsizetype>(s.size(), qsizetype(kMaxTokens) + 1));
    const qsizetype size = s.size();
    for (qsizetype i = 0; i < size && out.size() <= kMaxTokens; ) {
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
    if (a.size() > kMaxTokens) { a = a.mid(0, kMaxTokens); res.truncated = true; }
    if (b.size() > kMaxTokens) { b = b.mid(0, kMaxTokens); res.truncated = true; }
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
    // identity -- two inputs equal in the first kMaxTokens but differing after
    // would otherwise be wrongly reported identical.
    res.identical = (!res.truncated && res.added == 0 && res.removed == 0);
    return res;
}

} // namespace

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

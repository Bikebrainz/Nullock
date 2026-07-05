#include "compare.hpp"

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
    QStringList out;
    int i = 0;
    while (i < s.size()) {
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
    for (int i = 0; i < s.size(); ++i) {
        if (s[i] == QLatin1Char('\n')) { out << s.mid(start, i - start + 1); start = i + 1; }
    }
    if (start < s.size()) out << s.mid(start);
    return out;
}

QStringList tokenizeChars(const QString &s) {
    QStringList out;
    out.reserve(s.size());
    for (const QChar c : s) out << QString(c);
    return out;
}

// Longest-common-subsequence diff over token lists, emitting coalesced segments.
DiffResult lcsDiff(QStringList a, QStringList b) {
    DiffResult res;
    if (a.size() > kMaxTokens) { a = a.mid(0, kMaxTokens); res.truncated = true; }
    if (b.size() > kMaxTokens) { b = b.mid(0, kMaxTokens); res.truncated = true; }
    const int n = a.size(), m = b.size();

    // dp[i][j] = LCS length of a[i:] and b[j:]. Flat (n+1)*(m+1) table.
    std::vector<int> dp(static_cast<size_t>(n + 1) * (m + 1), 0);
    const int stride = m + 1;
    auto cell = [&dp, stride](int i, int j) -> int & { return dp[static_cast<size_t>(i) * stride + j]; };
    for (int i = n - 1; i >= 0; --i)
        for (int j = m - 1; j >= 0; --j)
            cell(i, j) = (a[i] == b[j]) ? cell(i + 1, j + 1) + 1
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
        if (a[i] == b[j])                        { push("eq",  a[i]); ++i; ++j; }
        else if (cell(i + 1, j) >= cell(i, j + 1)) { push("del", a[i]); ++i; ++res.removed; }
        else                                      { push("ins", b[j]); ++j; ++res.added; }
    }
    while (i < n) { push("del", a[i]); ++i; ++res.removed; }
    while (j < m) { push("ins", b[j]); ++j; ++res.added; }

    res.identical = (res.added == 0 && res.removed == 0);
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

#include "intruder_grep.hpp"

#include <QRegularExpression>

namespace Nullock::Core::IntruderGrep {

namespace {

// Cap the scanned text to the first kMaxScan chars. QString::left is cheap
// (implicitly shared when the string is already short) and guarantees every
// downstream regex / indexOf operates on a bounded input -- the single most
// important defense against a huge response stalling the GUI-thread callback.
QString bounded(const QString &text) {
    return text.size() > kMaxScan ? text.left(kMaxScan) : text;
}

} // namespace

bool grepMatch(const QString &text, const QStringList &needles) {
    if (needles.isEmpty()) return false;
    const QString hay = bounded(text);

    for (const QString &needle : needles) {
        if (needle.isEmpty()) continue;
        // Try as a regex. A valid pattern uses regex semantics (so "tok_\d+"
        // works); an INVALID pattern degrades to a literal substring search
        // (so a stray "[" in a literal needle can't throw or spuriously miss).
        const QRegularExpression re(needle);
        if (re.isValid()) {
            if (re.match(hay).hasMatch()) return true;
        } else {
            if (hay.contains(needle)) return true;
        }
    }
    return false;
}

QString grepExtract(const QString &text, const ExtractSpec &spec) {
    const QString hay = bounded(text);

    // Regex mode wins when a pattern is present.
    if (!spec.regex.isEmpty()) {
        const QRegularExpression re(spec.regex);
        if (!re.isValid()) return {};          // malformed -> no extraction
        const QRegularExpressionMatch m = re.match(hay);
        if (!m.hasMatch()) return {};
        // First capture group if the pattern defines one; otherwise the whole
        // match. lastCapturedIndex() is >0 when at least one group captured.
        return m.lastCapturedIndex() >= 1 ? m.captured(1) : m.captured(0);
    }

    // Delimiter mode: text after the first `start` and before the next `end`.
    // A missing start/end yields nothing. An empty start means "from the
    // beginning"; an empty end means "to the end of the scanned prefix".
    if (spec.start.isEmpty() && spec.end.isEmpty()) return {};

    int from = 0;
    if (!spec.start.isEmpty()) {
        const int s = hay.indexOf(spec.start);
        if (s < 0) return {};
        from = s + spec.start.size();
    }
    int to = hay.size();
    if (!spec.end.isEmpty()) {
        const int e = hay.indexOf(spec.end, from);
        if (e < 0) return {};
        to = e;
    }
    if (to < from) return {};
    return hay.mid(from, to - from);
}

} // namespace Nullock::Core::IntruderGrep

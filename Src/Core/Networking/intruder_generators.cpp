#include "intruder_generators.hpp"

#include <QDate>
#include <QVector>

#include <limits>

namespace Nullock::Core::IntruderGenerators {

namespace {
QString fmtNumber(qint64 n, int width, bool hex) {
    QString s = hex ? QString::number(n, 16) : QString::number(n);
    if (width > 0) {
        const bool neg = s.startsWith(QLatin1Char('-'));
        QString digits = neg ? s.mid(1) : s;
        while (digits.size() < width) digits.prepend(QLatin1Char('0'));
        s = neg ? QLatin1Char('-') + digits : digits;
    }
    return s;
}

// "Propername"/"ProperName": uppercase the FIRST code point; the rest is either
// lowered (lowerRest=true) or left unchanged. Code-point safe -- toUcs4 so a
// leading non-BMP glyph is upper-cased/copied whole, never split into surrogates.
QString properCase(const QString &s, bool lowerRest) {
    const QList<uint> cps = s.toUcs4();
    if (cps.isEmpty()) return s;
    const char32_t first = cps[0];
    QString out = QString::fromUcs4(&first, 1).toUpper();
    QString rest;
    for (int i = 1; i < cps.size(); ++i) { const char32_t u = cps[i]; rest += QString::fromUcs4(&u, 1); }
    out += lowerRest ? rest.toLower() : rest;
    return out;
}
} // namespace

QStringList numbers(qint64 from, qint64 to, qint64 step, int width, bool hex) {
    QStringList out;
    if (step == 0) return out;
    if (step > 0 && from > to) return out;
    if (step < 0 && from < to) return out;

    qint64 n = from;
    for (int i = 0; i < kMaxCount; ++i) {
        if (step > 0 ? (n > to) : (n < to)) break;
        out.append(fmtNumber(n, width, hex));
        // Advance without signed overflow: if n + step would wrap, stop instead.
        if (step > 0 && n > std::numeric_limits<qint64>::max() - step) break;
        if (step < 0 && n < std::numeric_limits<qint64>::min() - step) break;
        n += step;
    }
    return out;
}

QStringList brute(const QString &charset, int minLen, int maxLen) {
    QStringList out;
    if (charset.isEmpty()) return out;
    if (minLen < 1) minLen = 1;
    if (maxLen < minLen) return out;

    // Enumerate by CODE POINT (toUcs4), not UTF-16 unit, so a non-BMP charset
    // symbol is emitted whole -- charset.at() splits a surrogate pair into two
    // lone surrogates. And bound cumulative CHAR volume, not just string COUNT: a
    // single-char charset yields exactly one string per length, so kMaxCount alone
    // lets total length grow to O(maxLen^2) -> a multi-GB OOM.
    const QList<uint> cps = charset.toUcs4();
    const int base = cps.size();
    constexpr qint64 kMaxChars = static_cast<qint64>(kMaxCount) * 64;   // ~6.4M cap
    qint64 emitted = 0;
    for (int len = minLen; len <= maxLen && out.size() < kMaxCount && emitted < kMaxChars; ++len) {
        QVector<int> idx(len, 0);               // odometer of `len` charset indices
        while (out.size() < kMaxCount && emitted < kMaxChars) {
            QString s;
            s.reserve(len);
            for (int k = 0; k < len; ++k) { const char32_t u = cps[idx[k]]; s.append(QString::fromUcs4(&u, 1)); }
            out.append(s);
            emitted += len;
            // increment: rightmost digit fastest; carry left.
            int pos = len - 1;
            for (; pos >= 0; --pos) {
                if (++idx[pos] < base) break;
                idx[pos] = 0;
            }
            if (pos < 0) break;                 // rolled all the way over -> length done
        }
    }
    return out;
}

QStringList dates(const QString &fromIso, const QString &toIso, int stepDays,
                  const QString &format) {
    QStringList out;
    if (stepDays <= 0) return out;
    const QDate from = QDate::fromString(fromIso, Qt::ISODate);
    const QDate to   = QDate::fromString(toIso, Qt::ISODate);
    if (!from.isValid() || !to.isValid() || from > to) return out;

    for (QDate d = from; d <= to && out.size() < kMaxCount; d = d.addDays(stepDays))
        out.append(d.toString(format));
    return out;
}

QStringList charSub(const QStringList &items, const QHash<QChar, QChar> &subs) {
    QStringList out;
    if (subs.isEmpty()) return out;
    for (const QString &item : items) {
        if (out.size() >= kMaxCount) break;
        QList<int> positions;                        // indices whose char has a substitution
        for (int i = 0; i < item.size(); ++i)
            if (subs.contains(item[i])) positions << i;
        const int k = positions.size();
        // Bit `b` (LSB = leftmost substitutable position) selects whether that
        // position is substituted. qint64 + a 31-bit clamp avoids UB on a huge k;
        // the kMaxCount guard stops the enumeration long before that anyway.
        const int kb = qMin(k, 31);
        const qint64 combos = qint64(1) << kb;
        for (qint64 mask = 0; mask < combos && out.size() < kMaxCount; ++mask) {
            QString s = item;
            for (int b = 0; b < kb; ++b)
                if (mask & (qint64(1) << b)) s[positions[b]] = subs.value(item[positions[b]]);
            out << s;
        }
    }
    return out;
}

QStringList caseMod(const QStringList &items, unsigned modes) {
    QStringList out;
    if (modes == 0) return out;
    auto add = [&](const QString &s) { if (out.size() < kMaxCount) out.append(s); };
    for (const QString &item : items) {
        if (out.size() >= kMaxCount) break;
        if (modes & CaseNoChange)   add(item);
        if (modes & CaseLower)      add(item.toLower());
        if (modes & CaseUpper)      add(item.toUpper());
        if (modes & CaseProper)     add(properCase(item, /*lowerRest=*/true));
        if (modes & CaseProperKeep) add(properCase(item, /*lowerRest=*/false));
    }
    return out;
}

QStringList charBlocks(const QString &base, int minMult, int maxMult, int step) {
    QStringList out;
    if (base.isEmpty() || step < 1) return out;
    if (minMult < 1) minMult = 1;
    if (maxMult < minMult) return out;
    constexpr qint64 kMaxChars = static_cast<qint64>(kMaxCount) * 64;
    qint64 emitted = 0;
    for (int k = minMult; k <= maxMult && out.size() < kMaxCount; k += step) {
        const qint64 blockLen = static_cast<qint64>(base.size()) * k;
        if (emitted + blockLen > kMaxChars) break;   // would breach the volume cap -> stop BEFORE building
        out.append(base.repeated(k));                // base multiplied k times (whole repeat, not truncate)
        emitted += blockLen;
    }
    return out;
}

QStringList frob(const QString &base) {
    QStringList out;
    const QList<uint> cps = base.toUcs4();
    if (cps.isEmpty()) return out;
    // Bound total emitted chars too, not just count: frob emits N payloads each of
    // length N, so an L-char base is O(L^2) chars -- the same OOM shape brute()
    // guards against. Cap volume at kMaxCount*64 chars.
    constexpr qint64 kMaxChars = static_cast<qint64>(kMaxCount) * 64;
    qint64 emitted = 0;
    for (int i = 0; i < cps.size() && out.size() < kMaxCount && emitted < kMaxChars; ++i) {
        QList<uint> mod = cps;
        uint n = mod[i] + 1;
        if (n > 0x10FFFFu) n = 0;                        // wrapped past the max Unicode scalar
        if (n >= 0xD800u && n <= 0xDFFFu) n = 0xE000u;   // skip the surrogate range -> stay valid
        mod[i] = n;
        QString s;
        s.reserve(cps.size());
        for (const uint cp : mod) { const char32_t u = cp; s.append(QString::fromUcs4(&u, 1)); }
        out.append(s);
        emitted += cps.size();
    }
    return out;
}

QStringList nullPayloads(int count) {
    QStringList out;
    if (count < 1) return out;
    const int n = qMin(count, kMaxCount);
    out.reserve(n);
    for (int i = 0; i < n; ++i) out.append(QString());   // empty -> re-sends the base request
    return out;
}

QStringList types() {
    return { QStringLiteral("numbers"), QStringLiteral("brute"),
             QStringLiteral("dates"), QStringLiteral("null"),
             QStringLiteral("frobber"), QStringLiteral("blocks"),
             QStringLiteral("casemod"), QStringLiteral("charsub") };
}

} // namespace Nullock::Core::IntruderGenerators

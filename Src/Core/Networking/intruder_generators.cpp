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

    const int base = charset.size();
    for (int len = minLen; len <= maxLen && out.size() < kMaxCount; ++len) {
        QVector<int> idx(len, 0);               // odometer of `len` charset indices
        while (out.size() < kMaxCount) {
            QString s;
            s.reserve(len);
            for (int k = 0; k < len; ++k) s.append(charset.at(idx[k]));
            out.append(s);
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

QStringList types() {
    return { QStringLiteral("numbers"), QStringLiteral("brute"), QStringLiteral("dates") };
}

} // namespace Nullock::Core::IntruderGenerators

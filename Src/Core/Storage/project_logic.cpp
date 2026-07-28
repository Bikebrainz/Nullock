// Pure project-name validation (see project_logic.hpp). No I/O; Qt6::Core only.

#include "project_logic.hpp"

#include <QStringList>

namespace Nullock::Core::ProjectLogic {

bool isValidProjectName(const QString &name) {
    if (name.isEmpty() || name.size() > 64) return false;
    if (name.contains(QChar('\0')) || name.contains(QChar('/')) || name.contains(QChar('\\'))
        || name.contains(QLatin1String("..")) || name.startsWith(QChar('.')) || name.startsWith(QChar(' '))
        || name.endsWith(QChar('.')) || name.endsWith(QChar(' '))) return false;
    static const QStringList kReserved = {
        "CON", "NUL", "PRN", "AUX", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };
    // Windows applies device semantics to the name STEM (before the first dot), so
    // "CON.txt" / "COM1.log" still resolve to the device -- check the stem, not the
    // whole name. Fold the legacy superscript digits (COM¹/COM²/COM³, LPT¹...) to
    // ASCII first: Windows resolves those to the real device, but toUpper() alone
    // does not fold them, so they would otherwise slip the reserved check.
    QString stem = name.section(QChar('.'), 0, 0).toUpper();
    stem.replace(QChar(0x00B9), QChar('1')).replace(QChar(0x00B2), QChar('2')).replace(QChar(0x00B3), QChar('3'));
    // Windows STRIPS trailing spaces AND dots from a name segment before resolving a
    // device, so "CON .txt" / "COM1 .log" still hit the device. Right-trim them from
    // the stem before matching -- the whole-name endsWith(' ')/('.') guard above does
    // NOT catch a trailing space that sits just before the extension dot.
    while (stem.endsWith(QChar(' ')) || stem.endsWith(QChar('.'))) stem.chop(1);
    if (kReserved.contains(stem)) return false;
    for (const QChar c : name) {
        const ushort u = c.unicode();
        if (u < 0x20) return false;            // control chars
        if (!c.isLetterOrNumber()
            && c != QChar('_') && c != QChar('-') && c != QChar(' ') && c != QChar('.'))
            return false;
    }
    return true;
}

} // namespace Nullock::Core::ProjectLogic

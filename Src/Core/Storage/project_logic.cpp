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
    // whole name.
    if (kReserved.contains(name.section(QChar('.'), 0, 0).toUpper())) return false;
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

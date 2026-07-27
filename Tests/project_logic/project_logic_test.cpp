// Regression corpus for the project-store path-traversal guard (no I/O). A project
// name becomes a directory under the projects root, so isValidProjectName() is the
// guard that stops a name escaping the root or naming a Windows device. An
// adversarial review confirmed it sound; this locks it AND the fix it surfaced:
//   - the Windows reserved-name check now matches the STEM before the first dot,
//     so "CON.txt" / "COM1.log" (still the device on Win32) are rejected -- while
//     NOT over-rejecting "console" / "contacts" whose stem merely starts with the
//     reserved token.
//
// Run via:  ctest -R project_logic -V

#include "project_logic.hpp"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::ProjectLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== accept normal project names ==================================
    chk("valid: a plain name", isValidProjectName("myproject"));
    chk("valid: hyphen + digits", isValidProjectName("test-run-01"));
    chk("valid: interior spaces", isValidProjectName("my big test"));
    chk("valid: an interior/extension dot", isValidProjectName("project.bak"));
    chk("valid: underscore", isValidProjectName("a_b_c"));

    // ===== path-traversal rejections ====================================
    chk("traversal: '..' rejected", !isValidProjectName(".."));
    chk("traversal: '../x' rejected", !isValidProjectName("../x"));
    chk("traversal: a forward slash rejected", !isValidProjectName("a/b"));
    chk("traversal: a backslash rejected", !isValidProjectName("a\\b"));
    chk("traversal: a drive-letter colon rejected", !isValidProjectName("C:foo"));
    chk("traversal: a UNC backslash rejected", !isValidProjectName("\\\\host\\share"));
    chk("traversal: NUL rejected", !isValidProjectName(QString("a") + QChar(0) + QString("b")));

    // ===== Windows reserved device names ================================
    chk("reserved: CON rejected", !isValidProjectName("CON"));
    chk("reserved: case-insensitive (con)", !isValidProjectName("con"));
    chk("reserved: NUL rejected", !isValidProjectName("NUL"));
    chk("reserved: COM1 rejected", !isValidProjectName("COM1"));
    chk("reserved: LPT9 rejected", !isValidProjectName("LPT9"));
    chk("reserved: AUX rejected", !isValidProjectName("AUX"));
    // The FIX: a reserved STEM with an extension is still the device.
    chk("reserved: CON.txt rejected (stem is the device) -- the fix", !isValidProjectName("CON.txt"));
    chk("reserved: NUL.json rejected", !isValidProjectName("NUL.json"));
    chk("reserved: COM1.log rejected", !isValidProjectName("COM1.log"));
    chk("reserved: con.bak rejected (case + ext)", !isValidProjectName("con.bak"));
    // ...but NOT over-rejecting names that merely START with a reserved token.
    chk("reserved: 'console' is allowed (stem CONSOLE != CON)", isValidProjectName("console"));
    chk("reserved: 'contacts' is allowed", isValidProjectName("contacts"));
    chk("reserved: 'com10' is allowed (only COM1..9 are devices)", isValidProjectName("com10"));
    // audit-7: legacy superscript digits fold to the real device (Windows resolves
    // COM²/LPT¹/COM³), but toUpper() alone doesn't fold them -> must still reject.
    chk("reserved: COM superscript-2 rejected", !isValidProjectName(QStringLiteral("COM") + QChar(0x00B2)));
    chk("reserved: LPT superscript-1 rejected", !isValidProjectName(QStringLiteral("LPT") + QChar(0x00B9)));
    chk("reserved: COM superscript-3 rejected", !isValidProjectName(QStringLiteral("COM") + QChar(0x00B3)));

    // ===== leading/trailing dot & space (Win32 strips them) =============
    chk("dot: a leading dot rejected", !isValidProjectName(".hidden"));
    chk("dot: a trailing dot rejected", !isValidProjectName("project."));
    chk("space: a leading space rejected", !isValidProjectName(" leading"));
    chk("space: a trailing space rejected", !isValidProjectName("trailing "));

    // ===== control chars / charset / length =============================
    chk("ctrl: a newline rejected", !isValidProjectName("a\nb"));
    chk("ctrl: a tab rejected", !isValidProjectName("a\tb"));
    chk("charset: '=' rejected", !isValidProjectName("a=b"));
    chk("charset: ';' rejected", !isValidProjectName("a;b"));
    chk("charset: '|' rejected", !isValidProjectName("a|b"));
    chk("empty: rejected", !isValidProjectName(""));
    chk("len: 64 chars accepted", isValidProjectName(QString(64, QChar('a'))));
    chk("len: 65 chars rejected", !isValidProjectName(QString(65, QChar('a'))));

    std::fprintf(stderr, "project_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

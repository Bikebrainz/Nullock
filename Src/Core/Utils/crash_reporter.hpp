#pragma once

// Local crash reporter. Catches the OS-level crash signals (SIGSEGV
// on Linux/Mac, SetUnhandledExceptionFilter on Windows), writes a
// minimal report to a per-user crash directory, and prints a hint on
// how to file a GitHub issue.
//
// What we capture:
//   * timestamp (UTC ISO 8601)
//   * Nullock version (from NULLOCK_VERSION compile-define)
//   * OS + architecture (Qt sysinfo)
//   * Stack trace (best-effort via QStringList from backtrace() on
//     Linux/Mac; on Windows we capture the exception address)
//   * Last 200 lines of recent log output
//
// What we DO NOT capture: project name, captured traffic, user data.
// We don't upload anything; the file is left for the user to inspect
// and (optionally) paste into a GitHub issue.
//
// Crash files land at:
//   Windows: %LOCALAPPDATA%/Nullock/crashes/
//   macOS:   ~/Library/Application Support/Nullock/crashes/
//   Linux:   ~/.local/share/Nullock/crashes/

#include <QString>

namespace Nullock::Core::CrashReporter {

// Install handlers. Idempotent. Call once during app startup.
void install();

// The directory we write reports to. Created on first install().
QString crashDir();

// Convenience: record a non-fatal error (e.g. caught exception in a
// JS extension). Same on-disk format as a crash but tagged "non-fatal".
void recordNonFatal(const QString &source, const QString &description);

} // namespace Nullock::Core::CrashReporter

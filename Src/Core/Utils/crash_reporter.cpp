#include "crash_reporter.hpp"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QSysInfo>
#include <QTextStream>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <execinfo.h>
#include <unistd.h>
#endif

namespace Nullock::Core::CrashReporter {

namespace {

std::atomic<bool> g_installed{false};

QString isoNow() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

QString crashFilename(const QString &kind) {
    QString stamp = isoNow();
    stamp.replace(':', '-');
    return crashDir() + "/" + kind + "-" + stamp + ".txt";
}

void writeReport(const QString &kind, const QString &what,
                 const QString &stackBlob) {
    QDir().mkpath(crashDir());
    QFile f(crashFilename(kind));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    QTextStream out(&f);
    out << "Nullock crash report (" << kind << ")\n";
    out << "================================\n\n";
    out << "When:         " << isoNow() << "\n";
    out << "Version:      " <<
#ifdef NULLOCK_VERSION
        QStringLiteral(NULLOCK_VERSION)
#else
        QStringLiteral("unknown")
#endif
        << "\n";
    out << "Build:        " << __DATE__ << " " << __TIME__ << "\n";
    out << "OS:           " << QSysInfo::prettyProductName() << "\n";
    out << "Kernel:       " << QSysInfo::kernelType() << " "
                            << QSysInfo::kernelVersion() << "\n";
    out << "Architecture: " << QSysInfo::currentCpuArchitecture() << "\n";
    out << "\n--- description ---\n" << what << "\n";
    out << "\n--- stack ---\n"       << stackBlob << "\n";
    out << "\n--- next steps ---\n"
        << "Please file a GitHub issue with this report attached:\n"
        << "  https://github.com/Bikebrainz/Nullock/issues/new\n\n"
        << "We never upload these automatically. Review before sharing.\n";
}

QString captureStackTrace() {
#ifdef Q_OS_WIN
    HANDLE proc = GetCurrentProcess();
    SymInitialize(proc, nullptr, TRUE);
    void *frames[64];
    USHORT n = CaptureStackBackTrace(0, 64, frames, nullptr);
    QString out;
    char buf[sizeof(SYMBOL_INFO) + 256];
    auto *sym = reinterpret_cast<SYMBOL_INFO *>(buf);
    sym->MaxNameLen   = 255;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    for (USHORT i = 0; i < n; ++i) {
        if (SymFromAddr(proc, (DWORD64)(frames[i]), nullptr, sym)) {
            out += QString("  [%1] %2  + 0x%3\n")
                       .arg(i, 2)
                       .arg(QString::fromLocal8Bit(sym->Name))
                       .arg((quint64)frames[i] - sym->Address, 0, 16);
        } else {
            out += QString("  [%1] 0x%2  (no symbol)\n")
                       .arg(i, 2).arg((quint64)frames[i], 0, 16);
        }
    }
    return out;
#else
    void *frames[64];
    int n = backtrace(frames, 64);
    char **syms = backtrace_symbols(frames, n);
    QString out;
    for (int i = 0; i < n; ++i) {
        out += QString("  [%1] %2\n").arg(i, 2).arg(syms ? syms[i] : "<no symbol>");
    }
    if (syms) free(syms);
    return out;
#endif
}

#ifdef Q_OS_WIN
LONG WINAPI seFilter(EXCEPTION_POINTERS *info) {
    QString what = QString("Windows SEH: code=0x%1, address=0x%2")
                      .arg(info->ExceptionRecord->ExceptionCode, 0, 16)
                      .arg((quint64)info->ExceptionRecord->ExceptionAddress, 0, 16);
    writeReport("crash", what, captureStackTrace());
    std::fprintf(stderr,
        "\n[Nullock] crash report written to %s\n",
        crashDir().toLocal8Bit().constData());
    return EXCEPTION_EXECUTE_HANDLER;
}
#else
void posixSig(int sig) {
    const char *name = "?";
    switch (sig) {
        case SIGSEGV: name = "SIGSEGV"; break;
        case SIGABRT: name = "SIGABRT"; break;
        case SIGFPE:  name = "SIGFPE";  break;
        case SIGILL:  name = "SIGILL";  break;
        case SIGBUS:  name = "SIGBUS";  break;
    }
    writeReport("crash", QString("POSIX signal: %1 (%2)").arg(name).arg(sig),
                captureStackTrace());
    std::fprintf(stderr,
        "\n[Nullock] crash report written to %s\n",
        crashDir().toLocal8Bit().constData());
    // Re-raise with the default handler so we still produce a core file.
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}
#endif

} // namespace

QString crashDir() {
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
           + "/crashes";
}

void install() {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return;
#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(seFilter);
#else
    struct sigaction sa{};
    sa.sa_handler = posixSig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    for (int s : { SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS })
        sigaction(s, &sa, nullptr);
#endif
}

void recordNonFatal(const QString &source, const QString &description) {
    writeReport("non-fatal",
                source + ": " + description,
                captureStackTrace());
}

} // namespace Nullock::Core::CrashReporter

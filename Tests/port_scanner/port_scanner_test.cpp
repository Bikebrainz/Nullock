// Regression corpus for the port scanner's pure banner classifier (no network).
// An adversarial audit confirmed 4 mislabels; this locks the fixes:
//   FP fixes:
//     - an OS-version mention ("Microsoft Windows") in a telnet/SMTP/FTP greeting
//       is NOT a winrm/smb service (that mapping was removed);
//     - an HTML body that merely mentions "PostgreSQL"/"MySQL"/"Redis" is HTTP,
//       not that database (an HTTP/1. status line anywhere wins first).
//   FN fixes:
//     - an IMAP "* OK" greeting is detected even without the literal word IMAP;
//     - common dev/app-server ports (3000/5000/8081/9090) classify as http.
//   Plus: TLS is detected from the RAW 0x16 0x03 record bytes (the scanner now
//   classifies on raw bytes, not a lossy UTF-8 round-trip), and the known wire
//   prefixes / port table still resolve.
//
// Run via:  ctest -R port_scanner -V

#include "port_scanner.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString cls(quint16 port, const QByteArray &banner) { return classifyBanner(port, banner); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== #1 OS mention is NOT a service mislabel =======================
    chk("telnet banner mentioning 'Microsoft Windows' -> telnet (port), NOT winrm/smb",
        cls(23, "\r\nMicrosoft Windows [Version 10.0.19045]\r\n") == "telnet");
    chk("an SMTP greeting that prints the Windows OS -> smtp (220+SMTP), not winrm/smb",
        cls(25, "220 mail.example.com ESMTP Microsoft Windows ready") == "smtp");

    // ===== #1 HTML body mentioning a DB is HTTP, not the DB ==============
    chk("HTTP body mentioning PostgreSQL -> http (HTTP/1. wins), not postgresql",
        cls(8080, "HTTP/1.1 500\r\n\r\n<title>Could not connect to PostgreSQL</title>") == "http");
    chk("a leading blank line then HTTP/1. -> http (status line anywhere)",
        cls(80, "\r\nHTTP/1.0 200 OK\r\nServer: x\r\n\r\nMySQL error") == "http");
    chk("a genuine non-HTTP banner containing 'PostgreSQL' -> postgresql",
        cls(5432, "E\x00\x00PostgreSQL 14.2 auth") == "postgresql");

    // ===== #4 IMAP without the literal word IMAP ========================
    // Use a NON-tabled port so this exercises the banner classifier, not the
    // port-143 fallback (else a revert of the fix would still pass via the table).
    chk("'* OK' greeting (no 'IMAP' word) on a non-tabled port -> imap (FN fix)",
        cls(12345, "* OK Dovecot ready.") == "imap");
    chk("'+OK' greeting on a non-tabled port -> pop3 (not imap)",
        cls(54322, "+OK POP3 ready") == "pop3");

    // ===== #3 app-server ports classify as http =========================
    chk("port 3000 (no banner) -> http", cls(3000, QByteArray()) == "http");
    chk("port 5000 (no banner) -> http", cls(5000, QByteArray()) == "http");
    chk("port 9090 (no banner) -> http", cls(9090, QByteArray()) == "http");

    // ===== TLS detected from RAW 0x16 0x03 record bytes =================
    chk("raw TLS record (0x16 0x03 ...) -> tls",
        cls(8443, QByteArray::fromHex("160301004a0100")) == "tls");

    // ===== regressions: known prefixes + port table still work ==========
    chk("SSH- prefix -> ssh", cls(22, "SSH-2.0-OpenSSH_8.9") == "ssh");
    chk("'220 ' + FTP -> ftp", cls(21, "220 ProFTPD Server ready") == "ftp");
    chk("'220-' multiline -> ftp", cls(21, "220-Welcome\r\n220 ready") == "ftp");
    chk("HTTP/ start -> http", cls(80, "HTTP/1.1 200 OK") == "http");
    chk("RFB -> vnc", cls(5900, "RFB 003.008") == "vnc");
    chk("MySQL handshake string -> mysql", cls(3306, "\x0a" "5.7.40-log\x00mysql_native") == "mysql");
    chk("empty banner + known port 22 -> ssh (port table)", cls(22, QByteArray()) == "ssh");
    chk("empty banner + unknown port -> empty label", cls(54321, QByteArray()).isEmpty());
    chk("non-empty unrecognized banner on unknown port -> unknown",
        cls(54321, "some random chatter") == "unknown");

    std::fprintf(stderr, "port_scanner_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

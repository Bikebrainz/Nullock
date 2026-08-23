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
// A second hardening pass anchors the DATABASE labels to the real wire
// handshake instead of a free substring: a MySQL protocol-10 greeting, a
// PostgreSQL 'E'/'R' message frame, or a Redis RESP reply now classify on ANY
// port, while a banner that merely *names* a DB is trusted only when it sits on
// the canonical DB port (3306/5432/6379). The cases below lock both directions
// (handshake -> labeled; product-name-in-prose -> NOT labeled).
//
// Run via:  ctest -R port_scanner -V

#include "port_scanner.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>
#include <initializer_list>

using namespace Nullock::Core;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString cls(quint16 port, const QByteArray &banner) { return classifyBanner(port, banner); }

// Banners with embedded NULs must be assembled byte-by-byte: the
// QByteArray(const char*) ctor truncates at the first NUL, which would hide the
// very handshake framing (NUL-terminated MySQL version, PG length fields) these
// cases exist to test. `bytes` builds an exact-length QByteArray from raw octets.
QByteArray bytes(std::initializer_list<int> vs) {
    QByteArray b;
    for (int v : vs) b.append(static_cast<char>(v));
    return b;
}

// MySQL/MariaDB protocol-10 greeting, raw form (starts at the protocol byte):
// 0x0a + NUL-terminated ASCII server version + binary tail.
QByteArray mysqlGreetRaw() {
    return bytes({0x0a}) + "8.0.32-log" + bytes({0x00}) + "thread-id+salt";
}
// MySQL greeting, full wire form: 3-byte LE length + seq id 0 + proto byte at +4.
QByteArray mysqlGreetWire() {
    return bytes({0x36, 0x00, 0x00, 0x00, 0x0a}) + "5.7.40" + bytes({0x00}) + "rest";
}
// PostgreSQL ErrorResponse 'E' : type byte + 4-byte BE length (26) + fields.
QByteArray pgErrorResponse() {
    return bytes({'E', 0x00, 0x00, 0x00, 0x1a})
         + "S" + "FATAL" + bytes({0x00})
         + "C" + "28000" + bytes({0x00})
         + bytes({0x00});
}
// PostgreSQL Authentication 'R' : type byte + 4-byte BE length (8) + auth tag.
QByteArray pgAuthRequest() {
    return bytes({'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05});
}
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
    // F2: a 220 greeting -- single-line OR multi-line "220-" continuation -- keys
    // on the PROTOCOL WORD, not the dash. "220-...ESMTP..." is SMTP, not FTP (old
    // code hard-coded 220- => ftp). Non-tabled ports so the classifier decides.
    chk("'220-' multiline ESMTP greeting -> smtp (F2: word, not dash)",
        cls(40019, "220-mail.example.com ESMTP Exim 4.94\r\n220-No auth\r\n") == "smtp");
    chk("'220-' multiline FTP greeting -> ftp (word, any port)",
        cls(40020, "220-ProFTPD Server ready\r\n220 features\r\n") == "ftp");
    chk("'220 ' single-line ESMTP on a non-tabled port -> smtp",
        cls(40021, "220 smtp.example.com ESMTP ready") == "smtp");
    chk("HTTP/ start -> http", cls(80, "HTTP/1.1 200 OK") == "http");
    chk("RFB -> vnc", cls(5900, "RFB 003.008") == "vnc");
    chk("MySQL handshake string -> mysql", cls(3306, "\x0a" "5.7.40-log\x00mysql_native") == "mysql");
    chk("empty banner + known port 22 -> ssh (port table)", cls(22, QByteArray()) == "ssh");
    chk("empty banner + unknown port -> empty label", cls(54321, QByteArray()).isEmpty());
    chk("non-empty unrecognized banner on unknown port -> unknown",
        cls(54321, "some random chatter") == "unknown");

    // ===== DB handshake FRAMING wins on ANY port (positive) =============
    // Non-tabled ports so these exercise the wire-handshake recognizers, NOT
    // the 3306/5432/6379 port fallback (a revert of the framing logic must FAIL
    // here, where the port table can't rescue it).
    chk("MySQL proto-10 greeting (0x0a + NUL-terminated version) -> mysql, any port",
        cls(40001, mysqlGreetRaw()) == "mysql");
    chk("MySQL full wire greeting (len+seq header, proto at +4) -> mysql, any port",
        cls(40002, mysqlGreetWire()) == "mysql");
    // The MySQL recognizer is FRAMING, not "first byte 0x0a": the version must
    // START WITH A DIGIT and be NUL-TERMINATED in range. Both soundness guards were
    // untested. A 0x0a-led banner whose version-like text starts with a LETTER is
    // NOT a handshake (else "\n"+"MariaDB-x"+NUL would mislabel as mysql and feed the
    // wrong protocol to service-vuln correlation).
    chk("0x0a + NON-digit version + NUL is NOT mysql (digit-first framing guard)",
        cls(40031, bytes({0x0a}) + "MariaDB-x" + bytes({0x00})) == "unknown");
    // A 0x0a + digit version with NO NUL terminator in range is NOT a handshake
    // (a real greeting terminates early); guards the no-terminator -> false branch.
    chk("0x0a + digit version with NO NUL terminator is NOT mysql",
        cls(40032, bytes({0x0a}) + QByteArray(70, '5')) == "unknown");
    chk("PostgreSQL ErrorResponse 'E' framing -> postgresql, any port",
        cls(40003, pgErrorResponse()) == "postgresql");
    chk("PostgreSQL Authentication 'R' framing -> postgresql, any port",
        cls(40004, pgAuthRequest()) == "postgresql");
    chk("Redis RESP '-NOAUTH' reply -> redis, any port",
        cls(40005, "-NOAUTH Authentication required.\r\n") == "redis");
    chk("Redis RESP '+PONG' reply -> redis, any port",
        cls(40006, "+PONG\r\n") == "redis");
    chk("Redis RESP '-DENIED' (protected mode) -> redis, any port",
        cls(40007, "-DENIED Redis is running in protected mode.\r\n") == "redis");
    chk("Redis RESP '-ERR' reply -> redis, any port",
        cls(40008, "-ERR unknown command 'GET'\r\n") == "redis");
    chk("Redis nil bulk-string '$-1' framing -> redis, any port",
        cls(40009, "$-1\r\n") == "redis");
    chk("Redis INFO 'redis_version:' marker -> redis, any port",
        cls(40010, "$120\r\n# Server\r\nredis_version:7.0.5\r\n") == "redis");

    // ===== product NAME in a non-handshake context is NOT mislabeled =====
    // (the core hardening: a banner that merely *mentions* a DB on a non-DB port
    // must not be labeled that DB.)
    chk("'MySQL' mentioned in plain text on a non-DB port -> NOT mysql (unknown)",
        cls(40011, "Welcome -- this host runs MySQL 8 behind the app") == "unknown");
    chk("'PostgreSQL' mentioned in plain text on a non-DB port -> NOT postgresql",
        cls(40012, "PostgreSQL is the world's most advanced open source DB") == "unknown");
    chk("'Redis' mentioned in plain text on a non-DB port -> NOT redis",
        cls(40013, "We use Redis for our session cache.") == "unknown");
    chk("a telnet greeting mentioning MySQL -> telnet (port), NOT mysql",
        cls(23, "MySQL maintenance box\r\nlogin: ") == "telnet");
    chk("'$' as a shell-prompt char (not RESP framing) on a non-DB port -> unknown",
        cls(40014, "$ welcome to the jump host") == "unknown");
    chk("text starting with 'E' but no PG length framing -> NOT postgresql",
        cls(40015, "ERROR: command not found") == "unknown");

    // ===== port-gated product NAME as a secondary signal ================
    // On the canonical DB port, a bare product mention (framing ambiguous) is
    // still trusted; on any other port the same text is not.
    chk("ambiguous 'MySQL' text ON port 3306 -> mysql (port-gated secondary)",
        cls(3306, "Access denied for user (using MySQL)") == "mysql");
    chk("same ambiguous 'MySQL' text on a non-3306 port -> NOT mysql",
        cls(40016, "Access denied for user (using MySQL)") == "unknown");
    chk("PG 'FATAL' text ON port 5432 -> postgresql (port-gated secondary)",
        cls(5432, "FATAL: password authentication failed for user") == "postgresql");
    chk("same 'FATAL' text on a non-5432 port -> NOT postgresql",
        cls(40017, "FATAL: password authentication failed for user") == "unknown");
    chk("ambiguous 'Redis' text ON port 6379 -> redis (port-gated secondary)",
        cls(6379, "this is a Redis-compatible service") == "redis");
    chk("same ambiguous 'Redis' text on a non-6379 port -> NOT redis",
        cls(40018, "this is a Redis-compatible service") == "unknown");
    // audit-12: the three POSITIVE cases above are NOT discriminating -- 3306/5432/6379
    // are all in the port table returning those same labels, so they pass with the
    // port-gated name checks deleted. What actually classifies a canonical DB port is
    // the PORT TABLE; pin that directly (with no product name in the banner at all) so
    // dropping a case is caught here instead of looking "covered" by the name check.
    chk("3306 classifies mysql with NO name mention (port table, not the name signal)",
        cls(3306, "Access denied for user") == "mysql");
    chk("5432 classifies postgresql with NO name/FATAL mention",
        cls(5432, "connection reset by peer") == "postgresql");
    chk("6379 classifies redis with NO name mention",
        cls(6379, "some opaque chatter") == "redis");

    // ===== leading-whitespace preamble must not defeat the wire prefixes =
    // audit-12: the scanner DISPLAYS the trimmed grab but classified the UNTRIMMED
    // one, so a service that leads with a blank line lost every startsWith() signal
    // and fell through to the port guess -- the analyst saw a banner that looks like
    // it should obviously have matched next to a wrong/unknown service label.
    chk("leading CRLF does not defeat 'SSH-' (off-table port -> was 'unknown')",
        cls(2222, "\r\nSSH-2.0-OpenSSH_9.7p1 Debian\r\n") == "ssh");
    chk("leading CRLF does not defeat the '220 ' FTP greeting",
        cls(40040, "\r\n220 ProFTPD Server ready") == "ftp");
    chk("leading CRLF does not defeat the '220-' SMTP continuation",
        cls(40041, "\r\n220-mail.example ESMTP Exim 4.94\r\n") == "smtp");
    chk("leading whitespace does not defeat '* OK' (imap)",
        cls(40042, " \t* OK Dovecot ready.") == "imap");
    chk("leading CRLF does not defeat '+OK' (pop3)",
        cls(40043, "\r\n+OK POP3 ready") == "pop3");
    chk("leading whitespace does not defeat 'RFB' (vnc)",
        cls(40044, "  RFB 003.008\n") == "vnc");
    // HTTP/2 deliberately: an "HTTP/1." status line is already caught by the
    // position-independent contains() below the prefix check, so a /1.1 banner would
    // pass here with or without the fix -- only a non-1.x version discriminates.
    chk("leading CRLF does not defeat the 'HTTP/' status line",
        cls(40045, "\r\nHTTP/2 200 OK\r\n") == "http");
    // ...but the trim is TEXT-only. A binary handshake whose FIRST byte is itself a
    // whitespace-valued framing byte (MySQL's 0x0a protocol version) must still be
    // judged on the RAW bytes -- trimming it would eat the framing and shift every
    // offset the length checks depend on. These two fail if the trim is applied
    // before the framing/TLS checks instead of only before the text prefixes.
    chk("binary MySQL greeting (0x0a lead) still judged RAW -> mysql",
        cls(40046, mysqlGreetRaw()) == "mysql");
    chk("0x0a lead + bare product name is still NOT mysql (raw framing, no name trust)",
        cls(40047, bytes({0x0a}) + "MariaDB-x" + bytes({0x00})) == "unknown");
    chk("TLS record (0x16 0x03) still judged RAW on an off-table port",
        cls(40048, QByteArray::fromHex("160301004a0100")) == "tls");

    // ===== newly added port-table services ==============================
    chk("port 5672 -> amqp",       cls(5672,  QByteArray()) == "amqp");
    chk("port 2181 -> zookeeper",  cls(2181,  QByteArray()) == "zookeeper");
    chk("port 2379 -> etcd",       cls(2379,  QByteArray()) == "etcd");
    chk("port 8500 -> consul",     cls(8500,  QByteArray()) == "consul");
    chk("port 9042 -> cassandra",  cls(9042,  QByteArray()) == "cassandra");
    chk("port 28015 -> rethinkdb", cls(28015, QByteArray()) == "rethinkdb");
    chk("port 50051 -> grpc",      cls(50051, QByteArray()) == "grpc");
    chk("port 1883 -> mqtt",       cls(1883,  QByteArray()) == "mqtt");
    chk("port 27017 -> mongodb (verify still present)",
        cls(27017, QByteArray()) == "mongodb");
    chk("port 9090 -> http (Prometheus over HTTP)",
        cls(9090, QByteArray()) == "http");

    // ---- portStatusForError: socket-error -> status verdict ------------
    // Was inline in probeOne() (the socket TU) and untested. The security-
    // relevant part is which errors set hostNotFound (-> the caller skips the
    // rest of the host's ports): a regression widening that to a transient
    // error silently misses a live host's remaining open ports (FN); mapping
    // HostNotFound to "filtered" instead brands a dead host "up but firewalled".
    {
        bool hnf = true;   // deliberately pre-set to prove the fn resets it
        chk("port: refused -> closed, not host-not-found",
            portStatusForError(QAbstractSocket::ConnectionRefusedError, &hnf) == "closed" && !hnf);
        hnf = false;
        chk("port: host-not-found -> unreachable + sets hostNotFound",
            portStatusForError(QAbstractSocket::HostNotFoundError, &hnf) == "unreachable" && hnf);
        hnf = false;
        chk("port: network error -> unreachable, NOT host-not-found",
            portStatusForError(QAbstractSocket::NetworkError, &hnf) == "unreachable" && !hnf);
        hnf = false;
        chk("port: address-unavailable -> unreachable, NOT host-not-found",
            portStatusForError(QAbstractSocket::SocketAddressNotAvailableError, &hnf) == "unreachable" && !hnf);
        hnf = false;
        chk("port: timeout -> filtered, NOT host-not-found",
            portStatusForError(QAbstractSocket::SocketTimeoutError, &hnf) == "filtered" && !hnf);
        hnf = false;
        chk("port: unknown error -> filtered",
            portStatusForError(QAbstractSocket::UnknownSocketError, &hnf) == "filtered" && !hnf);
        // Safety property: ONLY HostNotFoundError may skip the rest of the host.
        chk("port: a null hostNotFound ptr is tolerated",
            portStatusForError(QAbstractSocket::ConnectionRefusedError, nullptr) == "closed");
    }

    std::fprintf(stderr, "port_scanner_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

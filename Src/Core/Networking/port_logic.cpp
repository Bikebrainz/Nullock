// Pure banner/port -> service classification, split out of port_scanner.cpp so
// a unit test can link it against Qt6::Core alone. port_scanner.cpp is a QObject
// TU (PortScanner with worker threads + sockets); referencing that QObject from
// a test drags in Networking's shared moc compilation and the FrontEndGUI /
// ProxyModel link chain. classifyBanner is a free function with no Qt object
// deps, so the test links only this object. (Same free-function-split rationale
// as sequencer_logic.cpp.)

#include "port_scanner.hpp"

namespace Nullock::Core {

namespace {

// --- Database wire-handshake recognizers --------------------------------
// These look at the actual greeting/reply framing rather than a bare product
// name, so a telnet/text banner that merely *mentions* "MySQL"/"PostgreSQL"/
// "Redis" can't be mislabeled as that database. (The product-name substring is
// still trusted, but only when port-gated to the canonical DB port -- see
// classifyBanner.) All pure: they read the bytes, touch nothing else.

// A MySQL/MariaDB server-version string is printable ASCII: digits, letters,
// '.', '-', '_', '+', and the odd space ("5.7.40-log", "10.6.12-MariaDB").
inline bool isMysqlVersionChar(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           c == '.' || c == '-' || c == '_' || c == '+' || c == ' ';
}

// Validate the protocol-version byte + NUL-terminated version that sits at
// `protoOff`. The MySQL greeting (protocol 10 / handshake v10) is: protocol
// version byte (0x0a, rarely the legacy 0x09) then an ASCII server version
// that STARTS WITH A DIGIT and is NUL-terminated. Requiring the digit + the
// terminator is what makes this framing rather than "first byte is 0x0a".
bool mysqlVersionStringAt(const QByteArray &b, int protoOff) {
    const int n = static_cast<int>(b.size());
    if (n < protoOff + 3) return false;              // proto + >=1 char + NUL
    const unsigned char proto = static_cast<unsigned char>(b[protoOff]);
    if (proto != 0x0a && proto != 0x09) return false;
    int i = protoOff + 1;
    const unsigned char first = static_cast<unsigned char>(b[i]);
    if (first < '0' || first > '9') return false;    // version starts with a digit
    const int limit = qMin(n, i + 64);               // versions are short
    for (; i < limit; ++i) {
        const unsigned char c = static_cast<unsigned char>(b[i]);
        if (c == 0x00) return (i - protoOff) >= 2;   // hit the NUL terminator
        if (!isMysqlVersionChar(c)) return false;
    }
    return false;                                    // no terminator in range
}

bool looksLikeMysqlHandshake(const QByteArray &b) {
    // Raw form: the grab starts right at the protocol-version byte.
    if (mysqlVersionStringAt(b, 0)) return true;
    // Full wire form: 3-byte little-endian payload length + 1-byte sequence id
    // (0 for the first packet) then the protocol byte at offset 4.
    if (b.size() >= 6 && static_cast<unsigned char>(b[3]) == 0x00 &&
        mysqlVersionStringAt(b, 4)) {
        return true;
    }
    return false;
}

// PostgreSQL backend messages are <1-byte type><Int32 big-endian length>. On a
// banner grab the first thing an open backend sends is either an ErrorResponse
// ('E', e.g. a startup-protocol/SSL complaint) or an Authentication request
// ('R'). We anchor on the type byte AND a sane length field -- the length's top
// two bytes are ~0 for any real message, which ASCII text starting with 'E'/'R'
// (e.g. "ERROR", "Redis") can't satisfy.
bool looksLikePostgresFraming(const QByteArray &b) {
    if (b.size() < 5) return false;
    const char t = b[0];
    if (t != 'E' && t != 'R') return false;
    const quint32 len = (static_cast<quint32>(static_cast<quint8>(b[1])) << 24) |
                        (static_cast<quint32>(static_cast<quint8>(b[2])) << 16) |
                        (static_cast<quint32>(static_cast<quint8>(b[3])) <<  8) |
                         static_cast<quint32>(static_cast<quint8>(b[4]));
    return len >= 4 && len <= 0x10000;
}

// Redis answers any command (incl. our HTTP probe, which it parses as an inline
// command) with a typed RESP reply: a simple string "+PONG", an error
// "-ERR"/"-NOAUTH"/"-DENIED"/"-WRONGPASS", or a bulk string "$<len>". The INFO
// reply carries a "redis_version:" line. Any of these is real RESP framing, not
// a bare "Redis" mention.
bool looksLikeRedisReply(const QByteArray &b) {
    if (b.isEmpty()) return false;
    if (b.startsWith("+PONG"))        return true;
    if (b.startsWith("-ERR"))         return true;
    if (b.startsWith("-NOAUTH"))      return true;
    if (b.startsWith("-DENIED"))      return true;
    if (b.startsWith("-WRONGPASS"))   return true;
    if (b.contains("redis_version:")) return true;
    // Bulk-string framing "$<digits>\r\n" or the nil "$-1\r\n" -- require a
    // digit or '-' after '$' so a stray '$' (shell prompt, "$HOME") doesn't hit.
    if (b.size() >= 2 && b[0] == '$') {
        const char c = b[1];
        if ((c >= '0' && c <= '9') || c == '-') return true;
    }
    return false;
}

} // namespace

// Tiny banner classifier. Looks at the first bytes the service spits out
// (TCP-connect banner grab) and labels what we think it is. Operates on the RAW
// grabbed bytes -- a UTF-8 round-trip would corrupt a binary banner (a TLS
// record, a length byte >= 0x80, a NUL) before these checks run.
QString classifyBanner(quint16 port, const QByteArray &banner) {
    // The scanner DISPLAYS QString::fromUtf8(grab).trimmed() but classified the
    // UNTRIMMED grab, so a service that leads with a blank line or padding
    // ("\r\nSSH-2.0-OpenSSH_9.7p1") defeated every startsWith() signal below: the
    // port guess won and the analyst was shown a banner that looks like it should
    // obviously have matched. Test the TEXT prefixes against a leading-whitespace-
    // trimmed view so the classification agrees with what is displayed.
    //
    // The BINARY signals (TLS record, DB handshake framing) deliberately stay on the
    // RAW bytes: their first byte IS the framing, and 0x0a / 0x09 / 0x20 are
    // legitimate framing values (MySQL's protocol-version byte is 0x0a) that a trim
    // would eat, shifting every subsequent offset.
    qsizetype lead = 0;
    while (lead < banner.size()
           && (banner[lead] == ' '  || banner[lead] == '\t'
            || banner[lead] == '\r' || banner[lead] == '\n'))
        ++lead;
    const QByteArray b = lead ? banner.mid(lead) : banner;

    // Known wire prefixes first -- they're more reliable than port-only.
    if (b.startsWith("SSH-"))            return "ssh";
    // A 220 greeting -- single-line ("220 ") OR multi-line continuation ("220-").
    // Both forms are used by SMTP *and* FTP, so key on the protocol word, not the
    // dash: "220-mail.example ESMTP Exim" is SMTP, not FTP. Neither word -> fall
    // through to the port-based classification below.
    if (b.startsWith("220 ") || b.startsWith("220-")) {
        if (b.contains("SMTP")) return "smtp";
        if (b.contains("FTP"))  return "ftp";
    }
    if (b.startsWith("HTTP/"))           return "http";
    // An HTTP status line anywhere (a banner-grab GET answered after some preamble)
    // is HTTP -- catch it BEFORE the database checks below so an HTML body that
    // merely mentions "PostgreSQL"/"MySQL"/"Redis" isn't mislabeled as that database.
    if (b.contains("HTTP/1."))           return "http";
    // The untagged "* OK" greeting is IMAP-specific (POP3 uses "+OK"); don't
    // require the word IMAP -- many servers omit it from the first line.
    if (b.startsWith("* OK"))            return "imap";
    if (b.startsWith("+OK"))             return "pop3";
    if (b.startsWith("RFB"))             return "vnc";
    if (banner.length() >= 5 && (static_cast<unsigned char>(banner[0]) == 0x16)
        && (static_cast<unsigned char>(banner[1]) == 0x03))
        return "tls";
    // Databases, anchored to the real wire handshake. (We deliberately do NOT
    // map an OS mention like "Microsoft Windows" to a service -- an OS-version
    // line in a telnet/SMTP/FTP/RDP greeting is not evidence of winrm/smb, and
    // that mislabel fed the wrong protocol to service-vuln correlation. By the
    // same logic a banner that merely *names* a database is not that database:
    // we match the greeting framing, not the product string.)
    //
    // Primary signal -- handshake framing wins on ANY port:
    if (looksLikeMysqlHandshake(banner))      return "mysql";
    if (looksLikePostgresFraming(banner))     return "postgresql";
    if (looksLikeRedisReply(banner))          return "redis";
    // Secondary signal -- a bare product-name mention is only trusted when the
    // framing was ambiguous AND we're on the canonical DB port. This keeps the
    // old "name it" convenience for real DB ports without letting a product
    // mention on an unrelated port masquerade as the database.
    //
    // NOTE (audit-12): these three are SUBSUMED by the port table below -- 3306,
    // 5432 and 6379 all appear there returning the same labels, so a name mention
    // can never change the verdict. They are kept only as documentation of intent;
    // the real off-port coverage comes from the handshake-framing checks above,
    // and the port table is what actually classifies a canonical DB port. Do not
    // "restore" coverage by dropping the port gate: a product name on an unrelated
    // port is exactly the masquerade this ordering exists to refuse.
    if (port == 3306 && banner.contains("MySQL"))      return "mysql";
    if (port == 5432 &&
        (banner.contains("PostgreSQL") || banner.contains("FATAL")))
        return "postgresql";
    if (port == 6379 && banner.contains("Redis"))      return "redis";

    // Fallback to a port-based guess. Conservative -- only for the
    // common ones that don't auto-banner.
    switch (port) {
        case 21:   return "ftp";
        case 22:   return "ssh";
        case 23:   return "telnet";
        case 25:
        case 587:
        case 465:  return "smtp";
        case 53:   return "dns";
        case 80:
        case 3000:   // common dev/app servers (Node/Rails/Flask/Vite/...)
        case 5000:
        case 8080:
        case 8000:
        case 8081:
        case 9090:   // Prometheus exposes its UI/metrics over HTTP
        case 8888: return "http";
        case 110:  return "pop3";
        case 111:  return "rpcbind";
        case 135:  return "msrpc";
        case 139:
        case 445:  return "smb";
        case 143:  return "imap";
        case 161:  return "snmp";
        case 389:  return "ldap";
        case 443:
        case 8443: return "https";
        case 636:  return "ldaps";
        case 993:  return "imaps";
        case 995:  return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 1723: return "pptp";
        case 1883: return "mqtt";
        case 2049: return "nfs";
        case 2181: return "zookeeper";
        case 2375: return "docker";
        case 2376: return "docker-tls";
        case 2379: return "etcd";
        case 2380: return "etcd-peer";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5672: return "amqp";              // RabbitMQ / other AMQP 0-9-1 brokers
        case 5900: return "vnc";
        case 5984: return "couchdb";
        case 5985: return "winrm";
        case 6379: return "redis";
        case 6443: return "k8s-api";
        case 7474: return "neo4j";
        case 8086: return "influxdb";
        case 8500: return "consul";            // Consul HTTP API / UI
        case 9000: return "minio/php-fpm";
        case 9042: return "cassandra";         // CQL native transport
        case 9092: return "kafka";
        case 9200: return "elasticsearch";
        case 9300: return "elasticsearch-cluster";
        case 11211:return "memcached";
        case 15672:return "rabbitmq-mgmt";
        case 27017:return "mongodb";           // MongoDB wire protocol
        case 27018:return "mongodb-shard";
        case 27019:return "mongodb-config";
        case 28015:return "rethinkdb";         // RethinkDB client driver port
        case 50051:return "grpc";              // conventional gRPC (HTTP/2) port
    }
    return banner.isEmpty() ? QString() : QString("unknown");
}

} // namespace Nullock::Core

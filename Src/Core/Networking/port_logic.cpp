// Pure banner/port -> service classification, split out of port_scanner.cpp so
// a unit test can link it against Qt6::Core alone. port_scanner.cpp is a QObject
// TU (PortScanner with worker threads + sockets); referencing that QObject from
// a test drags in Networking's shared moc compilation and the FrontEndGUI /
// ProxyModel link chain. classifyBanner is a free function with no Qt object
// deps, so the test links only this object. (Same free-function-split rationale
// as sequencer_logic.cpp.)

#include "port_scanner.hpp"

namespace Nullock::Core {

// Tiny banner classifier. Looks at the first bytes the service spits out
// (TCP-connect banner grab) and labels what we think it is. Operates on the RAW
// grabbed bytes -- a UTF-8 round-trip would corrupt a binary banner (a TLS
// record, a length byte >= 0x80, a NUL) before these checks run.
QString classifyBanner(quint16 port, const QByteArray &banner) {
    // Known wire prefixes first -- they're more reliable than port-only.
    if (banner.startsWith("SSH-"))            return "ssh";
    if (banner.startsWith("220 ") && banner.contains("FTP"))    return "ftp";
    if (banner.startsWith("220 ") && banner.contains("SMTP"))   return "smtp";
    if (banner.startsWith("220-")) return "ftp";
    if (banner.startsWith("HTTP/"))           return "http";
    // An HTTP status line anywhere (a server that prepends a blank line, or a
    // banner-grab GET answered after some preamble) is HTTP -- catch it BEFORE
    // the database substring matches below so an HTML body that merely mentions
    // "PostgreSQL"/"MySQL"/"Redis" isn't mislabeled as that database.
    if (banner.contains("HTTP/1."))           return "http";
    // The untagged "* OK" greeting is IMAP-specific (POP3 uses "+OK"); don't
    // require the word IMAP -- many servers omit it from the first line.
    if (banner.startsWith("* OK"))            return "imap";
    if (banner.startsWith("+OK"))             return "pop3";
    if (banner.startsWith("RFB"))             return "vnc";
    if (banner.length() >= 5 && (static_cast<unsigned char>(banner[0]) == 0x16)
        && (static_cast<unsigned char>(banner[1]) == 0x03))
        return "tls";
    // Database product strings. (We deliberately do NOT map an OS mention like
    // "Microsoft Windows" to a service -- an OS-version line in a telnet/SMTP/
    // FTP/RDP greeting is not evidence of winrm/smb, and that mislabel fed the
    // wrong protocol to service-vuln correlation.)
    if (banner.contains("MySQL"))             return "mysql";
    if (banner.contains("PostgreSQL"))        return "postgresql";
    if (banner.contains("Redis"))             return "redis";

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
        case 9090:
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
        case 2049: return "nfs";
        case 2375: return "docker";
        case 2376: return "docker-tls";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 5984: return "couchdb";
        case 5985: return "winrm";
        case 6379: return "redis";
        case 6443: return "k8s-api";
        case 7474: return "neo4j";
        case 8086: return "influxdb";
        case 9000: return "minio/php-fpm";
        case 9092: return "kafka";
        case 9200: return "elasticsearch";
        case 9300: return "elasticsearch-cluster";
        case 11211:return "memcached";
        case 15672:return "rabbitmq-mgmt";
        case 27017:return "mongodb";
    }
    return banner.isEmpty() ? QString() : QString("unknown");
}

} // namespace Nullock::Core

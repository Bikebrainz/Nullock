#pragma once

#include <QByteArray>
#include <QString>

// Pure DNS-query wire parsing for the OAST DnsSink, split out of dns_sink.cpp so
// a unit test can link it against Qt6::Core alone and exercise it with hostile
// datagrams. The input bytes are ATTACKER-CONTROLLED (an inbound UDP DNS query),
// so this parser must be memory-safe on arbitrary input.
//
// It also UNIFIES what used to be two separate, subtly-divergent QNAME walkers
// (one in buildResponse to find the question end, one inline in onDatagram to
// build the name string) into a single parse, and bounds the assembled name at
// kMaxDnsNameChars (real DNS caps a name at 255 octets; the previous code capped
// only at the ~64KB datagram size, so a token-bearing query could carry a 64KB
// name into the hit log).
namespace Nullock::Core::DnsLogic {

// RFC 1035 caps a domain name at 255 octets. We bound the assembled string to
// the same, so a hostile query can't push a 64KB "name" into OastHit.hostHeader.
inline constexpr int kMaxDnsNameChars = 255;

struct ParsedQuery {
    // true iff the datagram is a well-formed standard single-question QUERY:
    // size>=12, QR=0 (a query, not a response), Opcode=0, QDCOUNT==1, and the
    // QNAME is uncompressed and terminated by a root (0) label fully within the
    // datagram with QTYPE+QCLASS (4 bytes) following in-bounds. Only then is a
    // response safe to frame AND a callback safe to confirm.
    bool    valid       = false;
    // The queried name, labels joined by '.', best-effort and length-capped.
    // Each label octet is sanitized to LDH+'_' (non-hostname bytes -> '?') so
    // attacker-controlled control/markup bytes can't ride into the hit log /
    // report. Populated with whatever labels were walked even when !valid,
    // EXCEPT empty when the very first label is compressed/overruns.
    QString qname;
    // Offset just past QTYPE+QCLASS; meaningful only when valid. Equals the
    // length of the original question section measured from offset 12 + 12.
    int     questionEnd = 0;
    quint16 qdcount     = 0;
};

// Parse the question section of a DNS query datagram. Memory-safe on any bytes:
// rejects compression pointers (top 2 bits of a label length set), labels whose
// body runs past the datagram, unterminated names, and a missing QTYPE/QCLASS.
ParsedQuery parseDnsQuery(const QByteArray &dgram);

// First label of a dotted name, lowercased, iff it is EXACTLY 16 hex chars --
// the OAST token shape. Empty otherwise.
QString extractToken(const QString &qname);

} // namespace Nullock::Core::DnsLogic

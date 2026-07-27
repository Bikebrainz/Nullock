#include "dns_logic.hpp"

#include <QRegularExpression>

#include <algorithm>   // std::min

namespace Nullock::Core::DnsLogic {

namespace {
// Map a raw DNS label octet to a safe character for the logged name. A label may
// legally carry ANY octet (control chars, backtick, newline, high bytes), and the
// assembled name fans out to OastHit.hostHeader -> finding evidence -> the
// Markdown report export, which is NOT HTML/JSON-escaped. Constrain to LDH (the
// real hostname charset) + underscore so an attacker can't inject backticks /
// newlines / markup at the source. A real OAST callback name is pure LDH, so this
// is loss-free for legitimate traffic.
QChar safeLabelChar(char c) {
    const unsigned char b = static_cast<unsigned char>(c);
    const bool ldh = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                  || (b >= '0' && b <= '9') || b == '-' || b == '_';
    return ldh ? QLatin1Char(char(b)) : QLatin1Char('?');
}
} // namespace

ParsedQuery parseDnsQuery(const QByteArray &d) {
    ParsedQuery r;
    if (d.size() < 12) return r;

    // Byte 2 is the high flags octet: QR (bit 7) then the 4-bit Opcode (bits
    // 6..3). Only a standard QUERY is a real callback. Reject a RESPONSE (QR=1)
    // -- answering one creates a self-sustaining ping-pong with another
    // always-answering UDP service -- and reject non-standard opcodes.
    const quint8 flags = quint8(d[2]);
    if ((flags & 0x80) != 0)        return r;   // QR=1: a response, not a query
    if (((flags >> 3) & 0x0F) != 0) return r;   // Opcode != standard query (0)

    // QDCOUNT is the 16-bit big-endian count at offset 4. This is a
    // single-question responder, so require exactly one question (a real
    // resolver callback always sends exactly one).
    r.qdcount = quint16((quint8(d[4]) << 8) | quint8(d[5]));
    if (r.qdcount != 1) return r;

    // Walk the QNAME labels from offset 12. Every datagram index read below is
    // proven < size() by the while-condition or an explicit guard before it.
    int  pos        = 12;
    bool terminated = false;
    while (pos < d.size()) {
        const quint8 len = quint8(d[pos]);          // pos < size: in bounds
        if (len == 0) { ++pos; terminated = true; break; }   // root label ends the name
        if ((len & 0xC0) != 0) return r;            // compression pointer: reject outright
        if (pos + 1 + len > d.size()) return r;     // label body would run past the datagram

        if (r.qname.size() < kMaxDnsNameChars) {    // append, bounded by the 255-char cap
            if (!r.qname.isEmpty()) r.qname += QLatin1Char('.');
            const int room = kMaxDnsNameChars - r.qname.size();
            const int take = std::min(int(len), room);
            for (int i = 0; i < take; ++i)          // sanitize each label octet
                r.qname += safeLabelChar(d[pos + 1 + i]);
        }
        pos += 1 + len;
    }
    if (!terminated) return r;                      // unterminated name: not a valid question

    const int questionEnd = pos + 4;                // + QTYPE(2) + QCLASS(2)
    if (questionEnd > d.size()) return r;           // truncated question: not answerable

    r.questionEnd = questionEnd;
    r.valid       = true;
    return r;
}

QString extractToken(const QString &qname) {
    const int dot = qname.indexOf('.');
    const QString head = (dot > 0 ? qname.left(dot) : qname).toLower();
    // \A..\z (absolute anchors), NOT ^..$: PCRE2 $ (no DollarEndOnly) also matches
    // immediately before a trailing newline, so "0123456789abcdef\n" would match and
    // this would return a 17-char token WITH an embedded LF -- a malformed OAST
    // correlation token (and a CR/LF sink downstream).
    static const QRegularExpression hex16(QStringLiteral("\\A[0-9a-f]{16}\\z"));
    return hex16.match(head).hasMatch() ? head : QString();
}

} // namespace Nullock::Core::DnsLogic

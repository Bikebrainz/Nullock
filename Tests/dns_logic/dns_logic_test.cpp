// Regression corpus for the OAST DNS-query wire parser.
//
// DnsSink parses ATTACKER-CONTROLLED inbound UDP DNS datagrams to pull a 16-hex
// OAST token from the leftmost label and to frame a response. This locks the
// parser's memory-safety + correctness on hostile input:
//   * no out-of-bounds on truncated / overrunning / unterminated packets,
//   * compression pointers rejected (no pointer-loop attack surface),
//   * the assembled name bounded at kMaxDnsNameChars (was only datagram-bounded),
//   * the single unified parser feeds BOTH the answer path and the token path,
//   * extractToken matches exactly the 16-hex shape.
//
// Run via:  ctest -R dns_logic -V

#include "dns_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QList>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::DnsLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Build a DNS query datagram: 12-byte header + labels + optional root + optional
// QTYPE/QCLASS. Each label byte uses size & 0xFF so a caller can craft an
// over-long-length-byte by passing a short body with a forced length (see raw()).
QByteArray dnsQuery(const QList<QByteArray> &labels, bool terminate = true,
                    bool withQtypeClass = true, quint16 qdcount = 1) {
    QByteArray q;
    q.append(char(0x12)).append(char(0x34));                           // ID
    q.append(char(0x01)).append(char(0x00));                           // flags (RD)
    q.append(char((qdcount >> 8) & 0xFF)).append(char(qdcount & 0xFF));// QDCOUNT
    q.append(char(0)).append(char(0));                                 // ANCOUNT
    q.append(char(0)).append(char(0));                                 // NSCOUNT
    q.append(char(0)).append(char(0));                                 // ARCOUNT
    for (const QByteArray &l : labels) {
        q.append(char(l.size() & 0xFF));
        q.append(l);
    }
    if (terminate)     q.append(char(0));                              // root label
    if (withQtypeClass) q.append(char(0)).append(char(1)).append(char(0)).append(char(1)); // A IN
    return q;
}
const QByteArray kTok = "0123456789abcdef";   // a valid 16-hex token
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== the happy path: a real OAST callback =========================
    {
        const QByteArray q = dnsQuery({ kTok, "oast", "example", "com" });
        const ParsedQuery p = parseDnsQuery(q);
        chk("valid: well-formed query parses", p.valid);
        chk("valid: qname joined with dots", p.qname == "0123456789abcdef.oast.example.com");
        chk("valid: token extracted from first label", extractToken(p.qname) == kTok);
        // questionEnd = 12 + (17+5+8+4 label bytes) + 1 root + 4 qtype/class
        chk("valid: questionEnd past QTYPE/QCLASS", p.questionEnd == q.size());
        chk("valid: qdcount read", p.qdcount == 1);
    }
    {
        // root-only name (".") with QTYPE/QCLASS -> valid, empty qname
        const QByteArray q = dnsQuery({});
        const ParsedQuery p = parseDnsQuery(q);
        chk("valid: root-only query is valid", p.valid && p.qname.isEmpty());
        chk("valid: root-only questionEnd = 12+1+4", p.questionEnd == 17);
    }

    // ===== truncation / size guards (memory safety) =====================
    chk("trunc: empty datagram -> invalid", !parseDnsQuery(QByteArray()).valid);
    chk("trunc: 1 byte -> invalid", !parseDnsQuery(QByteArray(1, '\0')).valid);
    chk("trunc: 11 bytes -> invalid", !parseDnsQuery(QByteArray(11, '\0')).valid);
    {
        // exactly 12 bytes (header only, qdcount=1, no question) -> invalid
        QByteArray q(12, '\0'); q[5] = 1;   // qdcount=1
        const ParsedQuery p = parseDnsQuery(q);
        chk("trunc: header-only (no question) -> invalid", !p.valid);
    }
    chk("trunc: qdcount==0 -> invalid", !parseDnsQuery(dnsQuery({ kTok }, true, true, 0)).valid);

    // ===== unterminated name ============================================
    {
        // labels but no root label and no qtype/class -> runs to end, not terminated
        const QByteArray q = dnsQuery({ kTok, "x" }, /*terminate=*/false, /*withQtypeClass=*/false);
        const ParsedQuery p = parseDnsQuery(q);
        chk("unterminated: not valid", !p.valid);
        chk("unterminated: qname still recovered (token survives for logging)",
            p.qname == "0123456789abcdef.x" && extractToken(p.qname) == kTok);
    }

    // ===== missing QTYPE/QCLASS =========================================
    {
        // name terminated but no 4 trailing bytes
        const QByteArray q = dnsQuery({ kTok }, /*terminate=*/true, /*withQtypeClass=*/false);
        const ParsedQuery p = parseDnsQuery(q);
        chk("no-qtype: terminated but truncated question -> invalid", !p.valid);
        chk("no-qtype: qname still recovered", p.qname == "0123456789abcdef");
    }

    // ===== label length runs past the datagram ==========================
    {
        // header + a length byte 0x40 (64) but only a few bytes of body
        QByteArray q(12, '\0'); q[5] = 1;     // qdcount=1
        q.append(char(0x40));                  // claims a 64-byte label
        q.append("short");                     // only 5 bytes follow
        const ParsedQuery p = parseDnsQuery(q);
        chk("overrun: over-long first label -> invalid, no OOB", !p.valid);
        chk("overrun: first-label overrun yields empty qname", p.qname.isEmpty());
    }

    // ===== compression pointers rejected ================================
    {
        // first label is a compression pointer (top 2 bits set)
        QByteArray q(12, '\0'); q[5] = 1;
        q.append(char(0xC0)).append(char(0x0C));   // pointer to offset 12
        const ParsedQuery p = parseDnsQuery(q);
        chk("compress: pointer first label -> invalid", !p.valid);
        chk("compress: pointer first label -> empty qname (nothing safely read)", p.qname.isEmpty());
    }
    {
        // a valid label THEN a compression pointer
        QByteArray q(12, '\0'); q[5] = 1;
        q.append(char(3)).append("abc");
        q.append(char(0xC0)).append(char(0x0C));
        const ParsedQuery p = parseDnsQuery(q);
        chk("compress: pointer after a label -> invalid", !p.valid);
        chk("compress: earlier label retained in qname", p.qname == "abc");
    }

    // ===== total-name-length cap (was only datagram-bounded) ============
    {
        QList<QByteArray> many;
        for (int i = 0; i < 20; ++i) many.append(QByteArray(50, 'a'));  // 20*50 = 1000 chars
        const QByteArray q = dnsQuery(many);
        const ParsedQuery p = parseDnsQuery(q);
        chk("cap: a huge name is bounded to kMaxDnsNameChars", p.qname.size() <= kMaxDnsNameChars);
        chk("cap: still parses as a valid question (just capped name)", p.valid);
        chk("cap: bound is the RFC 1035 255-octet limit", kMaxDnsNameChars == 255);
    }

    // ===== QR / opcode / qdcount strictness =============================
    {
        // a DNS RESPONSE (QR=1) that still carries a parseable question -> reject
        // (closes the answer-a-response ping-pong loop).
        QByteArray q = dnsQuery({ kTok });
        q[2] = char(quint8(q[2]) | 0x80);   // set QR bit
        chk("qr: a response (QR=1) is rejected", !parseDnsQuery(q).valid);
    }
    {
        // non-standard opcode (e.g. 1 = IQUERY) -> reject
        QByteArray q = dnsQuery({ kTok });
        q[2] = char((quint8(q[2]) & 0x87) | (1 << 3));   // opcode = 1
        chk("opcode: non-standard opcode rejected", !parseDnsQuery(q).valid);
    }
    {
        // qdcount must be EXACTLY 1 (single-question OAST responder)
        chk("qdcount: 2 rejected", !parseDnsQuery(dnsQuery({ kTok }, true, true, 2)).valid);
        chk("qdcount: 1 accepted", parseDnsQuery(dnsQuery({ kTok }, true, true, 1)).valid);
    }

    // ===== label sanitization (report-injection defence) ================
    {
        // a label carrying a backtick + newline + a high byte -> all neutralized
        QByteArray evil; evil.append('a').append(char(0x60)).append('b').append(char(0x0A))
                             .append('c').append(char(0x80)).append('d');
        const QByteArray q = dnsQuery({ kTok, evil });
        const ParsedQuery p = parseDnsQuery(q);
        chk("sanitize: still a valid query", p.valid);
        chk("sanitize: non-LDH bytes replaced with '?'", p.qname == "0123456789abcdef.a?b?c?d");
        chk("sanitize: no backtick survives", !p.qname.contains('`'));
        chk("sanitize: no newline survives", !p.qname.contains('\n'));
        chk("sanitize: token still extracted from clean first label", extractToken(p.qname) == kTok);
    }
    {
        // LDH + underscore are preserved (real DNS names, incl _dmarc-style)
        const QByteArray q = dnsQuery({ kTok, "_dmarc", "Example-1" });
        chk("sanitize: LDH + underscore preserved",
            parseDnsQuery(q).qname == "0123456789abcdef._dmarc.Example-1");
    }

    // ===== extractToken shape ===========================================
    chk("token: exact 16-hex accepted", extractToken("0123456789abcdef.x") == "0123456789abcdef");
    chk("token: uppercase hex lowercased + matched", extractToken("0123456789ABCDEF.x") == "0123456789abcdef");
    chk("token: 15 hex rejected", extractToken("0123456789abcde.x").isEmpty());
    chk("token: 17 hex rejected", extractToken("0123456789abcdef0.x").isEmpty());
    chk("token: non-hex char rejected", extractToken("0123456789abcdeg.x").isEmpty());
    chk("token: bare 16-hex (no dot) accepted", extractToken("0123456789abcdef") == "0123456789abcdef");
    chk("token: empty -> empty", extractToken(QString()).isEmpty());
    chk("token: leading-dot (empty first label) rejected", extractToken(".0123456789abcdef").isEmpty());

    // ===== memory-safety fuzz: never crash on arbitrary short packets ===
    {
        bool qnameCapped = true, endInBounds = true;
        for (int n = 0; n <= 40; ++n) {
            QByteArray q(n, '\0');
            for (int i = 0; i < n; ++i) q[i] = char((i * 37 + 0xC0) & 0xFF);  // hostile-ish bytes
            const auto p = parseDnsQuery(q);     // must not crash / OOB
            // Non-vacuous invariants on the result of parsing arbitrary bytes:
            if (p.qname.size() > kMaxDnsNameChars) qnameCapped = false;
            if (p.valid && p.questionEnd > q.size()) endInBounds = false;
        }
        chk("fuzz: qname stays <= kMaxDnsNameChars on every hostile packet", qnameCapped);
        chk("fuzz: a valid parse never claims to consume past the datagram", endInBounds);
    }

    std::fprintf(stderr, "dns_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

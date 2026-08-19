// Regression corpus for the MITM CA's host-injection guard (no I/O). The `host`
// is attacker-influenceable (the intercepted CONNECT target / TLS SNI) and flows
// into the openssl `-subj /CN=<host>` arg and the SAN extension file, so this
// guard is the CA's only defence. An adversarial review found it SOUND; these
// assertions LOCK it so a future relaxation can't silently reopen:
//   - ext-file injection ("evil\nbasicConstraints = critical, CA:TRUE"),
//   - subject-DN grafting ("evil/CN=bank.com" / "a=b"),
//   - leaf-file path traversal ("../../x", a backslash, a drive letter),
//   - argument injection (a leading '-'),
//   - and the UTF-8-byte length bound (not UTF-16 code units).
// Also asserts the sanitize() == identity invariant on every valid host (so two
// distinct valid hosts never collide to one cached leaf-cert path).
//
// Run via:  ctest -R cert_logic -V

#include "cert_logic.hpp"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Proxy::CertLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== isValidHostForCert: accept real hostnames ====================
    chk("valid: a plain hostname", isValidHostForCert("example.com"));
    chk("valid: a subdomain", isValidHostForCert("api.v2.example.co.uk"));
    chk("valid: hyphens and digits", isValidHostForCert("my-host-01.example.com"));
    chk("valid: an underscore (not leading)", isValidHostForCert("a_b.example.com"));
    chk("valid: a single label", isValidHostForCert("localhost"));

    // ===== isValidHostForCert: reject the injection vectors =============
    chk("inject: a newline (SAN ext-file line injection) is rejected",
        !isValidHostForCert("evil\nbasicConstraints = critical, CA:TRUE"));
    chk("inject: a bare CR is rejected", !isValidHostForCert("evil\rX"));
    chk("inject: a '/' (subject-DN grafting) is rejected", !isValidHostForCert("evil/CN=bank.com"));
    chk("inject: an '=' is rejected", !isValidHostForCert("a=b"));
    chk("inject: a space is rejected", !isValidHostForCert("a b.com"));
    chk("inject: a NUL is rejected", !isValidHostForCert(QString("a") + QChar(0) + QString("b")));
    chk("inject: a semicolon is rejected", !isValidHostForCert("a;b"));

    // ===== isValidHostForCert: path-traversal vectors ===================
    chk("path: '..' is rejected", !isValidHostForCert("../../etc/passwd"));
    chk("path: a forward slash is rejected", !isValidHostForCert("a/b"));
    chk("path: a backslash is rejected", !isValidHostForCert("a\\b"));
    chk("path: a drive-letter colon is rejected", !isValidHostForCert("C:host"));

    // ===== isValidHostForCert: argument-injection / structural =========
    chk("arg: a leading '-' (openssl flag) is rejected", !isValidHostForCert("-subj"));
    chk("arg: a leading '_' is rejected", !isValidHostForCert("_x"));
    chk("dot: a leading dot is rejected", !isValidHostForCert(".example.com"));
    chk("dot: a trailing dot is rejected", !isValidHostForCert("example.com."));
    chk("dot: a double dot is rejected", !isValidHostForCert("a..b.com"));
    chk("empty: an empty host is rejected", !isValidHostForCert(""));

    // ===== isValidHostForCert: UTF-8 BYTE length bound (the fix) ========
    {
        const QString ascii253(253, QChar('a'));
        chk("len: 253 ASCII bytes is accepted", isValidHostForCert(ascii253));
        chk("len: 254 ASCII bytes is rejected", !isValidHostForCert(QString(254, QChar('a'))));
        // A 200-char host of 3-byte letters (e.g. U+4E2D) = 600 UTF-8 bytes: rejected
        // by the BYTE bound even though the UTF-16 size (200) is under 253.
        QString cjk;
        for (int i = 0; i < 200; ++i) cjk += QChar(0x4E2D);
        chk("len: a host whose UTF-8 length exceeds 253 is rejected (byte bound, not code-unit)",
            !isValidHostForCert(cjk));
    }

    // ===== sanitize: identity on valid hosts (cache-collision invariant) =
    {
        const char *valids[] = { "example.com", "a-b_c.d.example.co.uk", "host01", "x_y-z.test" };
        bool allIdentity = true;
        for (const char *h : valids) {
            const QString host = QString::fromLatin1(h);
            if (isValidHostForCert(host) && sanitize(host) != host) allIdentity = false;
        }
        chk("sanitize: is IDENTITY on every valid host (no two valid hosts share a leaf path)",
            allIdentity);
    }
    chk("sanitize: maps a '/' to '_' (path-safe)", sanitize("a/b") == "a_b");
    chk("sanitize: maps a backslash and space to '_'", sanitize("a\\ b") == "a__b");
    chk("sanitize: keeps the allowed punctuation", sanitize("a-b_c.d") == "a-b_c.d");

    // ===== isIpv4Literal: exactly four ASCII 0..255 octets =====
    chk("ipv4: 127.0.0.1",           isIpv4Literal("127.0.0.1"));
    chk("ipv4: 192.168.1.254",       isIpv4Literal("192.168.1.254"));
    chk("ipv4: 0.0.0.0 and 255.255.255.255",
        isIpv4Literal("0.0.0.0") && isIpv4Literal("255.255.255.255"));
    chk("ipv4: octet > 255 rejected (1.2.3.256)", !isIpv4Literal("1.2.3.256"));
    chk("ipv4: only 3 octets rejected (1.2.3)",   !isIpv4Literal("1.2.3"));
    chk("ipv4: 5 octets rejected (1.2.3.4.5)",    !isIpv4Literal("1.2.3.4.5"));
    chk("ipv4: non-digit rejected (a.b.c.d)",     !isIpv4Literal("a.b.c.d"));
    chk("ipv4: empty octet rejected (1..2.3)",    !isIpv4Literal("1..2.3"));
    chk("ipv4: a DNS name is not an IPv4 literal", !isIpv4Literal("example.com"));
    chk("ipv4: 4-digit octet rejected (1.2.3.4444)", !isIpv4Literal("1.2.3.4444"));

    // ===== sanEntryForHost: IP: for an IPv4 literal, DNS: otherwise =====
    chk("SAN: IPv4 literal -> IP: entry",  sanEntryForHost("10.0.0.5") == "IP:10.0.0.5");
    chk("SAN: DNS name -> DNS: entry",     sanEntryForHost("api.example.com") == "DNS:api.example.com");
    chk("SAN: over-range dotted-quad is treated as DNS (not IP)",
        sanEntryForHost("1.2.3.999") == "DNS:1.2.3.999");

    std::fprintf(stderr, "cert_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

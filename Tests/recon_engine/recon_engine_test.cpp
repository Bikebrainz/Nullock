// Regression corpus for recon_engine's pure helpers (no DNS): crt.sh name
// canonicalization + acceptance, the search-domain answer filter, and the
// wildcard-DNS suppression decision. These lock the soundness fixes from the
// adversarial audit:
//   - cleanName strips ALL leading "*." (was one), so "*.*.x" doesn't leave a
//     residual wildcard;
//   - acceptCertName drops the apex-collapse and residual-wildcard cert names;
//   - recordMatchesQuery rejects search-domain suffix expansion;
//   - isWildcardResolved suppresses the wildcard-DNS false positive (a candidate
//     resolving ONLY to the wildcard IPs is not a distinct host).
//
// Run via:  ctest -R recon_engine -V

#include "recon_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::ReconLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QStringList L(std::initializer_list<const char *> xs) {
    QStringList l; for (auto x : xs) l << QString::fromLatin1(x); return l;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== cleanName ====================================================
    chk("cleanName: trims + lowercases", cleanName("  API.Example.COM  ") == "api.example.com");
    chk("cleanName: strips a single leading '*.'", cleanName("*.example.com") == "example.com");
    chk("cleanName: strips ALL leading '*.' (was a single-strip bug)",
        cleanName("*.*.example.com") == "example.com");
    chk("cleanName: a non-wildcard name is unchanged", cleanName("mail.example.com") == "mail.example.com");
    chk("cleanName: an embedded '*' is NOT stripped (left for acceptCertName to drop)",
        cleanName("d*.example.com") == "d*.example.com");

    // ===== acceptCertName ===============================================
    chk("acceptCertName: a real subdomain is accepted", acceptCertName("mail.example.com", "example.com"));
    chk("acceptCertName: a deep subdomain is accepted", acceptCertName("a.b.example.com", "example.com"));
    chk("acceptCertName: the apex itself is NOT a subdomain (wildcard collapse)",
        !acceptCertName("example.com", "example.com"));
    chk("acceptCertName: a residual wildcard is rejected", !acceptCertName("*.example.com", "example.com"));
    chk("acceptCertName: a partial wildcard 'd*.example.com' is rejected",
        !acceptCertName("d*.example.com", "example.com"));
    chk("acceptCertName: an out-of-scope name is rejected", !acceptCertName("mail.evil.com", "example.com"));
    chk("acceptCertName: a suffix-confusion name is rejected",
        !acceptCertName("notexample.com", "example.com"));
    chk("acceptCertName: empty inputs rejected",
        !acceptCertName("", "example.com") && !acceptCertName("mail.example.com", ""));
    // audit-8: a mixed-case target domain must still accept its subdomains
    // (case-insensitive), else crt.sh discovery silently returns zero.
    chk("acceptCertName: a mixed-case target accepts subdomains",
        acceptCertName("mail.example.com", "Example.com"));
    chk("acceptCertName: mixed-case apex still rejected",
        !acceptCertName("example.com", "Example.com"));

    // ===== recordMatchesQuery (search-domain expansion guard) ===========
    chk("recordMatchesQuery: exact match", recordMatchesQuery("ftp.example.com", "ftp.example.com"));
    chk("recordMatchesQuery: case-insensitive", recordMatchesQuery("FTP.Example.COM", "ftp.example.com"));
    chk("recordMatchesQuery: a CNAME-chain deeper name is accepted",
        recordMatchesQuery("real.ftp.example.com", "ftp.example.com"));
    chk("recordMatchesQuery: a search-domain-expanded name is rejected",
        !recordMatchesQuery("ftp.example.com.corp.local", "ftp.example.com"));
    chk("recordMatchesQuery: an unrelated host is rejected",
        !recordMatchesQuery("other.example.com", "ftp.example.com"));
    chk("recordMatchesQuery: a trailing-dot (rooted) FQDN of the asked name matches",
        recordMatchesQuery("ftp.example.com.", "ftp.example.com"));

    // ===== isWildcardResolved (the wildcard-DNS FP suppression) =========
    chk("wildcard: candidate resolving ONLY to the wildcard IP is a wildcard hit",
        isWildcardResolved(L({"1.2.3.4"}), L({"1.2.3.4"})));
    chk("wildcard: candidate with a DISTINCT IP is a real host (kept)",
        !isWildcardResolved(L({"9.9.9.9"}), L({"1.2.3.4"})));
    chk("wildcard: candidate whose IPs are a SUBSET of the wildcard set is a wildcard hit",
        isWildcardResolved(L({"1.2.3.4"}), L({"1.2.3.4", "5.6.7.8"})));
    chk("wildcard: candidate with one wildcard + one distinct IP is a real host",
        !isWildcardResolved(L({"1.2.3.4", "9.9.9.9"}), L({"1.2.3.4"})));
    chk("wildcard: NO wildcard set (empty) -> never suppress (no filtering)",
        !isWildcardResolved(L({"1.2.3.4"}), QStringList()));
    chk("wildcard: a non-resolving candidate (empty IPs) is not a wildcard hit",
        !isWildcardResolved(QStringList(), L({"1.2.3.4"})));

    // ===== mergeIps (A + AAAA union; crt.sh lead later resolved) =========
    chk("mergeIps: union of disjoint A and AAAA addresses",
        mergeIps(L({"1.2.3.4"}), L({"2606:4700::1111"})) == L({"1.2.3.4", "2606:4700::1111"}));
    chk("mergeIps: existing order preserved, new appended",
        mergeIps(L({"1.1.1.1", "2.2.2.2"}), L({"3.3.3.3"})) == L({"1.1.1.1", "2.2.2.2", "3.3.3.3"}));
    chk("mergeIps: duplicates are dropped (idempotent re-resolve)",
        mergeIps(L({"1.2.3.4"}), L({"1.2.3.4"})) == L({"1.2.3.4"}));
    chk("mergeIps: a crt.sh lead (empty) gains the resolved IPs",
        mergeIps(QStringList(), L({"1.2.3.4", "2606:4700::1111"})) == L({"1.2.3.4", "2606:4700::1111"}));
    chk("mergeIps: nothing incoming leaves existing unchanged",
        mergeIps(L({"1.2.3.4"}), QStringList()) == L({"1.2.3.4"}));
    chk("mergeIps: empty incoming entries are skipped",
        mergeIps(L({"1.2.3.4"}), L({""})) == L({"1.2.3.4"}));
    chk("mergeIps: partial overlap unions only the new address",
        mergeIps(L({"1.2.3.4", "5.6.7.8"}), L({"5.6.7.8", "9.9.9.9"}))
            == L({"1.2.3.4", "5.6.7.8", "9.9.9.9"}));

    // ===== ipToReverseDnsName (reverse-DNS / PTR .arpa name) ============
    chk("rev: IPv4 1.2.3.4",   ipToReverseDnsName("1.2.3.4")      == "4.3.2.1.in-addr.arpa");
    chk("rev: IPv4 8.8.8.8",   ipToReverseDnsName("8.8.8.8")      == "8.8.8.8.in-addr.arpa");
    chk("rev: IPv4 mixed",     ipToReverseDnsName("192.168.1.10") == "10.1.168.192.in-addr.arpa");
    chk("rev: IPv4 leading zeros normalized",
        ipToReverseDnsName("01.002.3.4") == "4.3.2.1.in-addr.arpa");
    chk("rev: IPv4 trims whitespace",
        ipToReverseDnsName("  10.0.0.1  ") == "1.0.0.10.in-addr.arpa");
    chk("rev: too few octets -> empty",    ipToReverseDnsName("1.2.3").isEmpty());
    chk("rev: too many octets -> empty",   ipToReverseDnsName("1.2.3.4.5").isEmpty());
    chk("rev: octet > 255 -> empty",       ipToReverseDnsName("1.2.3.256").isEmpty());
    chk("rev: non-numeric octet -> empty", ipToReverseDnsName("1.2.3.x").isEmpty());
    chk("rev: empty -> empty",             ipToReverseDnsName("").isEmpty());
    // IPv6: 32 reversed nibbles + "ip6.arpa" == 72 chars
    {
        const QString r1 = ipToReverseDnsName("::1");
        chk("rev: IPv6 ::1 length 72",      r1.size() == 72);
        chk("rev: IPv6 ::1 ends .ip6.arpa", r1.endsWith(QLatin1String(".ip6.arpa")));
        chk("rev: IPv6 ::1 reversed starts 1.0.0.0.",
            r1.startsWith(QLatin1String("1.0.0.0.")));
        const QString r0 = ipToReverseDnsName("::");
        chk("rev: IPv6 :: all-zero starts 0.0.0.0.",
            r0.startsWith(QLatin1String("0.0.0.0.")));
        chk("rev: IPv6 :: length 72",       r0.size() == 72);
        const QString r2 = ipToReverseDnsName("2001:db8::1");
        chk("rev: IPv6 2001:db8::1 length 72", r2.size() == 72);
        chk("rev: IPv6 2001:db8::1 ends .ip6.arpa",
            r2.endsWith(QLatin1String(".ip6.arpa")));
    }
    chk("rev: IPv6 two '::' -> empty",     ipToReverseDnsName("1::2::3").isEmpty());
    chk("rev: IPv6 too many groups -> empty",
        ipToReverseDnsName("1:2:3:4:5:6:7:8:9").isEmpty());
    chk("rev: IPv6 non-hex group -> empty", ipToReverseDnsName("2001:zzzz::1").isEmpty());
    chk("rev: IPv6 embedded IPv4 (::ffff:1.2.3.4) -> empty",
        ipToReverseDnsName("::ffff:1.2.3.4").isEmpty());
    chk("rev: IPv6 uppercase hex normalized identical to lowercase",
        ipToReverseDnsName("2001:DB8::1") == ipToReverseDnsName("2001:db8::1"));

    // ===== whoisReferralServer ==========================================
    chk("whois-ref: IANA refer:",
        whoisReferralServer("domain: COM\nrefer:        whois.verisign-grs.com\n")
            == "whois.verisign-grs.com");
    chk("whois-ref: 'whois:' key",
        whoisReferralServer("whois:        whois.nic.uk\n") == "whois.nic.uk");
    chk("whois-ref: 'Registrar WHOIS Server:' key",
        whoisReferralServer("Domain: x\nRegistrar WHOIS Server: whois.godaddy.com\n")
            == "whois.godaddy.com");
    chk("whois-ref: uppercase key still matches (lowercased)",
        whoisReferralServer("Refer: whois.example.com\n") == "whois.example.com");
    chk("whois-ref: strips a scheme + trailing slash",
        whoisReferralServer("refer: https://whois.example.com/\n") == "whois.example.com");
    chk("whois-ref: no referral -> empty",
        whoisReferralServer("Domain Name: example.com\nStatus: ok\n").isEmpty());
    chk("whois-ref: free-text value (has spaces) is not a server",
        whoisReferralServer("refer: see the registrar website\n").isEmpty());
    chk("whois-ref: value without a dot is rejected",
        whoisReferralServer("refer: localhost\n").isEmpty());
    chk("whois-ref: an embedded CR in the value is rejected (no host concatenation)",
        whoisReferralServer("refer: whois.example.com\revil.com\n").isEmpty());
    chk("whois-ref: a value with a path returns only the host (path cut at first '/')",
        whoisReferralServer("refer: https://whois.example.com/foo\n") == "whois.example.com");

    // ===== sanitizeWhoisQuery (CR/LF / injection guard) =================
    chk("whois-q: plain domain",     sanitizeWhoisQuery("example.com") == "example.com");
    chk("whois-q: trims",            sanitizeWhoisQuery("  example.com  ") == "example.com");
    chk("whois-q: IPv4 allowed",     sanitizeWhoisQuery("8.8.8.8") == "8.8.8.8");
    chk("whois-q: IPv6 colons allowed", sanitizeWhoisQuery("2001:db8::1") == "2001:db8::1");
    chk("whois-q: CRLF injection rejected",
        sanitizeWhoisQuery("example.com\r\nEVIL").isEmpty());
    chk("whois-q: embedded space rejected", sanitizeWhoisQuery("exa mple.com").isEmpty());
    chk("whois-q: empty rejected",   sanitizeWhoisQuery("").isEmpty());
    chk("whois-q: over-length rejected", sanitizeWhoisQuery(QString(256, QChar('a'))).isEmpty());

    std::fprintf(stderr, "recon_engine_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

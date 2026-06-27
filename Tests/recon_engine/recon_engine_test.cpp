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

    // ===== recordMatchesQuery (search-domain expansion guard) ===========
    chk("recordMatchesQuery: exact match", recordMatchesQuery("ftp.example.com", "ftp.example.com"));
    chk("recordMatchesQuery: case-insensitive", recordMatchesQuery("FTP.Example.COM", "ftp.example.com"));
    chk("recordMatchesQuery: a CNAME-chain deeper name is accepted",
        recordMatchesQuery("real.ftp.example.com", "ftp.example.com"));
    chk("recordMatchesQuery: a search-domain-expanded name is rejected",
        !recordMatchesQuery("ftp.example.com.corp.local", "ftp.example.com"));
    chk("recordMatchesQuery: an unrelated host is rejected",
        !recordMatchesQuery("other.example.com", "ftp.example.com"));

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

    std::fprintf(stderr, "recon_engine_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

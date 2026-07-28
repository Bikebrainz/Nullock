// Regression corpus for update_check's pure logic (no network): the semver
// precedence that decides "update available", and the release-URL allow-list.
// Locks the soundness fixes from the audit:
//   - a normal release outranks its own pre-release (1.3.0 > 1.3.0-rc1), so a user
//     on an rc IS told about the final release (the old "strip -rc1, treat equal"
//     made that a silent false negative);
//   - pre-release identifiers follow semver §11 (numeric < alphanumeric, fewer
//     fields < more);
//   - build metadata (+...) and a leading "v" don't affect precedence;
//   - isTrustedReleaseUrl only accepts an HTTPS github.com page.
//
// Run via:  ctest -R update_check -V

#include "update_check.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::UpdateLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
int sign(int x) { return x < 0 ? -1 : (x > 0 ? 1 : 0); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== compareSemver: core numeric precedence =======================
    chk("semver: 1.0.0 < 1.0.1", sign(compareSemver("1.0.0", "1.0.1")) == -1);
    chk("semver: 1.0.1 < 1.1.0", sign(compareSemver("1.0.1", "1.1.0")) == -1);
    chk("semver: 1.9.0 < 2.0.0", sign(compareSemver("1.9.0", "2.0.0")) == -1);
    chk("semver: equal -> 0", compareSemver("1.2.3", "1.2.3") == 0);
    chk("semver: 2.0.0 > 1.9.9", sign(compareSemver("2.0.0", "1.9.9")) == 1);
    chk("semver: numeric (not lexical) field compare (1.0.10 > 1.0.9)",
        sign(compareSemver("1.0.10", "1.0.9")) == 1);

    // ===== leading 'v', short core, build metadata ======================
    chk("semver: leading 'v' ignored", compareSemver("v1.2.3", "1.2.3") == 0);
    chk("semver: leading 'V' ignored", compareSemver("V1.2.3", "1.2.3") == 0);
    chk("semver: short core padded (1.2 == 1.2.0)", compareSemver("1.2", "1.2.0") == 0);
    chk("semver: bare major (1 == 1.0.0)", compareSemver("1", "1.0.0") == 0);
    chk("semver: build metadata (+...) ignored (semver §10)",
        compareSemver("1.2.3+build99", "1.2.3") == 0);
    chk("semver: a non-numeric field is treated as 0 (1.x.0 == 1.0.0)",
        compareSemver("1.x.0", "1.0.0") == 0);

    // ===== pre-release precedence (the FN fix) ==========================
    chk("semver: a release OUTRANKS its own rc -- 1.3.0 > 1.3.0-rc1 (FN fix)",
        sign(compareSemver("1.3.0", "1.3.0-rc1")) == 1);
    chk("semver: on an rc, the FINAL is newer -- 1.3.0-rc1 < 1.3.0 (the FN that was missed)",
        sign(compareSemver("1.3.0-rc1", "1.3.0")) == -1);
    chk("semver: rc1 < rc2 (alphanumeric identifier order)",
        sign(compareSemver("1.3.0-rc1", "1.3.0-rc2")) == -1);
    chk("semver: numeric pre-release identifier ranks below alphanumeric (alpha.1 < alpha.beta)",
        sign(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta")) == -1);
    chk("semver: fewer pre-release fields rank lower (alpha < alpha.1)",
        sign(compareSemver("1.0.0-alpha", "1.0.0-alpha.1")) == -1);
    // TWO numeric pre-release identifiers must compare NUMERICALLY, not lexically:
    // beta.2 < beta.10 (2 < 10). The existing cases only pit numeric vs alphanumeric
    // (alpha.1 < alpha.beta) or single alphanumeric tokens (rc1 < rc2); a regression
    // to a string compare of the numeric identifier would order beta.10 before beta.2.
    chk("semver: numeric pre-release identifiers compare numerically (beta.2 < beta.10)",
        sign(compareSemver("1.0.0-beta.2", "1.0.0-beta.10")) == -1);
    // audit-9: a numeric identifier PAST INT_MAX must still compare numerically -- a
    // toInt()-based compare overflows/fails on both and falls back to a lexical order
    // that puts 9999999999 > 10000000000 ('9' > '1'). Correct is 9999999999 < 10000000000.
    chk("semver: large numeric pre-release identifiers compare numerically past INT_MAX",
        sign(compareSemver("1.0.0-beta.9999999999", "1.0.0-beta.10000000000")) == -1);
    chk("semver: identical pre-release -> equal", compareSemver("1.0.0-rc1", "1.0.0-rc1") == 0);
    chk("semver: a pre-release of a NEWER core still beats the older release (1.2.0 < 1.3.0-rc1)",
        sign(compareSemver("1.2.0", "1.3.0-rc1")) == -1);
    chk("semver: a release does NOT 'downgrade' to a newer-core's rc when current is newer "
        "(2.0.0 > 2.0.0-rc1)", sign(compareSemver("2.0.0", "2.0.0-rc1")) == 1);

    // ===== isTrustedReleaseUrl: HTTPS github.com only ===================
    chk("url: https github release page accepted",
        isTrustedReleaseUrl("https://github.com/Bikebrainz/Nullock/releases/tag/v1.2.3"));
    chk("url: a github subdomain accepted", isTrustedReleaseUrl("https://www.github.com/x"));
    chk("url: http (not https) rejected", !isTrustedReleaseUrl("http://github.com/x"));
    chk("url: a non-github host rejected", !isTrustedReleaseUrl("https://evil.com/x"));
    chk("url: a look-alike host rejected (github.com.evil.com)",
        !isTrustedReleaseUrl("https://github.com.evil.com/x"));
    // audit-9: a PREFIX look-alike (evilgithub.com) must be rejected -- the allow-list
    // is dot-anchored (host==github.com OR endsWith ".github.com"); a dropped-dot
    // regression to endsWith("github.com") would ACCEPT this phishing host.
    chk("url: a prefix look-alike host rejected (evilgithub.com)",
        !isTrustedReleaseUrl("https://evilgithub.com/x"));
    // userinfo-@ bypass: the browser navigates to the host AFTER '@' (evil.com), so
    // this must be rejected. The UI opens this link; a naive substring match on
    // "github.com" would accept it and surface a phishing page. Distinct from the
    // suffix look-alike above.
    chk("url: a userinfo-@ bypass rejected (github.com@evil.com -> host evil.com)",
        !isTrustedReleaseUrl("https://github.com@evil.com/x"));
    chk("url: a javascript: scheme rejected", !isTrustedReleaseUrl("javascript:alert(1)"));
    chk("url: a file: scheme rejected", !isTrustedReleaseUrl("file:///etc/passwd"));
    chk("url: empty rejected", !isTrustedReleaseUrl(""));

    std::fprintf(stderr, "update_check_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Regression corpus for tls_profile's pure logic (no TLS backend): the
// name<->profile mapping, the browser cipher lists, and the TLS-1.3-suite split
// that underpins the soundness fix from the audit:
//   - settableCipherNames() drops the "TLS_*" 1.3 suite names (Qt 6 has no
//     setCiphersuites(), so they are NOT settable). apply() requires exactly the
//     SETTABLE names to resolve before it touches cfg's cipher list -- otherwise a
//     PARTIAL list (e.g. the 3 always-dropped 1.3 names) would ship a fingerprint
//     MORE anomalous than Qt's default, defeating the whole purpose.
//
// Run via:  ctest -R tls_profile -V

#include "tls_profile.hpp"

#include <QCoreApplication>
#include <QSet>

#include <cstdio>

using namespace Nullock::Core::TlsProfile;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
int countTls13(const QStringList &l) {
    int n = 0; for (const QString &s : l) if (isTls13SuiteName(s)) ++n; return n;
}
bool hasDuplicates(const QStringList &l) { return QSet<QString>(l.begin(), l.end()).size() != l.size(); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== fromName: name -> profile (case-insensitive, aliases) =========
    chk("fromName: 'chrome' -> Chrome130", fromName("chrome") == Profile::Chrome130);
    chk("fromName: 'chrome130' -> Chrome130", fromName("chrome130") == Profile::Chrome130);
    chk("fromName: 'Chrome130' case-insensitive", fromName("Chrome130") == Profile::Chrome130);
    chk("fromName: 'firefox' -> Firefox131", fromName("firefox") == Profile::Firefox131);
    chk("fromName: 'FIREFOX131' case-insensitive", fromName("FIREFOX131") == Profile::Firefox131);
    chk("fromName: 'none' -> None", fromName("none") == Profile::None);
    chk("fromName: '' -> None", fromName("") == Profile::None);
    chk("fromName: an unknown name -> None (soft fall-through)", fromName("safari17") == Profile::None);

    // ===== name: profile -> canonical string + roundtrip ================
    chk("name: Chrome130 -> 'chrome130'", name(Profile::Chrome130) == "chrome130");
    chk("name: Firefox131 -> 'firefox131'", name(Profile::Firefox131) == "firefox131");
    chk("name: None -> 'none'", name(Profile::None) == "none");
    chk("roundtrip: Chrome130", fromName(name(Profile::Chrome130)) == Profile::Chrome130);
    chk("roundtrip: Firefox131", fromName(name(Profile::Firefox131)) == Profile::Firefox131);

    // ===== cipherNames: the browser lists ===============================
    {
        const QStringList chrome = cipherNames(Profile::Chrome130);
        const QStringList ff = cipherNames(Profile::Firefox131);
        chk("cipherNames: Chrome130 non-empty", !chrome.isEmpty());
        chk("cipherNames: Firefox131 non-empty", !ff.isEmpty());
        chk("cipherNames: None is empty", cipherNames(Profile::None).isEmpty());
        chk("cipherNames: no duplicates in Chrome list", !hasDuplicates(chrome));
        // audit-10: the Firefox settable subset (TLS<=1.2; the 3 "TLS_" 1.3 names are
        // dropped) is 10, led by ECDHE-ECDSA-AES128-GCM-SHA256 -- only Chrome's was pinned.
        const QStringList ffSettable = settableCipherNames(ff);
        chk("Firefox settable count == 10", ffSettable.size() == 10);
        chk("Firefox settable leads ECDHE-ECDSA-AES128-GCM-SHA256",
            ffSettable.value(0) == "ECDHE-ECDSA-AES128-GCM-SHA256");
        chk("Firefox settable ends ECDHE-RSA-AES256-SHA",
            ffSettable.value(ffSettable.size() - 1) == "ECDHE-RSA-AES256-SHA");
        // audit-10: Firefox 131 has NO plain-RSA kx -- assert the INVARIANT (every
        // cipher is ECDHE- or a TLS 1.3 suite), not two hard-coded names.
        bool ffAllEcdheOr13 = true;
        for (const QString &cn : ff)
            if (!(cn.startsWith("ECDHE-") || isTls13SuiteName(cn))) ffAllEcdheOr13 = false;
        chk("Firefox: every cipher is ECDHE- or a TLS1.3 suite (no plain-RSA kx)", ffAllEcdheOr13);
        chk("cipherNames: no duplicates in Firefox list", !hasDuplicates(ff));
        chk("cipherNames: Chrome lists a known TLS1.2 suite",
            chrome.contains("ECDHE-RSA-AES128-GCM-SHA256"));
        chk("cipherNames: Chrome leads with the TLS1.3 suites (intended order)",
            chrome.value(0) == "TLS_AES_128_GCM_SHA256");
        chk("cipherNames: Firefox has NO plain-RSA-kx cipher (browser fidelity)",
            !ff.contains("AES128-GCM-SHA256") && !ff.contains("AES128-SHA"));
    }

    // ===== isTls13SuiteName: the "TLS_*" 1.3 names ======================
    chk("isTls13SuiteName: TLS_AES_128_GCM_SHA256 -> true", isTls13SuiteName("TLS_AES_128_GCM_SHA256"));
    chk("isTls13SuiteName: TLS_CHACHA20_POLY1305_SHA256 -> true", isTls13SuiteName("TLS_CHACHA20_POLY1305_SHA256"));
    chk("isTls13SuiteName: an ECDHE 1.2 cipher -> false", !isTls13SuiteName("ECDHE-RSA-AES128-GCM-SHA256"));
    chk("isTls13SuiteName: a plain 1.2 cipher -> false", !isTls13SuiteName("AES128-SHA"));

    // ===== settableCipherNames: the Qt6-settable (<=1.2) subset =========
    {
        const QStringList chrome = cipherNames(Profile::Chrome130);
        const QStringList settable = settableCipherNames(chrome);
        chk("settable: drops exactly the TLS1.3 suite names",
            settable.size() == chrome.size() - countTls13(chrome));
        chk("settable: Chrome drops its 3 leading 1.3 suites", countTls13(chrome) == 3);
        chk("settable: the result contains NO TLS_* name", countTls13(settable) == 0);
        chk("settable: a 1.2 cipher survives", settable.contains("ECDHE-RSA-AES128-GCM-SHA256"));
        chk("settable: order of the surviving 1.2 ciphers is preserved",
            settable.value(0) == "ECDHE-ECDSA-AES128-GCM-SHA256");
        chk("settable: an all-1.3 input yields an empty settable set",
            settableCipherNames(QStringList{ "TLS_AES_128_GCM_SHA256" }).isEmpty());
        chk("settable: an empty input yields empty", settableCipherNames(QStringList()).isEmpty());
    }

    std::fprintf(stderr, "tls_profile_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

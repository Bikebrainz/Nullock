// Regression corpus for the tls_inspect probe's pure evaluation logic (no
// network): the algorithm-aware key-strength gate, RFC 6125 hostname matching
// (SAN precedence, wildcard, trailing-dot), negotiated-cipher classification,
// and over-broad-wildcard detection. These lock the soundness fixes from the
// adversarial audit:
//   - keyIsWeak no longer flags a 256-bit EC key as weak (the headline FP);
//   - hostnameCovered ignores the CN when a SAN dNSName is present (FN);
//   - nameMatches normalizes a trailing FQDN dot (FP);
//   - cipherWeakness flags NULL/anon/EXPORT/RC4/DES and 3DES/MD5 (FN);
//   - isOverbroadWildcard catches *.com / *.co.uk (FN).
//
// Run via:  ctest -R tls_inspect -V

#include "tls_inspect.hpp"

#include <QCoreApplication>
#include <QStringList>

#include <cstdio>

using namespace Nullock::Core::TlsInspect;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// keyIsWeak with the detail discarded.
bool weakKey(const QString &algo, int bits) { QString d; return keyIsWeak(algo, bits, d); }
// cipherWeakness kind with the detail discarded.
QString cipherKind(const QString &name, int bits) { QString d; return cipherWeakness(name, bits, d); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== keyIsWeak: algorithm-aware (the EC false-positive fix) =========
    chk("EC P-256 (256-bit) is NOT weak (was the headline false positive)", !weakKey("EC", 256));
    chk("EC P-384 is NOT weak", !weakKey("EC", 384));
    chk("EC P-521 is NOT weak", !weakKey("EC", 521));
    chk("EC P-192 (< P-256) IS weak", weakKey("EC", 192));
    chk("EC 160-bit IS weak", weakKey("EC", 160));
    chk("RSA 1024 IS weak", weakKey("RSA", 1024));
    chk("RSA 2048 is NOT weak", !weakKey("RSA", 2048));
    chk("RSA 4096 is NOT weak", !weakKey("RSA", 4096));
    chk("DSA 1024 IS weak", weakKey("DSA", 1024));
    chk("DH 1024 IS weak", weakKey("DH", 1024));
    chk("Ed25519 (256-bit) is NEVER weak", !weakKey("ED25519", 256));
    chk("Ed448 is NEVER weak", !weakKey("ED448", 456));
    chk("opaque/unknown key (bits<=0) is NOT weak (undetermined, no FP)", !weakKey("", 0));
    chk("opaque key reported as -1 bits is NOT weak", !weakKey("", -1));
    chk("opaque key with a small positive bit count is NOT weak (Ed25519-as-opaque guard)", !weakKey("", 256));
    chk("opaque key with a sub-1024 bit count is still NOT weak (empty algo => undetermined)", !weakKey("", 200));
    chk("unknown algorithm with a sub-1024-bit key IS weak (conservative floor)", weakKey("XMSS", 512));
    chk("unknown algorithm with a >=1024-bit key is NOT weak (no FP on unmodeled scheme)", !weakKey("XMSS", 2048));
    chk("algorithm name is case-insensitive (ec/256 not weak)", !weakKey("ec", 256));
    {   // the detail text is interpretable (carries the algorithm + bit count)
        QString d; keyIsWeak("RSA", 1024, d);
        chk("weak-key detail names RSA and the bit count", d.contains("RSA") && d.contains("1024"));
        QString d2; keyIsWeak("EC", 192, d2);
        chk("weak EC detail mentions the curve size", d2.contains("192") && d2.toLower().contains("ec"));
    }

    // ===== nameMatches: wildcard + trailing-dot normalization =============
    chk("exact match", nameMatches("www.example.com", "www.example.com"));
    chk("exact match is case-insensitive", nameMatches("WWW.Example.COM", "www.example.com"));
    chk("wildcard matches one left-most label", nameMatches("api.example.com", "*.example.com"));
    chk("wildcard does NOT match two labels", !nameMatches("a.b.example.com", "*.example.com"));
    chk("wildcard does NOT match the bare apex", !nameMatches("example.com", "*.example.com"));
    chk("trailing-dot FQDN host still matches an exact cert (FP fix)",
        nameMatches("www.example.com.", "www.example.com"));
    chk("trailing-dot FQDN host still matches a wildcard cert (FP fix)",
        nameMatches("api.example.com.", "*.example.com"));
    chk("trailing dot on the cert name is normalized too",
        nameMatches("www.example.com", "www.example.com."));
    chk("a genuinely different host does NOT match", !nameMatches("evil.com", "www.example.com"));
    chk("empty cert name never matches", !nameMatches("www.example.com", ""));

    // ===== hostnameCovered: RFC 6125 SAN precedence (the FN fix) ==========
    {
        const QStringList cn{ "good.example.com" };
        // The classic miss: CN==host but the SAN list does NOT cover the host.
        const QStringList sanWrong{ "api.evil.com" };
        bool fb = true;
        chk("SAN present + host only in CN -> NOT covered (CN ignored per RFC 6125)",
            !hostnameCovered("good.example.com", cn, sanWrong, fb));
        chk("usedCnFallback is false when a SAN dNSName exists", fb == false);

        const QStringList sanRight{ "good.example.com", "api.example.com" };
        bool fb2 = true;
        chk("SAN present + host in SAN -> covered",
            hostnameCovered("good.example.com", cn, sanRight, fb2));
        chk("usedCnFallback stays false on a SAN match", fb2 == false);

        // No SAN dNSName at all -> the CN is the only identity (legacy fallback).
        bool fb3 = false;
        chk("no SAN -> fall back to CN match",
            hostnameCovered("good.example.com", cn, QStringList(), fb3));
        chk("usedCnFallback is true when no SAN dNSName is present", fb3 == true);

        bool fb4 = false;
        chk("no SAN + CN mismatch -> not covered",
            !hostnameCovered("other.example.com", cn, QStringList(), fb4));

        // A wildcard SAN is honored.
        bool fb5 = true;
        chk("wildcard SAN dNSName covers a sub-label host",
            hostnameCovered("a.example.com", QStringList(), QStringList{ "*.example.com" }, fb5));
    }

    // ===== cipherWeakness: weak vs legacy vs sound ========================
    chk("NULL-encryption cipher (0 bits) -> weak-cipher", cipherKind("TLS_RSA_WITH_NULL_SHA", 0) == "tls-weak-cipher");
    chk("NULL by name even with nonzero bits -> weak-cipher", cipherKind("NULL-SHA", 0) == "tls-weak-cipher");
    chk("anonymous DH (ADH) -> weak-cipher", cipherKind("ADH-AES128-SHA", 128) == "tls-weak-cipher");
    chk("anonymous ECDH (AECDH) -> weak-cipher", cipherKind("AECDH-AES256-SHA", 256) == "tls-weak-cipher");
    chk("EXPORT-grade -> weak-cipher", cipherKind("EXP-RC2-CBC-MD5", 40) == "tls-weak-cipher");
    chk("RC4 -> weak-cipher", cipherKind("ECDHE-RSA-RC4-SHA", 128) == "tls-weak-cipher");
    chk("single DES -> weak-cipher", cipherKind("DES-CBC-SHA", 56) == "tls-weak-cipher");
    chk("3DES -> legacy-cipher (Sweet32)", cipherKind("ECDHE-RSA-DES-CBC3-SHA", 112) == "tls-legacy-cipher");
    chk("3DES alt spelling -> legacy-cipher", cipherKind("DES-CBC3-SHA", 112) == "tls-legacy-cipher");
    chk("MD5-MAC -> legacy-cipher", cipherKind("AES128-MD5", 128) == "tls-legacy-cipher");
    chk("sub-128-bit symmetric -> legacy-cipher", cipherKind("SEED-SHA", 80) == "tls-legacy-cipher");
    chk("modern AEAD (AES-128-GCM) is sound -> no finding", cipherKind("ECDHE-RSA-AES128-GCM-SHA256", 128).isEmpty());
    chk("TLS 1.3 AES-256-GCM is sound -> no finding", cipherKind("TLS_AES_256_GCM_SHA384", 256).isEmpty());
    chk("ChaCha20-Poly1305 is sound -> no finding", cipherKind("TLS_CHACHA20_POLY1305_SHA256", 256).isEmpty());
    chk("AES does not trip the DES matcher (no 'DES' substring confusion)", cipherKind("ECDHE-ECDSA-AES256-GCM-SHA384", 256).isEmpty());
    chk("ephemeral DHE (not anonymous) is sound", cipherKind("DHE-RSA-AES128-GCM-SHA256", 128).isEmpty());
    chk("empty cipher name -> no finding", cipherKind("", 0) == QString() || cipherKind("", 0).isEmpty());

    // ===== isOverbroadWildcard: public-suffix-spanning certs =============
    chk("*.com is over-broad", isOverbroadWildcard("*.com"));
    chk("*.co.uk is over-broad (two-level public suffix)", isOverbroadWildcard("*.co.uk"));
    chk("*.com.au is over-broad", isOverbroadWildcard("*.com.au"));
    chk("bare *. is over-broad", isOverbroadWildcard("*."));
    chk("*.example.com is a normal registrable-domain wildcard (NOT over-broad)", !isOverbroadWildcard("*.example.com"));
    chk("*.api.example.com is NOT over-broad", !isOverbroadWildcard("*.api.example.com"));
    chk("*.example.co.uk is NOT over-broad (registrable domain under co.uk)", !isOverbroadWildcard("*.example.co.uk"));
    chk("a non-wildcard name is never over-broad", !isOverbroadWildcard("www.example.com"));
    chk("over-broad check is case-insensitive", isOverbroadWildcard("*.CO.UK"));

    std::fprintf(stderr, "tls_inspect_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

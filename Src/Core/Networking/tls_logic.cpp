// Pure TLS-evaluation logic, split out of tls_inspect.cpp so a unit test can link
// it against Qt6::Core alone -- inspect()'s QSslSocket/QSslCertificate I/O stays
// in tls_inspect.cpp. Everything here is a deterministic function of strings/ints
// the I/O side extracts from the peer certificate and negotiated session:
//   nameMatches/hostnameCovered -- RFC 6125 identity matching (SAN precedence,
//     single-label "*." wildcard, trailing-dot/FQDN normalization);
//   keyIsWeak                   -- algorithm-aware key-strength gate (no "256-bit
//     EC key is weak" false positive);
//   cipherWeakness              -- weak/legacy negotiated-suite classification;
//   isOverbroadWildcard         -- public-suffix-spanning wildcard detection.

#include "tls_inspect.hpp"

#include <QSet>
#include <QString>
#include <QStringList>

namespace Nullock::Core::TlsInspect {

// Lower-case, whitespace-trim, and drop a single trailing '.' (the DNS root label
// of a fully-qualified host like "www.example.com." -- valid input some callers
// pass, and what SNI tolerates -- which must not be read as a name mismatch).
static QString normName(QString s) {
    s = s.toLower().trimmed();
    if (s.endsWith('.')) s.chop(1);
    return s;
}

bool nameMatches(const QString &host, const QString &certName) {
    const QString h = normName(host);
    const QString c = normName(certName);
    if (c.isEmpty() || h.isEmpty()) return false;
    if (c.startsWith("*.")) {
        const QString suffix = c.mid(1);                 // ".example.com"
        const int dot = h.indexOf('.');
        // A "*." wildcard matches EXACTLY one left-most label: the host must have
        // a label before the first dot, and the remainder must equal the suffix
        // (so "a.b.example.com" does NOT match "*.example.com", and the apex
        // "example.com" does not match "*.example.com").
        return dot > 0 && h.mid(dot) == suffix;
    }
    return h == c;
}

bool hostnameCovered(const QString &host, const QStringList &cnNames,
                     const QStringList &sanDnsNames, bool &usedCnFallback) {
    // RFC 6125 §6.4.4 / CA-Browser-Forum: when ANY SAN dNSName is present, the CN
    // MUST NOT be used for identity matching -- a cert whose SANs don't cover the
    // host is a mismatch even if its legacy CN happens to equal the host. Only
    // fall back to the CN when the cert presents no SAN dNSName at all.
    if (!sanDnsNames.isEmpty()) {
        usedCnFallback = false;
        for (const QString &n : sanDnsNames)
            if (nameMatches(host, n)) return true;
        return false;
    }
    usedCnFallback = true;
    for (const QString &n : cnNames)
        if (nameMatches(host, n)) return true;
    return false;
}

bool keyIsWeak(const QString &algo, int bits, QString &detail) {
    const QString a = algo.toUpper();
    // Opaque/unsupported key types report length() <= 0 -- strength is
    // undetermined, NOT zero. Never manufacture a weak-key finding from it.
    if (bits <= 0) return false;
    // EdDSA is a fixed, strong construction regardless of the small bit count.
    if (a == "ED25519" || a == "ED448") return false;
    if (a == "EC") {
        // EC key length IS the curve field size: P-256=256, P-384=384, P-521=521.
        // 256-bit EC ~= 128-bit security ~= RSA-3072 -- strong. Only curves below
        // P-256 are weak. (The 2048-bit RSA floor is a finite-field notion and
        // must NOT be applied to EC -- doing so flags every modern ECDSA cert.)
        if (bits < 256) {
            detail = QStringLiteral("EC public key on a %1-bit curve (weaker than P-256)").arg(bits);
            return true;
        }
        return false;
    }
    if (a == "RSA" || a == "DSA" || a == "DH") {
        if (bits < 2048) {
            detail = QStringLiteral("%1 public key is only %2 bits (< 2048)")
                         .arg(algo, QString::number(bits));
            return true;
        }
        return false;
    }
    // An EMPTY algorithm string means the backend could not classify the key
    // (Opaque) -- e.g. an Ed25519/Ed448 key surfacing without a dedicated
    // QSsl::KeyAlgorithm value, reporting a small bit count. Treat as
    // undetermined, NEVER weak, so a strong EdDSA key is not flagged via the
    // bit-count floor below.
    if (a.isEmpty()) return false;
    // A NAMED but unmodeled algorithm: only a sub-1024-bit key is unambiguously
    // weak across every scheme; above that, don't risk a false positive on
    // something we can't model.
    if (bits < 1024) {
        detail = QStringLiteral("%1 public key is only %2 bits").arg(algo, QString::number(bits));
        return true;
    }
    return false;
}

QString cipherWeakness(const QString &cipherName, int usedBits, QString &detail) {
    const QString n = cipherName.toUpper();
    if (n.isEmpty()) return QString();

    // ---- catastrophic: no confidentiality / no authentication ----
    if (usedBits == 0 || n.contains(QLatin1String("NULL"))) {
        detail = QStringLiteral("negotiated a NULL-encryption cipher (%1) -- no confidentiality").arg(cipherName);
        return QStringLiteral("tls-weak-cipher");
    }
    if (n.contains(QLatin1String("ADH")) || n.contains(QLatin1String("AECDH"))
        || n.startsWith(QLatin1String("ANON")) || n.contains(QLatin1String("_ANON"))) {
        detail = QStringLiteral("negotiated an anonymous (unauthenticated) cipher (%1) -- trivial MITM").arg(cipherName);
        return QStringLiteral("tls-weak-cipher");
    }
    if (n.contains(QLatin1String("EXPORT")) || n.startsWith(QLatin1String("EXP"))
        || n.contains(QLatin1String("-EXP-"))) {
        detail = QStringLiteral("negotiated an EXPORT-grade cipher (%1) -- deliberately weakened").arg(cipherName);
        return QStringLiteral("tls-weak-cipher");
    }
    if (n.contains(QLatin1String("RC4"))) {
        detail = QStringLiteral("negotiated RC4 (%1) -- biased keystream, prohibited by RFC 7465").arg(cipherName);
        return QStringLiteral("tls-weak-cipher");
    }
    // Single DES (56-bit) -- but NOT 3DES/DES-CBC3/DES-EDE3.
    const bool tripleDes = n.contains(QLatin1String("3DES")) || n.contains(QLatin1String("DES-CBC3"))
                        || n.contains(QLatin1String("DES_CBC3")) || n.contains(QLatin1String("EDE3"));
    if (!tripleDes && (n.contains(QLatin1String("DES-CBC")) || n.contains(QLatin1String("DES_CBC"))
                       || n.contains(QLatin1String("-DES-")) || n.contains(QLatin1String("_DES_")))) {
        detail = QStringLiteral("negotiated single-DES (%1) -- 56-bit, brute-forceable").arg(cipherName);
        return QStringLiteral("tls-weak-cipher");
    }

    // ---- legacy: weak but not immediately broken ----
    if (tripleDes) {
        detail = QStringLiteral("negotiated 3DES (%1) -- 112-bit, Sweet32 (CVE-2016-2183)").arg(cipherName);
        return QStringLiteral("tls-legacy-cipher");
    }
    if (n.endsWith(QLatin1String("-MD5")) || n.endsWith(QLatin1String("_MD5"))) {
        detail = QStringLiteral("negotiated an MD5-MAC cipher (%1)").arg(cipherName);
        return QStringLiteral("tls-legacy-cipher");
    }
    if (usedBits > 0 && usedBits < 128) {
        detail = QStringLiteral("negotiated a %1-bit symmetric cipher (%2) -- below 128-bit strength")
                     .arg(QString::number(usedBits), cipherName);
        return QStringLiteral("tls-legacy-cipher");
    }
    return QString();
}

bool isOverbroadWildcard(const QString &certName) {
    QString c = certName.toLower().trimmed();
    if (c.endsWith('.')) c.chop(1);                      // "*.com." FQDN root label
    if (c == QLatin1String("*")) return true;            // bare "*" / "*." -- matches anything
    if (!c.startsWith("*.")) return false;
    const QString base = c.mid(2);                       // the part after "*."
    if (base.isEmpty()) return true;                     // nothing after the wildcard
    const QStringList labels = base.split('.', Qt::SkipEmptyParts);
    if (labels.size() < 2) return true;                  // "*.com" -- spans a TLD
    if (labels.size() == 2) {
        // "*.<sld>.<tld>" is normally a legitimate registrable-domain wildcard,
        // EXCEPT where registrations happen a level down and "<sld>.<tld>" is
        // itself a public suffix (so "*.co.uk" would cover every .co.uk site).
        static const QSet<QString> twoLevelPublicSuffixes = {
            QStringLiteral("co.uk"),  QStringLiteral("org.uk"), QStringLiteral("gov.uk"),
            QStringLiteral("ac.uk"),  QStringLiteral("me.uk"),  QStringLiteral("net.uk"),
            QStringLiteral("com.au"), QStringLiteral("net.au"), QStringLiteral("org.au"),
            QStringLiteral("gov.au"), QStringLiteral("edu.au"), QStringLiteral("co.nz"),
            QStringLiteral("net.nz"), QStringLiteral("org.nz"), QStringLiteral("co.jp"),
            QStringLiteral("or.jp"),  QStringLiteral("ne.jp"),  QStringLiteral("go.jp"),
            QStringLiteral("co.za"),  QStringLiteral("org.za"), QStringLiteral("com.br"),
            QStringLiteral("net.br"), QStringLiteral("com.cn"), QStringLiteral("net.cn"),
            QStringLiteral("org.cn"), QStringLiteral("gov.cn"), QStringLiteral("co.in"),
            QStringLiteral("com.mx"), QStringLiteral("com.tr"), QStringLiteral("com.sg"),
        };
        if (twoLevelPublicSuffixes.contains(base)) return true;
    }
    return false;
}

} // namespace Nullock::Core::TlsInspect

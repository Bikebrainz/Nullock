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

#include <QByteArray>
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

namespace {
// Read one ASN.1 DER TLV header at `pos`. On success sets contentPos (start of
// content), contentLen, and nextPos (first byte after this TLV) and returns the
// tag byte; returns -1 on a malformed/overrunning/indefinite-length header.
// Handles short- and (up to 4-byte) long-form lengths.
int derReadTLV(const QByteArray &der, int pos, int &contentPos, int &contentLen, int &nextPos) {
    const int n = der.size();
    if (pos < 0 || pos + 1 >= n) return -1;                 // need at least tag + 1 length byte
    const int tag = static_cast<unsigned char>(der[pos]);
    int p = pos + 1;                                        // p <= n here (pos+1 < n)
    const int len0 = static_cast<unsigned char>(der[p++]);
    int len = 0;
    if (len0 < 0x80) {
        len = len0;                                         // short form
    } else {
        const int nbytes = len0 & 0x7f;
        // Subtraction form (n - p >= 0) so the bound never overflows. A 4-byte
        // length with bit 31 set decodes to a negative `len` and is rejected below.
        if (nbytes == 0 || nbytes > 4 || nbytes > n - p) return -1;  // indefinite / too large
        for (int i = 0; i < nbytes; ++i) len = (len << 8) | static_cast<unsigned char>(der[p++]);
        if (len < 0) return -1;
    }
    // CRITICAL: compare via subtraction, never `p + len > n`. An attacker can encode
    // len = 0x7FFFFFFF (positive, so `len < 0` misses it); `p + len` would overflow
    // signed int to a NEGATIVE value, pass `> n`, and yield a multi-GB over-read of
    // an attacker-controlled cert. `len > n - p` (both operands >= 0) cannot overflow.
    if (len < 0 || len > n - p) return -1;
    contentPos = p; contentLen = len; nextPos = p + len;    // p + len <= n, no overflow
    return tag;
}

// Decode a DER OBJECT IDENTIFIER content (no tag/len) to a dotted-decimal string.
QString derDecodeOid(const QByteArray &der, int pos, int len) {
    // Subtraction-form bounds (der.size() is 64-bit qsizetype) so `pos + len` can't
    // overflow into a passing value -- the same INT_MAX-length over-read vector.
    if (pos < 0 || pos > der.size() || len <= 0 || len > der.size() - pos) return QString();
    const int first = static_cast<unsigned char>(der[pos]);
    QString out = QString::number(first / 40) + QLatin1Char('.') + QString::number(first % 40);
    quint64 arc = 0;
    for (int i = 1; i < len; ++i) {
        const int b = static_cast<unsigned char>(der[pos + i]);
        arc = (arc << 7) | (b & 0x7f);
        if (!(b & 0x80)) { out += QLatin1Char('.') + QString::number(arc); arc = 0; }
    }
    return out;
}
} // namespace

QString signatureAlgorithmOid(const QByteArray &der) {
    // X.509  Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
    // AlgorithmIdentifier SEQUENCE { algorithm OID, parameters OPTIONAL }, ... }.
    // The OUTER signatureAlgorithm is the authoritative "signed-with" field, so we
    // skip tbsCertificate and read the OID of the SECOND outer child.
    constexpr int kSequence = 0x30, kOid = 0x06;
    int cp, cl, np;
    if (derReadTLV(der, 0, cp, cl, np) != kSequence) return QString();      // outer SEQUENCE; content [cp, np)
    int tcp, tcl, tnp;
    if (derReadTLV(der, cp, tcp, tcl, tnp) != kSequence) return QString();  // tbsCertificate (skipped)
    if (tnp > np) return QString();                                        // tbs must stay inside the outer SEQ
    int scp, scl, snp;
    if (derReadTLV(der, tnp, scp, scl, snp) != kSequence) return QString(); // signatureAlgorithm
    if (snp > np) return QString();                                        // sigAlg must stay inside the outer SEQ
    int ocp, ocl, onp;
    if (derReadTLV(der, scp, ocp, ocl, onp) != kOid) return QString();      // its algorithm OID
    if (onp > snp) return QString();                                       // OID must stay inside sigAlg
    return derDecodeOid(der, ocp, ocl);
}

QString weakSignatureFinding(const QString &oid, QString &severity, QString &detail) {
    severity.clear();
    detail.clear();
    // Certificate signature algorithms whose hash is collision-feasible: an
    // attacker who can mount a (chosen-prefix) collision can forge a colliding
    // certificate. MD2/MD4/MD5 are badly broken (high); SHA-1 is chosen-prefix-
    // broken and deprecated for PKI since 2017 (medium).
    struct Weak { const char *oid; const char *name; const char *sev; };
    static const Weak kWeak[] = {
        { "1.2.840.113549.1.1.2",  "MD2 with RSA",                "high"   },
        { "1.2.840.113549.1.1.3",  "MD4 with RSA",                "high"   },
        { "1.2.840.113549.1.1.4",  "MD5 with RSA",                "high"   },
        { "1.2.840.113549.2.5",    "MD5",                         "high"   },
        { "1.2.840.113549.1.1.5",  "SHA-1 with RSA",              "medium" },
        { "1.3.14.3.2.29",         "SHA-1 with RSA (legacy OID)", "medium" },
        { "1.3.14.3.2.26",         "SHA-1",                       "medium" },
        { "1.2.840.10040.4.3",     "DSA with SHA-1",              "medium" },
        { "1.2.840.10045.4.1",     "ECDSA with SHA-1",            "medium" },
    };
    for (const Weak &w : kWeak) {
        if (oid == QLatin1String(w.oid)) {
            severity = QLatin1String(w.sev);
            detail = QStringLiteral("certificate is signed with %1 -- a collision-feasible "
                                    "hash; an attacker able to mount a hash collision could forge "
                                    "a colliding certificate (signature OID %2)")
                         .arg(QLatin1String(w.name), oid);
            return QStringLiteral("tls-weak-sig-algo");
        }
    }
    return QString();
}

QString untrustedChainFinding(const QStringList &categories, QString &severity, QString &detail) {
    severity.clear();
    detail.clear();
    // `categories` are normalized chain-trust problems the I/O side derived from the
    // explicit chain verification (it maps Qt's QSslError values to these tokens and
    // drops the ones reported elsewhere: a hostname mismatch, an expired/not-yet-
    // valid cert, and a self-signed LEAF -- so this never double-reports them).
    QStringList msgs;
    if (categories.contains(QLatin1String("self-signed-in-chain")))
        msgs << QStringLiteral("a self-signed certificate is in the chain (an untrusted private root)");
    if (categories.contains(QLatin1String("incomplete-chain")))
        msgs << QStringLiteral("the chain is incomplete -- an intermediate/issuer certificate is missing");
    if (categories.contains(QLatin1String("untrusted-root")))
        msgs << QStringLiteral("the chain terminates in a root not in the system trust store");
    if (categories.contains(QLatin1String("ca-invalid")))
        msgs << QStringLiteral("a certificate in the chain is not a valid CA for the issuance it performed");
    if (msgs.isEmpty()) return QString();          // no recognized chain-trust problem -> sound
    severity = QStringLiteral("medium");
    detail = QStringLiteral("the presented certificate chain does NOT validate against the system "
                            "trust store: ") + msgs.join(QStringLiteral("; "))
           + QStringLiteral(" -- a browser would refuse this connection (possible MITM, "
                            "mis-deployed intermediate, or a private/self-managed CA)");
    return QStringLiteral("tls-untrusted-chain");
}

QString legacyProbeVerdict(bool encrypted, const QString &failureCategory) {
    // A legacy-protocol (TLS 1.0/1.1) probe is tri-state. A FAILED handshake does
    // NOT mean "the protocol is disabled" -- it could be a network error/timeout
    // that reached no verdict. Treating that as clean is a false negative (a
    // legacy-enabled server looks safe). So:
    //   encrypted              -> "enabled"      (the legacy handshake completed)
    //   failureCategory ==      -> "disabled"     (TCP connected but the server
    //     "tls-refused"            (clean)         declined THIS version: alert /
    //                                              reset / handshake-fail)
    //   anything else           -> "inconclusive" (unreachable / timeout / DNS /
    //     (unreachable/unknown)                    unknown -- report it, do NOT
    //                                              claim the protocol is disabled)
    if (encrypted) return QStringLiteral("enabled");
    if (failureCategory == QLatin1String("tls-refused")) return QStringLiteral("disabled");
    return QStringLiteral("inconclusive");
}

} // namespace Nullock::Core::TlsInspect

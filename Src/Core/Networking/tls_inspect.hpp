#pragma once

// TLS / certificate inspection (testssl.sh-class). The existing tls_profile only
// SHAPES our outbound ClientHello; nothing reads the peer side. This connects to
// a host:port, retrieves the certificate and negotiated protocol/cipher, and
// flags weak configuration: expired / not-yet-valid / self-signed certs, short
// RSA keys, hostname/SAN mismatch, soon-to-expire certs, and deprecated
// protocols (TLS 1.0/1.1) that still complete a handshake. Read-only: it reads
// what the server presents, it doesn't attack. Findings map to CWE-295/326/327.

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::TlsInspect {

struct Finding {
    QString kind;        // "tls-self-signed", "tls-expired", "tls-weak-key", ...
    QString severity;    // low | medium | high
    QString detail;
};

struct Request {
    QString host;
    int     port = 443;
    int     timeoutMs = 6000;
    bool    probeLegacyProtocols = true;   // attempt TLS 1.0/1.1 handshakes
};

struct Result {
    bool    connected = false;
    QString negotiatedProtocol;  // "TLSv1.3", ...
    QString cipher;
    QString subject;
    QString issuer;
    bool    selfSigned = false;
    QString notBefore;
    QString notAfter;
    int     daysToExpiry = 0;
    int     keyBits = 0;
    QString keyAlgorithm;        // "RSA" | "EC" | "DSA" | "DH" | "" (opaque/unknown)
    bool    hostnameMatch = true;
    QStringList sans;
    QStringList legacyProtocolsEnabled;  // e.g. ["TLSv1.0","TLSv1.1"]
    QStringList legacyProtocolsInconclusive;  // probed but no verdict (network error/
                                              // timeout) -- NOT confirmed disabled
    QList<Finding> findings;
    QString error;
};

// Connect, read the peer certificate + negotiated parameters, evaluate, and
// (when probeLegacyProtocols) test whether TLS 1.0/1.1 still handshake.
Result inspect(const Request &req);

// --- Pure evaluation logic, exposed for the unit test (no I/O; in tls_logic.cpp,
//     links Qt6::Core alone -- inspect()'s QSslSocket work stays in tls_inspect.cpp).
//
//   nameMatches       -- host vs one cert name (CN or SAN), single leading "*."
//                        wildcard, trailing-dot (FQDN root label) normalized.
//   hostnameCovered   -- RFC 6125 precedence: if any SAN dNSName exists, match
//                        ONLY against the SANs (the CN is ignored); fall back to
//                        the CN only when no SAN dNSName is present. Sets
//                        usedCnFallback so the caller can note a CN-only cert.
//   keyIsWeak         -- algorithm-aware key-strength gate. RSA/DSA/DH weak below
//                        2048 bits; EC weak below 256 (curves under P-256);
//                        Ed25519/Ed448 never weak; unknown/opaque (bits<=0) is
//                        treated as NOT weak (undetermined) -- never a false
//                        "256-bit EC key is weak" positive. true => weak, with a
//                        human-readable `detail`.
//   cipherWeakness    -- classify a negotiated suite by name + symmetric bits.
//                        Returns the finding KIND ("tls-weak-cipher" for
//                        NULL/anon/EXPORT/RC4/single-DES, "tls-legacy-cipher" for
//                        3DES/MD5-MAC/<128-bit) or "" when the suite is sound.
//   isOverbroadWildcard -- a wildcard spanning a public suffix (*.com, *.co.uk):
//                        a cert no conformant client should accept.
//   signatureAlgorithmOid -- the certificate's signatureAlgorithm OID (dotted
//                        decimal) parsed straight from the DER (QSslCertificate
//                        exposes no signature-algorithm API). "" if unparseable.
//   weakSignatureFinding -- map a signature OID using a collision-feasible hash
//                        (MD2/4/5 -> high; SHA-1 -> medium) to the finding kind
//                        "tls-weak-sig-algo" (setting severity + detail); "" for a
//                        modern algorithm (SHA-2/3, EdDSA, ...) or unknown OID.
bool    nameMatches(const QString &host, const QString &certName);
bool    hostnameCovered(const QString &host, const QStringList &cnNames,
                        const QStringList &sanDnsNames, bool &usedCnFallback);
bool    keyIsWeak(const QString &algo, int bits, QString &detail);
QString cipherWeakness(const QString &cipherName, int usedBits, QString &detail);
bool    isOverbroadWildcard(const QString &certName);
QString signatureAlgorithmOid(const QByteArray &der);
QString weakSignatureFinding(const QString &oid, QString &severity, QString &detail);
//   untrustedChainFinding -- compose a "tls-untrusted-chain" finding from the
//                        normalized chain-trust categories ("self-signed-in-chain",
//                        "incomplete-chain", "untrusted-root", "ca-invalid") the
//                        I/O side derives from explicit chain verification; "" when
//                        no recognized problem is present (a chain that validates).
QString untrustedChainFinding(const QStringList &categories, QString &severity, QString &detail);
//   legacyProbeVerdict -- tri-state for a TLS 1.0/1.1 probe: "enabled" (handshake
//                        completed), "disabled" (TCP reached, server refused the
//                        version -> clean), or "inconclusive" (unreachable/timeout
//                        -- a failed handshake is NOT proof the protocol is off).
QString legacyProbeVerdict(bool encrypted, const QString &failureCategory);

} // namespace Nullock::Core::TlsInspect

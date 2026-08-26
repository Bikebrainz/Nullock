#pragma once

// Pure host-validation logic for the MITM CA, split out of cert_authority.cpp so a
// unit test can link it against Qt6::Core alone (cert_authority.cpp pulls
// QProcess/QFile/Win32 ACL APIs). The `host` validated here is ATTACKER-
// INFLUENCEABLE -- it comes from the intercepted CONNECT target / TLS SNI -- and
// flows into the openssl `-subj /CN=<host>` argument and the SAN extension file, so
// this guard is the CA's only defence against host-driven injection.

#include <QString>

namespace Nullock::Proxy::CertLogic {

// Strict DNS-host validation. Permit ONLY [letter/number] plus '-', '.', '_';
// reject empty, a host whose UTF-8 length exceeds 253 (the DNS limit, measured in
// BYTES so supplementary-plane letters can't overflow the X.509 field), a leading
// '-'/'_', and a leading/trailing or double dot. This rejects every byte that
// could inject: '\n'/'\r' (an extra SAN-ext-file line, e.g. basicConstraints
// CA:TRUE), '/'/'=' (an extra `-subj` DN field), '\\'/':'/path separators (leaf-
// file path traversal). Returns true only for a benign hostname.
bool isValidHostForCert(const QString &host);

// Map any char outside [letter/number] '-' '.' '_' to '_' so the host is safe to
// embed in a leaf-file path. INVARIANT: every char isValidHostForCert permits is
// already in this keep-set, so sanitize() is IDENTITY on a valid host -- two
// distinct valid hosts never collapse to one leaf-file path (which would let one
// host be served another's cached cert). Preserve that if the validator is ever
// relaxed (e.g. don't permit a char sanitize would rewrite without re-checking).
QString sanitize(const QString &host);

// Is `host` an IPv4 dotted-quad literal (exactly four ASCII 0..255 octets)? This
// decides the SAN TYPE when minting a forged leaf: a client verifying an IP-literal
// host requires an iPAddress SAN (RFC 6125), so a "DNS:<ip>" SAN is rejected -- and
// in this proxy a rejected forged leaf then auto-blocklists the host, making every
// https://<ip>/ target un-interceptable. Pure. (IPv6 literals are a separate,
// tracked remainder: isValidHostForCert still rejects ':' as an injection guard, so
// an IPv6 target never reaches minting; relaxing that safely needs collision-proof
// leaf-file naming too.)
bool isIpv4Literal(const QString &host);

// Strict textual IPv6 literal (Qt6::Core only; no QHostAddress). Accepts full and
// "::"-compressed forms, an embedded IPv4 tail (::ffff:192.0.2.1), and "::";
// rejects a zone id (%eth0), a second "::", and empty/oversize/non-hex groups. A
// valid IPv6 becomes an "IP:" SAN and is accepted by isValidHostForCert.
bool isIpv6Literal(const QString &host);

// The subjectAltName entry for a leaf minted for `host`: "IP:<addr>" for an IPv4
// literal, else "DNS:<host>". `host` is assumed already isValidHostForCert-clean
// (so it is safe to embed verbatim in the openssl SAN extension file).
QString sanEntryForHost(const QString &host);

} // namespace Nullock::Proxy::CertLogic

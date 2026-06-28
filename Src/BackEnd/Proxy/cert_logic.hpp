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

} // namespace Nullock::Proxy::CertLogic

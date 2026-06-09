#pragma once

// TLS handshake profiles. Tunes QSslConfiguration to look as much like
// a real browser as Qt's API allows.
//
// What this can do (works on OpenSSL backend):
//   * Pin the cipher list to a known browser's order. JA3 hash depends
//     on cipher list, so this is the single highest-impact knob.
//   * Restrict TLS protocol to 1.2 or 1.3 to match the profile.
//   * Pin ALPN preferences to the browser's order.
//
// What this CAN'T do (Qt's API doesn't expose):
//   * TLS extension list / order (huge JA3 component)
//   * EC point format byte order
//   * Compression methods
//   * Application-level TLS extensions (signature_algorithms order, etc.)
//
// On Windows with SChannel backend, even cipher ordering is largely
// ignored -- SChannel sorts ciphers by its own preferences. Detect this
// and warn if requested but unsupported.
//
// Practical effect: a WAF that fingerprints by full JA3 will still spot
// our handshake as non-Chrome, but a tier-1 fingerprint match (cipher
// list + TLS version + ALPN) will pass.
//
// For full JA3-exact shaping, a swap to a TLS stack with byte-level
// control (utls, openssl-direct via FFI) would be needed. Out of scope
// for this iteration; see TODO comment in tls_profile.cpp.

#include <QString>

class QSslConfiguration;

namespace Nullock::Core::TlsProfile {

enum class Profile {
    None,        // Qt default behavior
    Chrome130,   // Recent stable Chrome
    Firefox131,  // Recent stable Firefox
};

Profile fromName(const QString &name);
QString name(Profile p);

// Apply the profile's cipher order, TLS version range, and ALPN order
// to cfg. Returns false if the requested profile isn't applicable to
// the current TLS backend (e.g. SChannel ignores cipher order, so we
// degrade silently with a warning).
bool apply(QSslConfiguration &cfg, Profile p);

} // namespace Nullock::Core::TlsProfile

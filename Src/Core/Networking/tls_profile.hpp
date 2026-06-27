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
//   * TLS 1.3 ciphersuite selection/order -- Qt 6.7 has no setCiphersuites(), so
//     the backend's default 1.3 suites are always offered (the "TLS_*" names in a
//     profile are documentation of intent, not settable; see settableCipherNames)
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
#include <QStringList>

class QSslConfiguration;

namespace Nullock::Core::TlsProfile {

enum class Profile {
    None,        // Qt default behavior
    Chrome130,   // Recent stable Chrome
    Firefox131,  // Recent stable Firefox
};

Profile fromName(const QString &name);
QString name(Profile p);

// Apply the profile's cipher list, TLS version floor, and ALPN order to cfg.
// Returns true ONLY when the fingerprint was actually shaped. Returns false when
// it was NOT shaped -- an unknown profile, a backend that ignores cipher order
// (SChannel), or a backend missing one of the profile's settable (TLS<=1.2)
// ciphers (in which case cfg's cipher list is left at the Qt default rather than
// shipping a PARTIAL list, which fingerprints worse than a clean default).
// Profile::None returns true (a no-op success: no shaping was requested).
bool apply(QSslConfiguration &cfg, Profile p);

// --- Pure helpers, exposed for the unit test (no I/O; in tls_profile_logic.cpp,
//     links Qt6::Core alone -- apply()'s QSslConfiguration work stays in
//     tls_profile.cpp).
//   cipherNames        -- the profile's full intended cipher list, in order.
//   isTls13SuiteName   -- an RFC 8446 TLS 1.3 ciphersuite name ("TLS_*"), which
//                         Qt 6 cannot pin via setCiphers().
//   settableCipherNames-- the subset Qt's setCiphers() can actually set (the 1.3
//                         "TLS_*" names removed) -- the set apply() requires to
//                         resolve COMPLETELY before it touches cfg's ciphers.
QStringList cipherNames(Profile p);
bool        isTls13SuiteName(const QString &cipherName);
QStringList settableCipherNames(const QStringList &names);

} // namespace Nullock::Core::TlsProfile

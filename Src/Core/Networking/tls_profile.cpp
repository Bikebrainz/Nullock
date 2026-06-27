#include "tls_profile.hpp"

#include <QDebug>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslSocket>

// TODO: byte-level JA3 shaping needs out-of-band TLS handshake control
// that Qt's API doesn't surface. The realistic future fix is an
// `OpenSslConnect` class that does the handshake via OpenSSL BIO + SSL
// directly, then hands the established session back to QSslSocket via
// resumeSession or wraps a BIO_socket bridge. Both routes are weeks of
// work and would replace QSslSocket for outbound, which has cascading
// implications for cert verification (R5), interception, and SChannel
// vs OpenSSL backend differences. Filed for v2.

// fromName(), name(), cipherNames(), isTls13SuiteName() and settableCipherNames()
// are pure and live in tls_profile_logic.cpp so they can be unit-tested against
// Qt6::Core alone. This TU keeps apply()/resolveCiphers()/backendIsOpenSsl(), which
// pull QSslConfiguration/QSslCipher/QSslSocket (the Qt Network chain).

namespace Nullock::Core::TlsProfile {

namespace {

QList<QSslCipher> resolveCiphers(const QStringList &names) {
    QList<QSslCipher> out;
    for (const QString &n : names) {
        QSslCipher c(n);
        if (c.isNull()) continue;       // backend doesn't support this name
        out.append(c);
    }
    return out;
}

bool backendIsOpenSsl() {
    // QSslSocket::sslLibraryVersionString() returns something like
    // "OpenSSL 3.0.12 24 Oct 2023" on the OpenSSL backend, or a name
    // including "Schannel" on the SChannel backend (newer Qt versions).
    // Older Qt only ship OpenSSL anyway. Heuristic match either way.
    const QString lib = QSslSocket::sslLibraryVersionString().toLower();
    if (lib.contains("openssl")) return true;
    if (lib.contains("boringssl")) return true;
    return false;
}

} // namespace

bool apply(QSslConfiguration &cfg, Profile p) {
    if (p == Profile::None) return true;        // no shaping requested -> no-op success

    const QStringList full = cipherNames(p);
    if (full.isEmpty()) return false;           // unknown profile -> not shaped

    // Qt 6 can only pin TLS <= 1.2 ciphers (there is no setCiphersuites()); the
    // TLS 1.3 suites are offered by the backend's default regardless. Require the
    // SETTABLE (1.2) names to resolve COMPLETELY: a PARTIAL cipher list produces a
    // fingerprint that matches neither the browser nor Qt's default -- MORE
    // anomalous, the opposite of the goal -- so on any miss we leave cfg's ciphers
    // at the Qt default and report "not shaped" rather than ship a mangled list.
    const QStringList settable = settableCipherNames(full);
    const QList<QSslCipher> ciphers = resolveCiphers(settable);
    if (ciphers.size() != settable.size()) {
        qWarning() << "tls-profile:" << name(p) << "-- backend resolved only"
                   << ciphers.size() << "of" << settable.size()
                   << "settable (TLS<=1.2) ciphers; leaving the default cipher list"
                   << "(a partial list is MORE fingerprintable). Profile NOT applied.";
        return false;
    }
    cfg.setCiphers(ciphers);

    // Protocol floor 1.2 (prefer 1.3); ALPN h2 then http/1.1 (modern browsers).
    cfg.setProtocol(QSsl::TlsV1_2OrLater);
    cfg.setAllowedNextProtocols({
        QByteArrayLiteral("h2"),
        QByteArrayLiteral("http/1.1"),
    });

    if (!backendIsOpenSsl()) {
        qWarning() << "tls-profile:" << name(p)
                   << "-- TLS backend isn't OpenSSL (likely SChannel on Windows); cipher"
                      " ORDER is ignored, so the JA3 fingerprint is NOT shaped.";
        return false;   // contract: true ONLY when the fingerprint is actually shaped
    }
    return true;
}

} // namespace Nullock::Core::TlsProfile

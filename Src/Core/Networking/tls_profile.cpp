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

namespace Nullock::Core::TlsProfile {

Profile fromName(const QString &name) {
    const QString n = name.toLower();
    if (n == "chrome" || n == "chrome130")  return Profile::Chrome130;
    if (n == "firefox" || n == "firefox131") return Profile::Firefox131;
    return Profile::None;
}

QString name(Profile p) {
    switch (p) {
        case Profile::Chrome130:  return "chrome130";
        case Profile::Firefox131: return "firefox131";
        case Profile::None:       return "none";
    }
    return "none";
}

namespace {

// Chrome 130's cipher list in handshake order. Pulled from real ClientHello
// capture; refresh as Chrome rolls. JA3 cipher field is derived from
// this list.
//   TLS_AES_128_GCM_SHA256
//   TLS_AES_256_GCM_SHA384
//   TLS_CHACHA20_POLY1305_SHA256
//   ECDHE-ECDSA-AES128-GCM-SHA256
//   ECDHE-RSA-AES128-GCM-SHA256
//   ECDHE-ECDSA-AES256-GCM-SHA384
//   ECDHE-RSA-AES256-GCM-SHA384
//   ECDHE-ECDSA-CHACHA20-POLY1305
//   ECDHE-RSA-CHACHA20-POLY1305
//   ECDHE-RSA-AES128-SHA
//   ECDHE-RSA-AES256-SHA
//   AES128-GCM-SHA256
//   AES256-GCM-SHA384
//   AES128-SHA
//   AES256-SHA
const QStringList &chrome130Ciphers() {
    static const QStringList kList = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    };
    return kList;
}

// Firefox 131 cipher list. Differs slightly in order from Chrome --
// ChaCha20-Poly1305 ranked higher, no plain RSA at all.
const QStringList &firefox131Ciphers() {
    static const QStringList kList = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
    };
    return kList;
}

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
    if (p == Profile::None) return true;

    const QStringList *names = nullptr;
    switch (p) {
        case Profile::Chrome130:  names = &chrome130Ciphers(); break;
        case Profile::Firefox131: names = &firefox131Ciphers(); break;
        default: return false;
    }
    const QList<QSslCipher> ciphers = resolveCiphers(*names);
    if (ciphers.isEmpty()) {
        qWarning() << "tls-profile: backend doesn't recognize any cipher in"
                   << name(p) << "-- profile not applied";
        return false;
    }
    cfg.setCiphers(ciphers);

    // Protocol: both profiles want 1.2 minimum, prefer 1.3.
    cfg.setProtocol(QSsl::TlsV1_2OrLater);

    // ALPN order: h2 then http/1.1 for both profiles (modern browsers).
    cfg.setAllowedNextProtocols({
        QByteArrayLiteral("h2"),
        QByteArrayLiteral("http/1.1"),
    });

    if (!backendIsOpenSsl()) {
        qWarning() << "tls-profile:" << name(p)
                   << "-- TLS backend isn't OpenSSL (likely SChannel on Windows);"
                   << "cipher ORDER will be ignored. JA3 fingerprint not fully shaped.";
        // Return true anyway -- we still applied what we could.
    }
    return true;
}

} // namespace Nullock::Core::TlsProfile

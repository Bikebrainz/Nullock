// Pure TLS-profile data/logic, split out of tls_profile.cpp so a unit test can
// link it against Qt6::Core alone -- apply()/resolveCiphers()/backendIsOpenSsl()
// keep the QSslConfiguration/QSslSocket I/O. The browser cipher *names*, the
// name<->enum mapping, and the TLS-1.3-suite split are deterministic string
// functions with no Qt Network dependency.

#include "tls_profile.hpp"

#include <QStringList>

namespace Nullock::Core::TlsProfile {

Profile fromName(const QString &name) {
    const QString n = name.toLower();
    if (n == "chrome" || n == "chrome130")   return Profile::Chrome130;
    if (n == "firefox" || n == "firefox131") return Profile::Firefox131;
    return Profile::None;
}

QString name(Profile p) {
    switch (p) {
        case Profile::Chrome130:  return QStringLiteral("chrome130");
        case Profile::Firefox131: return QStringLiteral("firefox131");
        case Profile::None:       return QStringLiteral("none");
    }
    return QStringLiteral("none");
}

QStringList cipherNames(Profile p) {
    switch (p) {
    case Profile::Chrome130:
        // Chrome 130's cipher list in handshake order (from a real ClientHello).
        return {
            QStringLiteral("TLS_AES_128_GCM_SHA256"),
            QStringLiteral("TLS_AES_256_GCM_SHA384"),
            QStringLiteral("TLS_CHACHA20_POLY1305_SHA256"),
            QStringLiteral("ECDHE-ECDSA-AES128-GCM-SHA256"),
            QStringLiteral("ECDHE-RSA-AES128-GCM-SHA256"),
            QStringLiteral("ECDHE-ECDSA-AES256-GCM-SHA384"),
            QStringLiteral("ECDHE-RSA-AES256-GCM-SHA384"),
            QStringLiteral("ECDHE-ECDSA-CHACHA20-POLY1305"),
            QStringLiteral("ECDHE-RSA-CHACHA20-POLY1305"),
            QStringLiteral("ECDHE-RSA-AES128-SHA"),
            QStringLiteral("ECDHE-RSA-AES256-SHA"),
            QStringLiteral("AES128-GCM-SHA256"),
            QStringLiteral("AES256-GCM-SHA384"),
            QStringLiteral("AES128-SHA"),
            QStringLiteral("AES256-SHA"),
        };
    case Profile::Firefox131:
        // Firefox 131: ChaCha20 ranked higher, no plain RSA kx at all.
        return {
            QStringLiteral("TLS_AES_128_GCM_SHA256"),
            QStringLiteral("TLS_CHACHA20_POLY1305_SHA256"),
            QStringLiteral("TLS_AES_256_GCM_SHA384"),
            QStringLiteral("ECDHE-ECDSA-AES128-GCM-SHA256"),
            QStringLiteral("ECDHE-RSA-AES128-GCM-SHA256"),
            QStringLiteral("ECDHE-ECDSA-CHACHA20-POLY1305"),
            QStringLiteral("ECDHE-RSA-CHACHA20-POLY1305"),
            QStringLiteral("ECDHE-ECDSA-AES256-GCM-SHA384"),
            QStringLiteral("ECDHE-RSA-AES256-GCM-SHA384"),
            QStringLiteral("ECDHE-ECDSA-AES256-SHA"),
            QStringLiteral("ECDHE-ECDSA-AES128-SHA"),
            QStringLiteral("ECDHE-RSA-AES128-SHA"),
            QStringLiteral("ECDHE-RSA-AES256-SHA"),
        };
    case Profile::None:
        return {};
    }
    return {};
}

bool isTls13SuiteName(const QString &cipherName) {
    // RFC 8446 TLS 1.3 ciphersuites are named "TLS_<AEAD>_<HASH>"
    // (TLS_AES_128_GCM_SHA256, ...). Qt 6.7 has NO setCiphersuites(); setCiphers()
    // models only <= TLS 1.2 ciphers, so these names are not settable -- the backend
    // offers its own default 1.3 suites regardless.
    return cipherName.startsWith(QLatin1String("TLS_"));
}

QStringList settableCipherNames(const QStringList &names) {
    // The subset Qt 6's setCiphers() can actually pin (TLS <= 1.2). The TLS 1.3
    // suite names are excluded because Qt can't set them; including them in the
    // resolve/completeness check would otherwise make every profile look "partial"
    // (the 1.3 names never resolve) and silently ship a mangled cipher list.
    QStringList out;
    for (const QString &n : names)
        if (!isTls13SuiteName(n)) out.append(n);
    return out;
}

} // namespace Nullock::Core::TlsProfile

#include "tls_inspect.hpp"

#include <QDateTime>
#include <QHostAddress>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>

namespace Nullock::Core::TlsInspect {

namespace {

QString protoName(QSsl::SslProtocol p) {
    switch (p) {
        case QSsl::TlsV1_0: return "TLSv1.0";
        case QSsl::TlsV1_1: return "TLSv1.1";
        case QSsl::TlsV1_2: return "TLSv1.2";
        case QSsl::TlsV1_3: return "TLSv1.3";
        default: return "unknown";
    }
}

// Canonical algorithm name for the peer key, so keyIsWeak() can apply the right
// strength floor (the 2048-bit threshold is RSA/finite-field; EC is judged on
// curve size). nameMatches/hostnameCovered/keyIsWeak/cipherWeakness/
// isOverbroadWildcard are pure and live in tls_logic.cpp (Qt6::Core only).
QString keyAlgoName(QSsl::KeyAlgorithm a) {
    switch (a) {
        case QSsl::Rsa: return "RSA";
        case QSsl::Dsa: return "DSA";
        case QSsl::Ec:  return "EC";
        case QSsl::Dh:  return "DH";
        default:        return QString();   // Opaque / unsupported
    }
}

// Try a handshake forcing one protocol; true if it completes encrypted.
bool handshakeWith(const QString &host, int port, int timeoutMs, QSsl::SslProtocol proto) {
    QSslSocket s;
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setProtocol(proto);
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    s.setSslConfiguration(cfg);
    s.connectToHostEncrypted(host, static_cast<quint16>(port));
    const bool ok = s.waitForEncrypted(timeoutMs);
    s.abort();
    return ok;
}

} // namespace

Result inspect(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (!QSslSocket::supportsSsl()) { result.error = "no TLS backend available"; return result; }

    QSslSocket sock;
    // VerifyNone so the handshake completes even against a bad cert -- we then
    // evaluate the certificate ourselves rather than letting Qt reject it.
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    sock.setSslConfiguration(cfg);
    sock.connectToHostEncrypted(req.host, static_cast<quint16>(req.port));
    if (!sock.waitForEncrypted(req.timeoutMs)) {
        result.error = "TLS handshake failed: " + sock.errorString();
        return result;
    }
    result.connected = true;
    result.negotiatedProtocol = protoName(sock.sessionProtocol());
    if (!sock.sessionCipher().isNull()) result.cipher = sock.sessionCipher().name();

    auto add = [&](const QString &k, const QString &sev, const QString &d) {
        result.findings.append({ k, sev, d });
    };

    const QSslCertificate cert = sock.peerCertificate();
    if (cert.isNull()) {
        result.error = "no peer certificate";
        sock.abort();
        return result;
    }
    result.subject = cert.subjectInfo(QSslCertificate::CommonName).join(", ");
    result.issuer  = cert.issuerInfo(QSslCertificate::CommonName).join(", ");
    result.selfSigned = cert.isSelfSigned();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QDateTime nb = cert.effectiveDate(), na = cert.expiryDate();
    result.notBefore = nb.toString(Qt::ISODate);
    result.notAfter  = na.toString(Qt::ISODate);
    result.daysToExpiry = na.isValid() ? static_cast<int>(now.daysTo(na)) : 0;
    result.keyBits = cert.publicKey().length();
    result.keyAlgorithm = keyAlgoName(cert.publicKey().algorithm());

    // CN + SAN names. Keep SAN dNSNames separate from the CN so hostname matching
    // can honor RFC 6125 SAN precedence (CN ignored when any SAN dNSName exists),
    // and filter SANs to the DNS type (an EmailEntry must never match a host).
    const QStringList cnNames = cert.subjectInfo(QSslCertificate::CommonName);
    QStringList sanDnsNames;
    const auto sanMap = cert.subjectAlternativeNames();
    for (auto it = sanMap.begin(); it != sanMap.end(); ++it) {
        result.sans << it.value();
        if (it.key() == QSsl::DnsEntry) sanDnsNames << it.value();
    }
    bool usedCnFallback = false;
    result.hostnameMatch = hostnameCovered(req.host, cnNames, sanDnsNames, usedCnFallback);

    // ---- evaluate ----
    // Validity window. An unparseable notAfter (a malformed cert the VerifyNone
    // handshake still completed against) must surface as a fault, not be silently
    // misread as "expires in 0 days" (daysTo() returns 0 for an invalid date).
    if (!na.isValid())
        add("tls-cert-validity-unparseable", "medium",
            "certificate notAfter date is missing or unparseable -- expiry cannot be evaluated");
    else if (na < now)
        add("tls-expired", "high", "certificate expired " + result.notAfter);
    else if (result.daysToExpiry >= 0 && result.daysToExpiry <= 21)
        add("tls-cert-expiring-soon", "low",
            QString("certificate expires in %1 days").arg(result.daysToExpiry));
    if (nb.isValid() && nb > now)
        add("tls-not-yet-valid", "medium", "certificate not valid until " + result.notBefore);
    if (result.selfSigned)
        add("tls-self-signed", "medium", "self-signed certificate (no trusted CA chain)");
    // Algorithm-aware key strength: a 256-bit EC key is strong (~RSA-3072); only
    // RSA/DSA/DH below 2048, or EC below P-256, is weak -- the flat <2048 check
    // flagged every modern ECDSA cert.
    QString keyDetail;
    if (keyIsWeak(result.keyAlgorithm, result.keyBits, keyDetail))
        add("tls-weak-key", "high", keyDetail);
    // Negotiated-cipher strength (NULL/anon/EXPORT/RC4/single-DES = weak-cipher;
    // 3DES/MD5-MAC/sub-128-bit = legacy-cipher).
    if (!sock.sessionCipher().isNull()) {
        QString cipherDetail;
        const QString ckind = cipherWeakness(result.cipher, sock.sessionCipher().usedBits(), cipherDetail);
        if (ckind == QLatin1String("tls-weak-cipher"))        add(ckind, "high",   cipherDetail);
        else if (ckind == QLatin1String("tls-legacy-cipher")) add(ckind, "medium", cipherDetail);
    }
    // Hostname check is meaningless for a bare IP literal (Qt's SAN API doesn't
    // surface iPAddress entries, so an IP host can't be matched soundly) -- only
    // flag DNS-name hosts.
    if (!result.hostnameMatch && QHostAddress(req.host).isNull())
        add("tls-hostname-mismatch", "medium",
            "host '" + req.host + "' is not in the certificate"
            + (usedCnFallback ? QStringLiteral(" CN (no SAN present)") : QStringLiteral(" SAN")));
    // An over-broad wildcard (e.g. *.com, *.co.uk) is a mis-issued cert no
    // conformant client should trust, independent of whether it covers this host.
    for (const QString &n : (cnNames + sanDnsNames))
        if (isOverbroadWildcard(n)) {
            add("tls-overbroad-wildcard", "medium",
                "certificate presents an over-broad wildcard '" + n + "' spanning a public suffix");
            break;
        }
    if (sock.sessionProtocol() == QSsl::TlsV1_0 || sock.sessionProtocol() == QSsl::TlsV1_1)
        add("tls-deprecated-protocol", "medium",
            "negotiated " + result.negotiatedProtocol + " (deprecated)");
    sock.abort();

    // ---- legacy-protocol probe ----
    if (req.probeLegacyProtocols) {
        if (handshakeWith(req.host, req.port, req.timeoutMs, QSsl::TlsV1_0))
            result.legacyProtocolsEnabled << "TLSv1.0";
        if (handshakeWith(req.host, req.port, req.timeoutMs, QSsl::TlsV1_1))
            result.legacyProtocolsEnabled << "TLSv1.1";
        if (!result.legacyProtocolsEnabled.isEmpty())
            add("tls-legacy-protocol-enabled", "medium",
                "server still accepts " + result.legacyProtocolsEnabled.join(", "));
    }

    return result;
}

} // namespace Nullock::Core::TlsInspect

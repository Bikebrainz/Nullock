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

// Match a host against a cert name (CN or SAN), honoring a single leading
// "*." wildcard label.
bool nameMatches(const QString &host, const QString &certName) {
    const QString h = host.toLower();
    const QString c = certName.toLower().trimmed();
    if (c.isEmpty()) return false;
    if (c.startsWith("*.")) {
        const QString suffix = c.mid(1);                 // ".example.com"
        const int dot = h.indexOf('.');
        // wildcard matches exactly one left-most label
        return dot > 0 && h.mid(dot) == suffix;
    }
    return h == c;
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
    result.daysToExpiry = static_cast<int>(now.daysTo(na));
    result.keyBits = cert.publicKey().length();

    // Subject + SAN names for hostname matching.
    QStringList names = cert.subjectInfo(QSslCertificate::CommonName);
    const auto sanMap = cert.subjectAlternativeNames();
    for (auto it = sanMap.begin(); it != sanMap.end(); ++it) {
        result.sans << it.value();
        names << it.value();
    }
    result.hostnameMatch = false;
    for (const QString &n : names)
        if (nameMatches(req.host, n)) { result.hostnameMatch = true; break; }

    // ---- evaluate ----
    if (na.isValid() && na < now)
        add("tls-expired", "high", "certificate expired " + result.notAfter);
    else if (result.daysToExpiry >= 0 && result.daysToExpiry <= 21)
        add("tls-cert-expiring-soon", "low",
            QString("certificate expires in %1 days").arg(result.daysToExpiry));
    if (nb.isValid() && nb > now)
        add("tls-not-yet-valid", "medium", "certificate not valid until " + result.notBefore);
    if (result.selfSigned)
        add("tls-self-signed", "medium", "self-signed certificate (no trusted CA chain)");
    if (result.keyBits > 0 && result.keyBits < 2048)
        add("tls-weak-key", "high",
            QString("public key is only %1 bits (< 2048)").arg(result.keyBits));
    // Hostname check is meaningless for a bare IP literal -- only flag for names.
    if (!result.hostnameMatch && QHostAddress(req.host).isNull())
        add("tls-hostname-mismatch", "medium",
            "host '" + req.host + "' is not in the certificate CN/SAN");
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

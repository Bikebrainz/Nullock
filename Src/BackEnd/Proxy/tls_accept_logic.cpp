#include "tls_accept_logic.hpp"

namespace Nullock::Proxy::TlsAcceptLogic {

bool isBenignCertError(QSslError::SslError e) {
    switch (e) {
    // Chain-of-trust failures an operator knowingly accepts on a lab/staging box:
    case QSslError::SelfSignedCertificate:
    case QSslError::SelfSignedCertificateInChain:
    case QSslError::UnableToGetLocalIssuerCertificate:
    case QSslError::UnableToVerifyFirstCertificate:
    case QSslError::CertificateUntrusted:
    // Validity-window failures (an expired or not-yet-valid staging cert):
    case QSslError::CertificateExpired:
    case QSslError::CertificateNotYetValid:
    // Name mismatch (a cert issued for a different name than the host):
    case QSslError::HostNameMismatch:
        return true;
    // Everything else stays fatal. Notably NOT ignorable:
    //   CertificateBlacklisted -- Qt's unconditional known-fraudulent check
    //                             (DigiNotar-class); ignoring it is indefensible.
    //   CertificateRevoked     -- fail closed if it ever fires (no OCSP/CRL here).
    //   NoPeerCertificate      -- there is nothing to accept.
    //   any non-certificate TLS error (protocol/cipher) -- unrelated to "bad cert".
    default:
        return false;
    }
}

QList<QSslError> filterIgnorableErrors(const QList<QSslError> &errs) {
    QList<QSslError> out;
    for (const QSslError &e : errs)
        if (isBenignCertError(e.error()))
            out.append(e);
    return out;
}

} // namespace Nullock::Proxy::TlsAcceptLogic

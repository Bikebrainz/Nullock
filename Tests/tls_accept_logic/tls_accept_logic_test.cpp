// Security-boundary test for the upstream-cert accept filter: WHICH TLS
// certificate errors a per-host "accept invalid cert" exception may ignore.
//
// The load-bearing property: benign chain/validity/name errors are ignorable,
// but a KNOWN-FRAUDULENT (CertificateBlacklisted), REVOKED, or no-peer-cert error
// is NOT -- filterIgnorableErrors returns a SMALLER list than its input whenever
// any non-benign error is present, and the proxy's contract is to fail the
// handshake closed in that case. A regression here would silently accept a cert
// Qt itself flags as forged.
//
// Run via:  ctest -R tls_accept_logic -V

#include "tls_accept_logic.hpp"

#include <QCoreApplication>
#include <QList>
#include <QSslError>

#include <cstdio>

using namespace Nullock::Proxy::TlsAcceptLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QSslError E(QSslError::SslError e) { return QSslError(e); }
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== isBenignCertError: the 8 benign validation errors are ignorable =====
    chk("benign: SelfSignedCertificate",        isBenignCertError(QSslError::SelfSignedCertificate));
    chk("benign: SelfSignedCertificateInChain", isBenignCertError(QSslError::SelfSignedCertificateInChain));
    chk("benign: UnableToGetLocalIssuerCertificate", isBenignCertError(QSslError::UnableToGetLocalIssuerCertificate));
    chk("benign: UnableToVerifyFirstCertificate",    isBenignCertError(QSslError::UnableToVerifyFirstCertificate));
    chk("benign: CertificateUntrusted",         isBenignCertError(QSslError::CertificateUntrusted));
    chk("benign: CertificateExpired",           isBenignCertError(QSslError::CertificateExpired));
    chk("benign: CertificateNotYetValid",       isBenignCertError(QSslError::CertificateNotYetValid));
    chk("benign: HostNameMismatch",             isBenignCertError(QSslError::HostNameMismatch));

    // ===== the fatal ones are NOT ignorable (fail closed) =====
    chk("fatal: CertificateBlacklisted NOT benign", !isBenignCertError(QSslError::CertificateBlacklisted));
    chk("fatal: CertificateRevoked NOT benign",     !isBenignCertError(QSslError::CertificateRevoked));
    chk("fatal: NoPeerCertificate NOT benign",      !isBenignCertError(QSslError::NoPeerCertificate));
    chk("fatal: NoError NOT benign",                !isBenignCertError(QSslError::NoError));
    chk("fatal: CertificateSignatureFailed NOT benign", !isBenignCertError(QSslError::CertificateSignatureFailed));

    // ===== filterIgnorableErrors: all-benign -> same size (caller may ignore) =====
    {
        QList<QSslError> in { E(QSslError::SelfSignedCertificate), E(QSslError::HostNameMismatch) };
        QList<QSslError> out = filterIgnorableErrors(in);
        chk("filter: all-benign returns same size (ignore allowed)", out.size() == in.size() && out.size() == 2);
    }
    // Mixed benign + fatal -> SMALLER (caller MUST fail closed, not ignore a subset).
    {
        QList<QSslError> in { E(QSslError::SelfSignedCertificate), E(QSslError::CertificateBlacklisted) };
        QList<QSslError> out = filterIgnorableErrors(in);
        chk("filter: benign+blacklisted -> smaller than input (fail closed)", out.size() == 1 && out.size() < in.size());
        chk("filter: the surviving error is the benign one", !out.isEmpty() && out.first().error() == QSslError::SelfSignedCertificate);
    }
    // A lone fatal error -> empty.
    {
        QList<QSslError> in { E(QSslError::CertificateRevoked) };
        chk("filter: lone revoked -> empty", filterIgnorableErrors(in).isEmpty());
    }
    {
        QList<QSslError> in { E(QSslError::NoPeerCertificate) };
        chk("filter: lone no-peer-cert -> empty", filterIgnorableErrors(in).isEmpty());
    }
    // Empty in -> empty out (size equal: a caller with no errors has nothing to do).
    chk("filter: empty -> empty", filterIgnorableErrors({}).isEmpty());

    std::fprintf(stderr, "tls_accept_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

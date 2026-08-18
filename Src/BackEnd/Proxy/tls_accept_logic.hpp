#pragma once

#include <QList>
#include <QSslError>

// Pure decision logic for "accept an invalid UPSTREAM TLS certificate for a host
// the operator explicitly allow-listed" (so a self-signed / expired staging box
// stays interceptable, the way Burp accepts invalid upstream certs). Split out of
// proxy_server.cpp so the security boundary -- WHICH cert errors may be ignored --
// unit-tests + mutation-proves against Qt6::Core+Network alone, with none of the
// proxy's socket/thread machinery.
//
// The rule (deliberately NARROW): ignore only the benign certificate-VALIDATION
// errors an operator means when they say "this lab cert is fine". Everything else
// -- above all a cert Qt flags as KNOWN-FRAUDULENT (CertificateBlacklisted, the
// DigiNotar-class check Qt runs unconditionally), a REVOKED cert, or NoPeerCertificate
// -- is NOT ignorable, so the handshake fails CLOSED. "Accept my staging cert" must
// never silently become "accept a cert we know is forged".
namespace Nullock::Proxy::TlsAcceptLogic {

// Is this a benign certificate-validation error that an explicit per-host
// "accept invalid cert" exception is allowed to ignore?
bool isBenignCertError(QSslError::SslError e);

// Filter a presented sslErrors list to only the benign, ignorable errors.
// Caller contract: ignore the returned list ONLY IF it is the SAME SIZE as the
// input (i.e. EVERY presented error was benign). If it is smaller, at least one
// non-ignorable error (revoked / blacklisted / no-peer-cert / a non-cert TLS
// error) is present and the caller MUST fail the handshake closed rather than
// ignore a subset.
QList<QSslError> filterIgnorableErrors(const QList<QSslError> &errs);

} // namespace Nullock::Proxy::TlsAcceptLogic

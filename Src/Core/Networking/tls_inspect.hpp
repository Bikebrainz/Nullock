#pragma once

// TLS / certificate inspection (testssl.sh-class). The existing tls_profile only
// SHAPES our outbound ClientHello; nothing reads the peer side. This connects to
// a host:port, retrieves the certificate and negotiated protocol/cipher, and
// flags weak configuration: expired / not-yet-valid / self-signed certs, short
// RSA keys, hostname/SAN mismatch, soon-to-expire certs, and deprecated
// protocols (TLS 1.0/1.1) that still complete a handshake. Read-only: it reads
// what the server presents, it doesn't attack. Findings map to CWE-295/326/327.

#include <QList>
#include <QString>

namespace Nullock::Core::TlsInspect {

struct Finding {
    QString kind;        // "tls-self-signed", "tls-expired", "tls-weak-key", ...
    QString severity;    // low | medium | high
    QString detail;
};

struct Request {
    QString host;
    int     port = 443;
    int     timeoutMs = 6000;
    bool    probeLegacyProtocols = true;   // attempt TLS 1.0/1.1 handshakes
};

struct Result {
    bool    connected = false;
    QString negotiatedProtocol;  // "TLSv1.3", ...
    QString cipher;
    QString subject;
    QString issuer;
    bool    selfSigned = false;
    QString notBefore;
    QString notAfter;
    int     daysToExpiry = 0;
    int     keyBits = 0;
    bool    hostnameMatch = true;
    QStringList sans;
    QStringList legacyProtocolsEnabled;  // e.g. ["TLSv1.0","TLSv1.1"]
    QList<Finding> findings;
    QString error;
};

// Connect, read the peer certificate + negotiated parameters, evaluate, and
// (when probeLegacyProtocols) test whether TLS 1.0/1.1 still handshake.
Result inspect(const Request &req);

} // namespace Nullock::Core::TlsInspect

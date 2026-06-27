#pragma once

#include "proxy_server.hpp"
#include "socket_outcome.hpp"
#include "tls_profile.hpp"

#include <QByteArray>
#include <QObject>
#include <QString>

namespace Nullock::Core {

// Synchronous one-shot HTTP/HTTPS client. Given a raw HTTP request body
// (request line + headers + body, CRLF-terminated) plus a host/port/TLS
// triple, it opens a connection, writes the bytes verbatim, and reads
// back the response. No QNetworkAccessManager middleware -- the user is
// responsible for the request bytes so they can fuzz/repro anything.
class HttpClient : public QObject {
    Q_OBJECT
public:
    explicit HttpClient(QObject *parent = nullptr);

    struct SendResult {
        bool       ok = false;
        // How the transport leg ended. Defaults to Ok and is only meaningful
        // when ok == false. Added so callers (the smuggling timing probe) can
        // tell a socket that stayed OPEN and silent (Timeout -- a true desync
        // block) from one the peer DROPPED (Reset -- a WAF quarantine) that
        // produces the same delay. Purely additive: existing consumers that
        // read ok/errorMessage/rawResponse/parsed are unaffected.
        SocketOutcome outcome = SocketOutcome::Ok;
        QString    errorMessage;
        QByteArray rawResponse;  // status line + headers + body, as received
        Nullock::Proxy::HttpResponse parsed;
    };

    SendResult send(const QString &host,
                    quint16 port,
                    bool useTls,
                    const QByteArray &requestBytes);

    // TLS handshake profile. Default Profile::None == Qt defaults.
    // Set once at App wire time from the --tls-fingerprint flag.
    void setProfile(TlsProfile::Profile p) { m_profile = p; }
    static void setDefaultProfile(TlsProfile::Profile p);
    static TlsProfile::Profile defaultProfile();

private:
    TlsProfile::Profile m_profile = TlsProfile::Profile::None;
};

} // namespace Nullock::Core

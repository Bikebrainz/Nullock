#pragma once

#include "proxy_server.hpp"

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
        QString    errorMessage;
        QByteArray rawResponse;  // status line + headers + body, as received
        Nullock::Proxy::HttpResponse parsed;
    };

    SendResult send(const QString &host,
                    quint16 port,
                    bool useTls,
                    const QByteArray &requestBytes);
};

} // namespace Nullock::Core

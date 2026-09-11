#pragma once

#include <QByteArray>
#include <QString>
#include <functional>

namespace Nullock::Core::OutboundScope {
// A null path denotes a connection without an HTTP resource (TCP/TLS probes,
// CONNECT, asterisk-form, or malformed fuzz requests). Protocol: 0 unknown,
// 1 HTTP, 2 HTTPS. Such targets require an unrestricted path grant.
struct Target {
    QString host;
    int port;
    int protocol;
    QString path;
};
using Checker = std::function<bool(const Target &)>;

// Installed once by App; checkers must be thread-safe. Each send reads the
// current project policy. The owner must drain workers before destroying it.
class Registration {
public:
    explicit Registration(Checker checker);
    ~Registration();
    Registration(const Registration &) = delete;
    Registration &operator=(const Registration &) = delete;
};
bool allows(const Target &target);
bool allowsRequest(const QString &host, int port, bool tls, const QByteArray &request);
bool allowsUrl(const QString &host, int port, bool tls, const QString &target);
inline QString blockedError() { return QStringLiteral("Target is outside project scope; request was not sent"); }
} // namespace Nullock::Core::OutboundScope

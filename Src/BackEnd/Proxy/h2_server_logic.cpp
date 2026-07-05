#include "h2_server_logic.hpp"

namespace Nullock::Proxy::H2ServerLogic {

H2ReqFields parseRequestHeaders(const QList<QPair<QString, QString>> &h2headers) {
    H2ReqFields f;
    for (const auto &kv : h2headers) {
        const QString &n = kv.first;
        if (n == QLatin1String(":method"))         f.method    = kv.second;
        else if (n == QLatin1String(":scheme"))    f.scheme    = kv.second;
        else if (n == QLatin1String(":authority")) f.authority = kv.second;
        else if (n == QLatin1String(":path"))      f.path      = kv.second;
        else if (!n.startsWith(QLatin1Char(':')))  f.headers.append(kv);   // regular header
        // unknown pseudo-headers are dropped (must not leak into an h1 request)
    }
    f.valid = !f.method.isEmpty() && !f.path.isEmpty();
    return f;
}

QList<HeaderNV> responseHeaders(int status,
                                const QList<QPair<QString, QString>> &headers) {
    QList<HeaderNV> out;
    out.reserve(headers.size() + 1);
    out.push_back({ QByteArrayLiteral(":status"), QByteArray::number(status) });
    for (const auto &kv : headers) {
        if (kv.first.isEmpty()) continue;
        const QString lower = kv.first.toLower();
        // h2 forbids connection-specific response headers (RFC 9113 s8.2.2).
        if (H2ClientLogic::isHopByHopHeader(lower)) continue;
        out.push_back({ lower.toUtf8(), kv.second.toUtf8() });
    }
    return out;
}

} // namespace Nullock::Proxy::H2ServerLogic

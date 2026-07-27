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
    const QSet<QString> connNamed = H2ClientLogic::connectionNamedHeaders(headers);
    for (const auto &kv : headers) {
        if (kv.first.isEmpty()) continue;
        const QString lower = kv.first.toLower();
        // h2 forbids connection-specific response headers (RFC 9113 s8.2.2).
        if (H2ClientLogic::isHopByHopHeader(lower)) continue;
        // ...including every field NAMED in the origin's Connection header, else an
        // origin-declared hop-by-hop header leaks across the h1->h2 hop to the browser.
        if (connNamed.contains(lower)) continue;
        // Drop content-length: we RE-FRAME the body ourselves (our own DATA frames
        // + END_STREAM define the length authoritatively). Forwarding the upstream's
        // value risks a client-side length mismatch -> STREAM_ERROR if our
        // re-serialized body differs from it by even one byte.
        if (lower == QLatin1String("content-length")) continue;
        out.push_back({ lower.toUtf8(), kv.second.toUtf8() });
    }
    return out;
}

} // namespace Nullock::Proxy::H2ServerLogic

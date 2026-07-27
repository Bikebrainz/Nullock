#include "h2_client_logic.hpp"

namespace Nullock::Proxy::H2ClientLogic {

bool isHopByHopHeader(const QString &lowerName) {
    // h2 forbids these connection-specific headers (RFC 9113 s8.2.2); Host is
    // replaced by :authority.
    return lowerName == QLatin1String("host")
        || lowerName == QLatin1String("connection")
        || lowerName == QLatin1String("proxy-connection")
        || lowerName == QLatin1String("transfer-encoding")
        || lowerName == QLatin1String("upgrade")
        || lowerName == QLatin1String("keep-alive")
        || lowerName == QLatin1String("te");
}

QSet<QString> connectionNamedHeaders(const QList<QPair<QString, QString>> &headers) {
    // Collect the tokens a Connection header lists. Directive tokens ("close",
    // "keep-alive") are harmless -- they never match a real header name (and
    // keep-alive is on the fixed hop-by-hop list anyway).
    QSet<QString> named;
    for (const auto &kv : headers) {
        if (kv.first.compare(QLatin1String("connection"), Qt::CaseInsensitive) != 0) continue;
        const auto toks = kv.second.split(QLatin1Char(','), Qt::SkipEmptyParts);
        for (const QString &tok : toks) {
            const QString t = tok.trimmed().toLower();
            if (!t.isEmpty()) named.insert(t);
        }
    }
    return named;
}

QList<HeaderNV> buildRequestHeaders(const QString &method,
                                    const QString &authority,
                                    const QString &path,
                                    const QList<QPair<QString, QString>> &headers) {
    QList<HeaderNV> out;
    out.reserve(headers.size() + 4);

    const QByteArray m = (method.isEmpty() ? QStringLiteral("GET") : method).toUtf8();
    const QByteArray p = (path.isEmpty() ? QStringLiteral("/") : path).toUtf8();

    // Pseudo-headers first, in the required order.
    out.push_back({ QByteArrayLiteral(":method"),    m });
    out.push_back({ QByteArrayLiteral(":scheme"),    QByteArrayLiteral("https") });
    out.push_back({ QByteArrayLiteral(":authority"), authority.toUtf8() });
    out.push_back({ QByteArrayLiteral(":path"),      p });

    const QSet<QString> connNamed = connectionNamedHeaders(headers);
    for (const auto &kv : headers) {
        if (kv.first.isEmpty()) continue;
        const QString lower = kv.first.toLower();
        if (isHopByHopHeader(lower)) continue;
        if (connNamed.contains(lower)) continue;   // named in a Connection header -> hop-by-hop
        out.push_back({ lower.toUtf8(), kv.second.toUtf8() });
    }
    return out;
}

const char *reasonFor(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 408: return "Request Timeout";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:
            if (status >= 200 && status < 300) return "OK";
            if (status >= 300 && status < 400) return "Redirect";
            if (status >= 400 && status < 500) return "Client Error";
            if (status >= 500 && status < 600) return "Server Error";
            return "Unknown";
    }
}

bool shouldRejectSubmit(int currentOpen, int cap) {
    return currentOpen >= cap;
}

bool bodyOverBudget(qint64 accumulated, qint64 cap) {
    return accumulated > cap;
}

PumpAction nextPumpAction(int openStreams, bool wrotePending, bool fatal) {
    if (fatal)            return PumpAction::Fatal;
    if (openStreams <= 0) return PumpAction::Done;
    if (wrotePending)     return PumpAction::WriteThenRead;
    return PumpAction::ReadOnly;
}

AssembleOutcome assembleOutcome(bool done, int statusCode, bool hadError, bool fatal) {
    // A cleanly-finished stream is always a success.
    if (done && statusCode != 0 && !hadError) return AssembleOutcome::Success;
    // Otherwise classify why it did not finish cleanly (order matters: a
    // connection fatal dominates a per-stream error, which dominates no-status).
    if (fatal)            return AssembleOutcome::Fatal;
    if (hadError)         return AssembleOutcome::StreamError;
    if (statusCode == 0)  return AssembleOutcome::NoStatus;
    // :status arrived but END_STREAM never did (peer FIN mid-body): serve the
    // partial response, as the pre-refactor code did.
    return AssembleOutcome::Success;
}

} // namespace Nullock::Proxy::H2ClientLogic

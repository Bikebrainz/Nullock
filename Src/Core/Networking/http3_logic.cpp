#include "http3_logic.hpp"

namespace Nullock::Core::Http3Detect {

QByteArray buildGet(const Request &req) {
    // Request-line / Host injection guard: the request-line target (path/query)
    // and the Host header are written RAW below, so a CR/LF in any of them would
    // inject a header or split the request line.
    if (req.host.contains('\r')  || req.host.contains('\n'))  return {};
    if (req.path.contains('\r')  || req.path.contains('\n'))  return {};
    if (req.query.contains('\r') || req.query.contains('\n')) return {};

    const QString path = req.path.isEmpty() ? QStringLiteral("/") : req.path;
    const QString target = req.query.isEmpty() ? path : path + "?" + req.query;
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/http3-detect\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// An h3 protocol-id is "h3" or "h3-<anything>" (drafts h3-29, h3-Q050, ...).
// Match the token start so "h3-29" counts but unrelated ids like "h2" don't.
bool looksHttp3(const QString &id) {
    return id == QLatin1String("h3") || id.startsWith(QLatin1String("h3-"));
}

QList<AltProtocol> parseAltSvc(const QString &value) {
    QList<AltProtocol> out;
    if (value.trimmed().compare(QLatin1String("clear"), Qt::CaseInsensitive) == 0)
        return out;
    for (const QString &entryRaw : value.split(',', Qt::SkipEmptyParts)) {
        const QStringList parts = entryRaw.split(';');
        if (parts.isEmpty()) continue;
        const QString head = parts.first().trimmed();
        const int eq = head.indexOf('=');
        if (eq <= 0) continue;
        AltProtocol p;
        p.id = head.left(eq).trimmed();
        p.authority = head.mid(eq + 1).trimmed();
        if (p.authority.startsWith('"') && p.authority.endsWith('"') && p.authority.size() >= 2)
            p.authority = p.authority.mid(1, p.authority.size() - 2);
        for (int i = 1; i < parts.size(); ++i) {
            const QString param = parts.at(i).trimmed();
            if (param.startsWith(QLatin1String("ma="), Qt::CaseInsensitive)) {
                bool ok = false;
                const int ma = param.mid(3).trimmed().toInt(&ok);
                if (ok) p.maxAge = ma;
            }
        }
        if (p.id.isEmpty()) continue;
        p.isHttp3 = looksHttp3(p.id);
        out.append(p);
    }
    return out;
}

} // namespace Nullock::Core::Http3Detect

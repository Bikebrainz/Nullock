// Pure (no-network) logic for the cache-deception probe: sentinel generation,
// the body-length similarity test, the inert catch-all control decision, and
// the GET builder's CR/LF guards. Split out of cache_deception.cpp so
// Tests/cache_deception links Qt6::Core alone (no HttpClient / Network / GUI).

#include "cache_deception.hpp"

#include <QRandomGenerator>

namespace Nullock::Core::CacheDeception {

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("nlk");
    for (int i = 0; i < 6; ++i) s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

bool lenSimilar(int a, int b) {
    const int mx = qMax(a, b), d = qAbs(a - b);
    // <=16 absolute (per-request token drift) OR <5% relative. Tighter than the
    // old 40-byte / 10% floor so two coincidentally-near short pages don't
    // match -- the inert control does the heavy lifting against catch-alls, but
    // this still has to separate "echoed page" from "real asset / soft page".
    return d <= 16 || (mx > 0 && double(d) / mx < 0.05);
}

bool isCatchAll(bool controlOk, int controlStatus, int controlLen, int baselineLen) {
    // A bogus, non-existent base with a static suffix that ALSO returns a
    // length-similar 2xx means the app routes every path to one page (SPA
    // history fallback / soft-200 catch-all). There is no per-user page to
    // leak, so a static-suffix "hit" is not path confusion.
    if (!controlOk) return false;
    if (controlStatus < 200 || controlStatus >= 300) return false;
    return lenSimilar(controlLen, baselineLen);
}

QByteArray buildGet(const Request &req, const QString &path) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    // host and path are attacker-influenceable on the HAR-import / deep-audit
    // path (basePath is set raw); a CR/LF would smuggle a second request line
    // or header -- refuse to build rather than emit it.
    if (crlf(req.host) || crlf(path)) return QByteArray();

    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cache-deception\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::CacheDeception

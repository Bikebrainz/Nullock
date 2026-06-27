// Pure WebSocket-handshake logic, split out of ws_probe.cpp so a unit test can
// link it against Qt6::Core alone -- handshake()/test() and their QSslSocket/
// QTcpSocket I/O stay in ws_probe.cpp. expectedAccept() is the RFC 6455 proof
// (base64(SHA1(key + magic GUID))), checkable against the spec's known vector;
// headerValue() and statusFromHeaderBlock() parse the upgrade response;
// buildHandshake() renders the request with CR/LF guards on every field.

#include "ws_probe.hpp"

#include <QByteArray>
#include <QCryptographicHash>

namespace Nullock::Core::WsProbe {

static const char *kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// RFC 6455: the server must echo base64(SHA1(key + GUID)).
QByteArray expectedAccept(const QByteArray &keyB64) {
    return QCryptographicHash::hash(keyB64 + kWsGuid, QCryptographicHash::Sha1).toBase64();
}

QString headerValue(const QByteArray &headerBlock, const char *name) {
    const QByteArray lower = headerBlock.toLower();
    // Match "\r\n<name>:" -- the leading CRLF means we only match a real header
    // line, never the status line at offset 0 (so no startsWith special-case is
    // needed), and the trailing ':' in the key prevents a prefix collision
    // (asking for "Sec-WebSocket-Accept" won't match "Sec-WebSocket-Accept-X:").
    const QByteArray key = QByteArray(name).toLower() + ":";
    const int i = lower.indexOf("\r\n" + key);
    if (i < 0) return QString();
    // Anchor the colon to the end of the matched name, not the next ':' in the
    // line -- so a value that itself contains a colon can't be misparsed.
    const int colon = i + 2 + static_cast<int>(qstrlen(name));
    const int eol = headerBlock.indexOf("\r\n", colon);
    return QString::fromLatin1(headerBlock.mid(colon + 1, (eol < 0 ? headerBlock.size() : eol) - colon - 1)).trimmed();
}

bool hasCredential(const QList<QPair<QString, QString>> &headers) {
    for (const auto &h : headers)
        if (h.first.compare("Cookie", Qt::CaseInsensitive) == 0
            || h.first.compare("Authorization", Qt::CaseInsensitive) == 0)
            return true;
    return false;
}

// Crafted Origins that defeat a naive host allow-list. Testing only one foreign
// sentinel (e.g. https://nullock-cswsh.test) and concluding "refused -> Origin
// validated" is a false negative against the common substring/affix checks; each
// variant here targets a specific buggy comparison (see the header).
QStringList originVariants(const QString &host) {
    QStringList out;
    if (host.isEmpty()) return out;
    out << QStringLiteral("https://attacker-cswsh.") + host         // endsWith(host): a subdomain
        << QStringLiteral("https://evil") + host                    // endsWith w/o dot anchor: sibling label
        << QStringLiteral("https://") + host + QStringLiteral(".attacker-cswsh.test")  // startsWith(host)
        << QStringLiteral("https://evil-") + host + QStringLiteral("-cswsh.test");     // contains(host)
    return out;
}

// Re-issuing an accepted cross-origin handshake with these stripped tells a
// session-gated socket (baseline now refused -> CONFIRMED hijack) apart from a
// session-blind public socket (baseline still 101 -> just Origin-not-validated).
QList<QPair<QString, QString>> stripCredentials(const QList<QPair<QString, QString>> &headers) {
    QList<QPair<QString, QString>> out;
    for (const auto &h : headers)
        if (h.first.compare("Cookie", Qt::CaseInsensitive) != 0
            && h.first.compare("Authorization", Qt::CaseInsensitive) != 0)
            out.append(h);
    return out;
}

// Parse the numeric status from the first line of a response header block.
int statusFromHeaderBlock(const QByteArray &headerBlock) {
    const int firstEol = headerBlock.indexOf("\r\n");
    const QByteArray statusLine = headerBlock.left(firstEol < 0 ? headerBlock.size() : firstEol);
    const int sp1 = statusLine.indexOf(' ');
    return sp1 < 0 ? 0 : statusLine.mid(sp1 + 1, 3).toInt();
}

// Render the upgrade request. `origin` empty -> omit Origin (control handshake).
// A CR/LF in basePath/host ABORTS (returns {}) -- a split request line/Host on a
// handshake is a framing hazard; the Origin and carried headers are guarded too.
QByteArray buildHandshake(const Request &req, const QString &origin, const QByteArray &key) {
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    QByteArray r;
    r  = "GET " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    r += "Host: " + req.host.toUtf8() + "\r\n";
    r += "Upgrade: websocket\r\n";
    r += "Connection: Upgrade\r\n";
    r += "Sec-WebSocket-Key: " + key + "\r\n";
    r += "Sec-WebSocket-Version: 13\r\n";
    if (!origin.isEmpty() && !origin.contains('\r') && !origin.contains('\n'))
        r += "Origin: " + origin.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Origin", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        r += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    r += "\r\n";
    return r;
}

} // namespace Nullock::Core::WsProbe

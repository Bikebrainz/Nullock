// Pure cookie-jar logic (see session_manager_logic.hpp). No I/O; Qt6::Core only.

#include "session_manager_logic.hpp"

#include <QStringList>

namespace Nullock::Core::SessionLogic {

QString stripCtrl(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        const ushort u = c.unicode();
        if (u == '\r' || u == '\n' || u == '\0') continue;
        if (u < 0x20) continue;     // other C0 controls
        out.append(c);
    }
    return out;
}

CapturedCookie parseSetCookie(const QString &raw) {
    CapturedCookie c;
    c.raw = stripCtrl(raw);
    // First "key=value" is the cookie itself; remaining "; attr[=val]" are attrs.
    const QStringList parts = c.raw.split(';');
    if (parts.isEmpty()) return c;
    const QString first = parts.first().trimmed();
    const int eq = first.indexOf('=');
    if (eq <= 0) return c;
    c.name  = stripCtrl(first.left(eq).trimmed());
    c.value = stripCtrl(first.mid(eq + 1).trimmed());
    // RFC 6265 token-ish: reject a name with '='/space/tab -- it would produce a
    // broken Cookie header on inject. (Control bytes were already stripped.)
    if (c.name.contains('=') || c.name.contains(' ') || c.name.contains('\t'))
        c.name.clear();
    for (int i = 1; i < parts.size(); ++i) {
        const QString seg = parts[i].trimmed();
        if (seg.isEmpty()) continue;
        const int eq2 = seg.indexOf('=');
        const QString key = (eq2 < 0 ? seg : seg.left(eq2)).trimmed().toLower();
        const QString val = eq2 < 0 ? QString() : seg.mid(eq2 + 1).trimmed();
        if      (key == "path")     c.path     = val;
        else if (key == "expires")  c.expires  = val;
        else if (key == "httponly") c.httpOnly = true;
        else if (key == "secure")   c.secure   = true;
        else if (key == "samesite") c.sameSite = val;
    }
    return c;
}

bool pathMatches(const QString &cookiePath, const QString &reqPath) {
    // An absent or relative cookie path scopes to "/" (matches everything).
    QString cp = cookiePath;
    if (cp.isEmpty() || !cp.startsWith('/')) cp = QStringLiteral("/");
    // Compare against the request path with any query/fragment removed.
    QString rp = reqPath.isEmpty() ? QStringLiteral("/") : reqPath;
    const int cut = rp.indexOf(QChar('?'));
    if (cut >= 0) rp = rp.left(cut);
    const int hash = rp.indexOf(QChar('#'));
    if (hash >= 0) rp = rp.left(hash);
    if (rp.isEmpty()) rp = QStringLiteral("/");

    if (cp == rp) return true;
    if (rp.startsWith(cp)) {
        if (cp.endsWith(QChar('/'))) return true;                       // cp is a directory prefix
        if (rp.size() > cp.size() && rp.at(cp.size()) == QChar('/')) return true;  // boundary at '/'
    }
    return false;
}

bool injectableOverTransport(const CapturedCookie &c, int port) {
    if (!c.secure) return true;     // a non-Secure cookie may ride any transport
    return port == 443;             // Secure: fail closed to the standard TLS port
}

} // namespace Nullock::Core::SessionLogic

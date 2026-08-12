// Pure cookie-jar logic (see session_manager_logic.hpp). No I/O; Qt6::Core only.

#include "session_manager_logic.hpp"

#include <QDateTime>
#include <QLocale>
#include <QRegularExpression>
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

// Trim ONLY the ASCII OWS (SP / HTAB). QString::trimmed() is Unicode-aware and also
// strips U+00A0 / U+0085 etc., which are legitimate BYTES of a cookie value -- doing
// so silently corrupts the token we replay and breaks the captured session.
static QString asciiTrimmed(const QString &s) {
    qsizetype b = 0, e = s.size();
    while (b < e && (s[b] == QLatin1Char(' ') || s[b] == QLatin1Char('\t'))) ++b;
    while (e > b && (s[e - 1] == QLatin1Char(' ') || s[e - 1] == QLatin1Char('\t'))) --e;
    return s.mid(b, e - b);
}

CapturedCookie parseSetCookie(const QString &raw) {
    CapturedCookie c;
    c.raw = stripCtrl(raw);
    // First "key=value" is the cookie itself; remaining "; attr[=val]" are attrs.
    const QStringList parts = c.raw.split(';');
    if (parts.isEmpty()) return c;
    const QString first = asciiTrimmed(parts.first());
    const int eq = first.indexOf('=');
    if (eq <= 0) return c;
    c.name  = stripCtrl(asciiTrimmed(first.left(eq)));
    c.value = stripCtrl(asciiTrimmed(first.mid(eq + 1)));
    // RFC 6265 token-ish: reject a name with '='/space -- it would produce a broken
    // Cookie header on inject.
    if (c.name.contains('=') || c.name.contains(' '))
        c.name.clear();
    // A CONTROL byte inside the name must DROP the cookie, not be silently spliced
    // out into a different, synthetic name: stripCtrl() runs first, so "a\tb=v" was
    // becoming a perfectly valid cookie named "ab" that the server never set (and the
    // contains('\t') arm above could never fire -- it was dead code). Check the
    // ORIGINAL text, ignoring the leading/trailing OWS that is legitimately allowed.
    {
        const QStringList rawParts = raw.split(';');
        const QString rawFirst = rawParts.isEmpty() ? QString() : rawParts.first();
        const int rawEq = rawFirst.indexOf('=');
        if (rawEq > 0) {
            const QString rawName = asciiTrimmed(rawFirst.left(rawEq));
            for (const QChar ch : rawName)
                if (ch.unicode() < 0x20) { c.name.clear(); break; }
        }
    }
    for (int i = 1; i < parts.size(); ++i) {
        const QString seg = asciiTrimmed(parts[i]);
        if (seg.isEmpty()) continue;
        const int eq2 = seg.indexOf('=');
        const QString key = asciiTrimmed(eq2 < 0 ? seg : seg.left(eq2)).toLower();
        const QString val = eq2 < 0 ? QString() : asciiTrimmed(seg.mid(eq2 + 1));
        if      (key == "path")     c.path     = val;
        else if (key == "expires")  c.expires  = val;
        else if (key == "max-age") {
            // RFC 6265 §5.2.2: Max-Age is delta-seconds (a possibly-negative
            // integer). A non-numeric / empty value is ignored (stays absent).
            bool ok = false;
            const long long ma = val.toLongLong(&ok);
            if (ok) c.maxAge = ma;
        }
        else if (key == "httponly") c.httpOnly = true;
        else if (key == "secure")   c.secure   = true;
        else if (key == "samesite") c.sameSite = val;
        else if (key == "domain") {
            // RFC 6265 5.2.3: a single leading '.' is ignored; the domain is
            // matched case-insensitively. (No longer dropped on the floor -- #194.)
            QString d = val.trimmed().toLower();
            if (d.startsWith(QLatin1Char('.'))) d = d.mid(1);
            c.domain = d;
        }
    }
    return c;
}

// RFC 3986 5.2.4 remove_dot_segments, preserving a trailing '/' (the directory-prefix
// rule below depends on it). Applied to the REQUEST path only: the server resolves
// "/admin/../public" to "/public", so matching it raw let a Path=/admin cookie ride a
// request that actually leaves that scope. (A cookie Path is used literally per RFC
// 6265, and leaving it un-normalized only ever fails CLOSED.)
static QString removeDotSegments(const QString &p) {
    const bool trailingSlash = p.endsWith(QLatin1Char('/'));
    QStringList out;
    for (const QString &s : p.split(QLatin1Char('/'))) {
        if (s.isEmpty() || s == QLatin1String(".")) continue;
        if (s == QLatin1String("..")) { if (!out.isEmpty()) out.removeLast(); continue; }
        out << s;
    }
    QString r = QLatin1Char('/') + out.join(QLatin1Char('/'));
    if (trailingSlash && !r.endsWith(QLatin1Char('/'))) r += QLatin1Char('/');
    return r;
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
    // Resolve dot-segments BEFORE matching: "/admin/../public" is really "/public",
    // so matching it raw over-injected a Path=/admin session cookie onto a request
    // that leaves that scope entirely.
    rp = removeDotSegments(rp);

    if (cp == rp) return true;
    if (rp.startsWith(cp)) {
        if (cp.endsWith(QChar('/'))) return true;                       // cp is a directory prefix
        if (rp.size() > cp.size() && rp.at(cp.size()) == QChar('/')) return true;  // boundary at '/'
    }
    return false;
}

bool domainMatches(const QString &cookieDomain, const QString &reqHost) {
    if (cookieDomain.isEmpty()) return false;          // host-only cookie: no Domain scope
    const QString cd = cookieDomain.toLower();
    const QString rh = reqHost.trimmed().toLower();
    if (rh.isEmpty()) return false;
    // A Domain cookie cannot broaden an IP-literal host -- IPs match only exactly.
    static const QRegularExpression ipv4(QStringLiteral("^(\\d{1,3}\\.){3}\\d{1,3}$"));
    if (ipv4.match(rh).hasMatch() || rh.contains(QLatin1Char(':')))
        return rh == cd;
    if (rh == cd) return true;
    // Subdomain: reqHost ends with "." + cookieDomain, so a real label boundary
    // separates them -- "evil-example.com" must NOT match "example.com".
    return rh.endsWith(QLatin1Char('.') + cd);
}

bool injectableOverTransport(const CapturedCookie &c, bool tls) {
    if (!c.secure) return true;     // a non-Secure cookie may ride any transport
    return tls;                     // Secure: only over an actual TLS connection --
                                    // a real transport check, not the old port==443
                                    // heuristic (which both leaked a Secure cookie
                                    // over cleartext on port 443 and refused it over
                                    // TLS on 8443). Fails closed: unknown transport
                                    // (tls=false) never injects a Secure cookie.
}

long long parseCookieExpires(const QString &httpDate) {
    const QString s = httpDate.trimmed();
    if (s.isEmpty()) return -1;
    // Qt's RFC 2822 parser handles the common Set-Cookie form incl. the obsolete
    // "GMT" zone; it resolves the zone itself, so convert to UTC for the epoch.
    QDateTime dt = QDateTime::fromString(s, Qt::RFC2822Date);
    if (dt.isValid()) return dt.toUTC().toSecsSinceEpoch();
    // Fallbacks: parse the wall-clock in the C locale (a non-English system
    // locale must not break month/day-name matching) and interpret it as UTC,
    // matching the literal 'GMT' these formats carry.
    static const char *kFmts[] = {
        "ddd, dd MMM yyyy hh:mm:ss 'GMT'",
        "ddd, dd-MMM-yyyy hh:mm:ss 'GMT'",   // '-'-separated variant
        "ddd MMM d hh:mm:ss yyyy",           // asctime() style (no zone)
    };
    for (const char *f : kFmts) {
        QDateTime local = QLocale::c().toDateTime(s, QString::fromLatin1(f));
        if (local.isValid()) {
            local.setTimeSpec(Qt::UTC);
            return local.toSecsSinceEpoch();
        }
    }
    return -1;
}

void resolveCookieExpiry(CapturedCookie &c, long long capturedAtEpoch) {
    c.persistent = false;
    c.expiresEpoch = 0;
    if (c.maxAge != kNoMaxAge) {
        // RFC 6265 §5.3: Max-Age takes precedence over Expires. Max-Age <= 0
        // yields an expiry at/before capture time (an immediate deletion).
        c.persistent = true;
        constexpr long long kMax = 9223372036854775807LL;
        c.expiresEpoch = (c.maxAge > 0 && capturedAtEpoch > kMax - c.maxAge)
                             ? kMax                          // clamp overflow -> far future
                             : capturedAtEpoch + c.maxAge;
        return;
    }
    if (!c.expires.isEmpty()) {
        const long long e = parseCookieExpires(c.expires);
        if (e >= 0) { c.persistent = true; c.expiresEpoch = e; }
    }
    // else: neither attribute -> a SESSION cookie (persistent stays false).
}

bool cookieExpired(const CapturedCookie &c, long long nowEpoch) {
    return c.persistent && nowEpoch >= c.expiresEpoch;
}

} // namespace Nullock::Core::SessionLogic

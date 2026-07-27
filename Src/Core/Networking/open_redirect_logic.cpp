// Pure, I/O-free helpers for the open-redirect probe: the sentinel host, the
// browser-style Location resolver, the client-side (meta-refresh / JS) redirect
// detector, and the CR/LF-guarded request builder. Kept in their OWN
// translation unit (separate from open_redirect.cpp's test(), which pulls
// HttpClient and the networking/GUI chain) so the unit test can link this logic
// against Qt6::Core alone.

#include "open_redirect.hpp"

#include <QRegularExpression>
#include <QStringList>

namespace Nullock::Core::OpenRedirect {

namespace {
const QString kSentinel = QStringLiteral("nullock-oob.test");
} // namespace

QString sentinelHost() { return kSentinel; }

bool isSentinelHost(const QString &host) {
    const QString h = host.toLower();
    return h == kSentinel || h.endsWith("." + kSentinel);
}

QStringList knownRedirectParams() {
    return { "url", "next", "redirect", "redirect_uri", "redirecturl", "return",
             "returnurl", "return_to", "returnto", "dest", "destination",
             "continue", "target", "to", "out", "view", "image_url", "go",
             "u", "r", "link", "checkout_url", "callback", "redir" };
}

// Resolve a redirect value against the request URL the way a browser would:
// backslashes count as slashes, and a "scheme:" with too few slashes
// ("https:/host", "https:host", "https:///host") is the browser-normalized
// "scheme://host". We only touch the authority/path head, never the
// query/fragment, so a backslash inside a same-origin query can't be twisted
// into an off-origin authority.
QString resolvedRedirectHost(const QUrl &base, QString loc) {
    if (loc.isEmpty()) return QString();
    const int cut = loc.indexOf(QRegularExpression(QStringLiteral("[?#]")));
    QString head = cut < 0 ? loc : loc.left(cut);
    const QString tail = cut < 0 ? QString() : loc.mid(cut);
    head.replace('\\', '/');
    static const QRegularExpression sch(QStringLiteral("^(https?):/*"),
                                        QRegularExpression::CaseInsensitiveOption);
    head.replace(sch, QStringLiteral("\\1://"));
    return base.resolved(QUrl(head.trimmed() + tail, QUrl::TolerantMode)).host();
}

// Pull every candidate redirect URL out of the body's client-side sinks and
// return the first whose resolved host is the sentinel. Anchored to REAL
// navigation structure -- an actual <meta http-equiv=refresh> tag, or a JS
// location.{href,replace,assign}=/( with a QUOTED string literal -- so a page
// that merely echoes a rejected payload as inert text (e.g. "invalid
// location=//nullock-oob.test") is never mistaken for a navigation. Each
// candidate is then RESOLVED (not substring-matched), which also covers
// scheme/slash-count confusion the same way the Location path does.
QString clientSideRedirectHost(const QByteArray &bodyBytes, const QUrl &base, QString *via) {
    const QString body = QString::fromUtf8(bodyBytes.left(256 * 1024));

    // (a) Real <meta http-equiv="refresh" ... content="...; url=TARGET">.
    static const QRegularExpression metaTag(
        QStringLiteral("<meta\\b[^>]*\\bhttp-equiv\\s*=\\s*[\"']?\\s*refresh\\b[^>]*>"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression urlInTag(
        QStringLiteral("\\burl\\s*=\\s*[\"']?\\s*([^\"'>\\s]+)"),
        QRegularExpression::CaseInsensitiveOption);
    auto mit = metaTag.globalMatch(body);
    while (mit.hasNext()) {
        const QString tag = mit.next().captured(0);
        const auto um = urlInTag.match(tag);
        if (!um.hasMatch()) continue;
        const QString host = resolvedRedirectHost(base, um.captured(1));
        if (isSentinelHost(host)) { if (via) *via = QStringLiteral("meta-refresh"); return host; }
    }

    // (b) JS location navigation with a quoted URL literal:
    //   [window.|document.|self.|top.|parent.]location[.href]= "URL"
    //   [...].location.(replace|assign)( "URL"
    // The mandatory quote is the key false-positive killer: a reflected payload
    // echoed as unquoted prose (location=//host) cannot match.
    static const QRegularExpression jsNav(
        QStringLiteral(
            "(?:\\b(?:window|self|top|parent|document)\\s*\\.\\s*)?"
            "\\blocation\\s*"
            "(?:\\.\\s*href\\s*=|\\.\\s*(?:replace|assign)\\s*\\(|=)"
            "\\s*[\"']([^\"']+)[\"']"),
        QRegularExpression::CaseInsensitiveOption);
    auto jit = jsNav.globalMatch(body);
    while (jit.hasNext()) {
        const QString url = jit.next().captured(1);
        const QString host = resolvedRedirectHost(base, url);
        if (isSentinelHost(host)) { if (via) *via = QStringLiteral("js-location"); return host; }
    }

    return QString();
}

// Build the raw GET, CR/LF-guarding the method/host/path (a tainted one aborts
// the request -> {}) and dropping any CR/LF-bearing header, matching the
// jwt_probe hardening pattern. The query arrives percent-encoded from the
// caller, so it is safe by construction.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    // The query is spliced into the SAME request line as basePath (target below).
    // The live caller pre-encodes it (FullyEncoded), but this public builder must
    // guard the query symmetrically with basePath -- else a CR/LF in it splits the
    // request line, whereas a tainted basePath correctly aborts. (Every sibling probe
    // now guards the query.)
    if (query.contains('\r') || query.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/open-redirect\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding: line 114 forces "identity" so the client-side
        // <meta>/JS redirect body scan sees PLAINTEXT; a surviving "gzip,.." lets the
        // server compress (client never inflates) -> a real body-based sentinel redirect
        // reads clean (vulnerable=false).
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::OpenRedirect

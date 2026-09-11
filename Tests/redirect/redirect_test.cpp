// Unit corpus for the pure redirect-following logic. Locks the decisions the
// Repeater/Intruder follow-loop makes: which statuses redirect, where a Location
// resolves, what method + body the follow-up uses, whether the policy permits it,
// and the cookie threading. A regression here would silently follow the wrong
// URL, leak a body across a method change, or carry cookies off-site.
//
// Run via:  ctest -R redirect -V

#include "redirect_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::RedirectLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using Hdrs = QList<QPair<QString, QString>>;
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseFollowPolicy / name =====================================
    chk("policy: never",   parseFollowPolicy("never")   == FollowNever);
    chk("policy: on-site", parseFollowPolicy("on-site") == FollowOnSite);
    chk("policy: in-scope",parseFollowPolicy("in-scope")== FollowInScope);
    chk("policy: always",  parseFollowPolicy("always")  == FollowAlways);
    chk("policy: unknown -> never", parseFollowPolicy("wat") == FollowNever);
    chk("policy: case-insensitive", parseFollowPolicy("ALWAYS") == FollowAlways);
    chk("policy: roundtrip name", followPolicyName(FollowInScope) == "in-scope");

    // ===== isRedirectStatus =============================================
    chk("status: 301/302/303/307/308 are redirects",
        isRedirectStatus(301) && isRedirectStatus(302) && isRedirectStatus(303)
        && isRedirectStatus(307) && isRedirectStatus(308));
    chk("status: 200 not a redirect", !isRedirectStatus(200));
    chk("status: 304 not a redirect (not-modified)", !isRedirectStatus(304));
    chk("status: 300 not followed (no single target)", !isRedirectStatus(300));

    // ===== resolveRedirect ==============================================
    {
        const QUrl cur("https://app.example.com/login?next=/home");
        chk("resolve: absolute URL",
            resolveRedirect(cur, "https://id.example.com/oauth") == QUrl("https://id.example.com/oauth"));
        chk("resolve: absolute path keeps host+scheme",
            resolveRedirect(cur, "/dashboard") == QUrl("https://app.example.com/dashboard"));
        chk("resolve: relative path is relative to the directory",
            resolveRedirect(cur, "step2") == QUrl("https://app.example.com/step2"));
        chk("resolve: protocol-relative keeps scheme",
            resolveRedirect(cur, "//cdn.example.com/x") == QUrl("https://cdn.example.com/x"));
        chk("resolve: empty Location -> empty", resolveRedirect(cur, "   ").isEmpty());
        chk("resolve: query preserved on absolute path",
            resolveRedirect(cur, "/a?b=1").query() == "b=1");
    }

    // ===== methodAfterRedirect ==========================================
    chk("method: 303 -> GET", methodAfterRedirect(303, "POST") == "GET");
    chk("method: 303 HEAD stays HEAD", methodAfterRedirect(303, "HEAD") == "HEAD");
    chk("method: 301 POST -> GET", methodAfterRedirect(301, "POST") == "GET");
    chk("method: 302 POST -> GET", methodAfterRedirect(302, "POST") == "GET");
    chk("method: 302 GET stays GET", methodAfterRedirect(302, "GET") == "GET");
    chk("method: 301 PUT preserved (only POST downgrades)", methodAfterRedirect(301, "PUT") == "PUT");
    chk("method: 307 POST preserved", methodAfterRedirect(307, "POST") == "POST");
    chk("method: 308 PUT preserved", methodAfterRedirect(308, "PUT") == "PUT");
    chk("method: case normalized to upper", methodAfterRedirect(307, "post") == "POST");

    // ===== redirectPreservesBody ========================================
    chk("body: 307 preserves", redirectPreservesBody(307));
    chk("body: 308 preserves", redirectPreservesBody(308));
    chk("body: 302 drops", !redirectPreservesBody(302));
    chk("body: 303 drops", !redirectPreservesBody(303));

    // ===== followAllowed ================================================
    chk("follow: never refuses even same host",
        !followAllowed(FollowNever, "a.com", "a.com", true));
    chk("follow: always allows off-site",
        followAllowed(FollowAlways, "a.com", "evil.com", false));
    chk("follow: on-site allows same host (case-insensitive)",
        followAllowed(FollowOnSite, "App.com", "app.com", false));
    chk("follow: on-site refuses different host",
        !followAllowed(FollowOnSite, "a.com", "b.com", true));
    chk("follow: in-scope defers to nextInScope=true",
        followAllowed(FollowInScope, "a.com", "b.com", true));
    chk("follow: in-scope refuses when not in scope",
        !followAllowed(FollowInScope, "a.com", "b.com", false));
    chk("follow: empty next host always refused",
        !followAllowed(FollowAlways, "a.com", "  ", true));

    // Real destination selection, including host-only cookies, duplicate paths,
    // secure downgrade, foreign Domain rejection and expiry/deletion.
    {
        CookieJar jar;
        const QUrl origin("https://app.example.com/login");
        seedRequestCookies(jar, origin, "GET / HTTP/1.1\r\nCookie: original=fixture\r\n\r\n");
        mergeSetCookies(jar, origin, Hdrs{{"set-cookie", "sid=root; Path=/"},
            {"Set-Cookie", "sid=private; Path=/private; Secure"},
            {"Set-Cookie", "bad=foreign; Domain=evil.test; Path=/"}});
        const auto same = renderCookieHeader(jar, QUrl("https://app.example.com/private/x"));
        chk("cookies: original retained at host", same.contains("original=fixture"));
        chk("cookies: both paths retained", same.contains("sid=root") && same.contains("sid=private"));
        chk("cookies: longer path first", same.indexOf("sid=private") < same.indexOf("sid=root"));
        chk("cookies: wrong path excluded", !renderCookieHeader(jar, origin).contains("sid=private"));
        chk("cookies: downgrade excludes secure", !renderCookieHeader(jar, QUrl("http://app.example.com/private")).contains("original="));
        chk("cookies: secure path cookie excluded on http", !renderCookieHeader(jar, QUrl("http://app.example.com/private")).contains("sid=private"));
        chk("cookies: foreign destination empty", renderCookieHeader(jar, QUrl("https://evil.test/private")).isEmpty());
        chk("cookies: host-only excludes subdomain", renderCookieHeader(jar, QUrl("https://sub.app.example.com/private")).isEmpty());
        mergeSetCookies(jar, origin, Hdrs{{"Set-Cookie", "sid=deleted; Path=/; Max-Age=0"}});
        chk("cookies: deletion honored", !renderCookieHeader(jar, origin).contains("sid="));
        mergeSetCookies(jar, origin, Hdrs{{"Set-Cookie", "domain=shared; Domain=example.com; Path=/"}});
        chk("cookies: explicit domain usable by sibling", renderCookieHeader(jar, QUrl("https://other.example.com/")).contains("domain=shared"));
    }
    chk("body: 302 PUT preserved", redirectPreservesBody(302, "PUT"));
    {
        const QUrl origin("https://a.test/start"), next("https://a.test/next");
        const QByteArray req = "POST /start HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\nAuthorization: Bearer fixture\r\nX-Api-Key: fixture\r\nConnection: x-hop\r\nX-Hop: removed\r\n\r\n{}";
        const auto same = buildFollowRequest(next, "POST", "", "{}", req, origin);
        chk("307: content type retained", same.contains("Content-Type: application/json\r\n"));
        chk("307: same-origin auth retained", same.contains("Authorization: Bearer fixture"));
        chk("307: connection-nominated header removed", !same.contains("X-Hop:"));
        const auto cross = buildFollowRequest(QUrl("https://b.test/"), "POST", "", "{}", req, origin);
        chk("cross origin: credentials removed", !cross.contains("Authorization:") && !cross.contains("X-Api-Key:"));
        chk("cross origin: entity retained", cross.contains("Content-Type: application/json") && cross.endsWith("{}"));
        const auto get = buildFollowRequest(next, "GET", "", {}, req, origin, false);
        chk("POST-to-GET: entity headers removed", !get.contains("Content-Type:") && !get.contains("Content-Length:"));
        chk("IPv6 authority bracketed", buildFollowRequest(QUrl("http://[::1]:8080/"), "GET", "").contains("Host: [::1]:8080"));
    }

    // ===== buildFollowRequest ===========================================
    {
        const QByteArray r = buildFollowRequest(QUrl("https://app.example.com/dash?q=1"), "GET", "sid=abc");
        const QString s = QString::fromUtf8(r);
        chk("build: request line with path+query",
            s.startsWith("GET /dash?q=1 HTTP/1.1\r\n"));
        chk("build: Host header (no default port)", s.contains("Host: app.example.com\r\n"));
        chk("build: Cookie header carried", s.contains("Cookie: sid=abc\r\n"));
        chk("build: terminates with blank line", s.endsWith("\r\n\r\n"));
        chk("build: no Content-Length on a bodyless GET", !s.contains("Content-Length"));
    }
    {
        const QByteArray r = buildFollowRequest(QUrl("http://h.test:8080/p"), "POST", "", "a=1&b=2");
        const QString s = QString::fromUtf8(r);
        chk("build: non-default port in Host", s.contains("Host: h.test:8080\r\n"));
        chk("build: Content-Length for a preserved body", s.contains("Content-Length: 7\r\n"));
        chk("build: body appended", s.endsWith("\r\n\r\na=1&b=2"));
    }
    {
        const QByteArray r = buildFollowRequest(QUrl("https://x.test"), "GET", "");
        chk("build: empty path -> '/'", QString::fromUtf8(r).startsWith("GET / HTTP/1.1\r\n"));
    }

    // ===== requestMethod / requestTarget / requestUrl ===================
    {
        const QByteArray req = "POST /login?x=1 HTTP/1.1\r\nHost: a.test\r\n\r\nu=admin";
        chk("parse: method", requestMethod(req) == "POST");
        chk("parse: method upper-cased", requestMethod("get / HTTP/1.1\r\n\r\n") == "GET");
        chk("parse: target with query", requestTarget(req) == "/login?x=1");
        chk("parse: malformed line -> empty method", requestMethod("garbage").isEmpty());
        const QUrl u = requestUrl(true, "a.test", 443, req);
        chk("parse: url scheme https", u.scheme() == "https");
        chk("parse: url host", u.host() == "a.test");
        chk("parse: url path", u.path() == "/login");
        chk("parse: url query", u.query() == "x=1");
        chk("parse: url default port omitted", u.port() == -1);
    }
    {
        const QUrl u = requestUrl(false, "h.test", 8080, "GET /p HTTP/1.1\r\n\r\n");
        chk("parse: non-default port kept", u.port() == 8080 && u.scheme() == "http");
    }

    std::fprintf(stderr, "redirect_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

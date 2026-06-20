// Regression corpus for the open-redirect probe's pure logic (no network):
//   - resolvedRedirectHost: browser-style resolution (backslashes, missing /
//     scheme slashes, triple-slash) AND the query-confusion FP guard (a
//     same-origin Location with the sentinel buried in its query must NOT
//     resolve to the sentinel).
//   - clientSideRedirectHost: the hardened client-side detector -- reflected
//     payload echoed as inert prose must NOT match (the headline FP); a real
//     <meta refresh> tag or a quoted JS location.{href,replace,assign} must;
//     location.assign and triple-slash (the FNs the audit found) now match.
//   - buildRequest: CR/LF guards on method/host/basePath (jwt_probe parity).
//
// Run via:  ctest -R open_redirect -V

#include "open_redirect.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QUrl>

#include <cstdio>

using namespace Nullock::Core::OpenRedirect;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QUrl mkBase() {
    QUrl b; b.setScheme("https"); b.setHost("trusted.example"); b.setPort(443); b.setPath("/account");
    return b;
}
const QString SENT = QStringLiteral("nullock-oob.test");
// Convenience: does the client-side detector resolve this body to the sentinel?
bool clientHits(const char *html) {
    return isSentinelHost(clientSideRedirectHost(QByteArray(html), mkBase(), nullptr));
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const QUrl base = mkBase();

    // ---- isSentinelHost --------------------------------------------------
    chk("sentinel: exact",        isSentinelHost(SENT));
    chk("sentinel: subdomain",    isSentinelHost("x." + SENT));
    chk("sentinel: suffix trick", !isSentinelHost(SENT + ".evil.com"));
    chk("sentinel: unrelated",    !isSentinelHost("trusted.example"));

    // ---- resolvedRedirectHost: browser-style off-origin resolution -------
    chk("resolve: absolute",       resolvedRedirectHost(base, "https://" + SENT) == SENT);
    chk("resolve: scheme-relative", resolvedRedirectHost(base, "//" + SENT) == SENT);
    chk("resolve: backslash",      resolvedRedirectHost(base, "\\\\" + SENT) == SENT);
    chk("resolve: slash-backslash", resolvedRedirectHost(base, "/\\" + SENT) == SENT);
    chk("resolve: missing-slash",  resolvedRedirectHost(base, "https:/" + SENT) == SENT);
    chk("resolve: no-slashes",     resolvedRedirectHost(base, "https:" + SENT) == SENT);
    chk("resolve: triple-slash",   resolvedRedirectHost(base, "https:///" + SENT) == SENT);
    chk("resolve: quad-slash",     resolvedRedirectHost(base, "https:////" + SENT) == SENT);
    chk("resolve: case-scheme",    resolvedRedirectHost(base, "HtTpS://" + SENT) == SENT);
    chk("resolve: query ignored",  resolvedRedirectHost(base, "https://" + SENT + "/p?x=1") == SENT);
    // FP guard: same-origin path with the sentinel only inside the query/fragment
    // must resolve to our OWN host, not the sentinel.
    chk("resolve: sentinel-in-query stays same-origin",
        resolvedRedirectHost(base, "/path?next=https://" + SENT) == "trusted.example");
    chk("resolve: sentinel-in-fragment stays same-origin",
        resolvedRedirectHost(base, "/path#https://" + SENT) == "trusted.example");
    chk("resolve: relative stays same-origin",
        resolvedRedirectHost(base, "/account") == "trusted.example");

    // ---- clientSideRedirectHost: FALSE-POSITIVE cases (must NOT match) ----
    // The headline FP: a rejected payload echoed as inert prose near "location".
    chk("client FP: unquoted prose 'location='",
        !clientHits("<html><body><p>Invalid location=//nullock-oob.test</p></body></html>"));
    chk("client FP: log echo",
        !clientHits("<pre>blocked attempt: location=https://nullock-oob.test</pre>"));
    chk("client FP: refresh prose without a <meta> tag",
        !clientHits("policy: http-equiv=refresh blocked; the url=//nullock-oob.test was denied"));
    chk("client FP: plain <a> link is not an auto-redirect",
        !clientHits("<a href=\"https://nullock-oob.test\">click</a>"));
    chk("client FP: geolocation (word-boundary)",
        !clientHits("<script>var geolocation=\"https://nullock-oob.test\";</script>"));
    chk("client FP: same-origin JS redirect",
        !clientHits("<script>location.href=\"/account\"</script>"));

    // ---- clientSideRedirectHost: TRUE-POSITIVE cases (must match) ---------
    chk("client TP: location.href",
        clientHits("<script>location.href=\"https://nullock-oob.test\"</script>"));
    chk("client TP: location.assign (FN fix)",
        clientHits("<script>location.assign(\"//nullock-oob.test\")</script>"));
    chk("client TP: window.location.replace",
        clientHits("<script>window.location.replace('https://nullock-oob.test')</script>"));
    chk("client TP: bare quoted location=",
        clientHits("<script>location=\"https://nullock-oob.test\"</script>"));
    chk("client TP: document.location.assign",
        clientHits("<script>document.location.assign(\"https://nullock-oob.test\")</script>"));
    chk("client TP: meta refresh",
        clientHits("<meta http-equiv=\"refresh\" content=\"0;url=https://nullock-oob.test\">"));
    chk("client TP: meta refresh single-quoted + triple slash (FN fix)",
        clientHits("<meta http-equiv='refresh' content='0; url=https:///nullock-oob.test'>"));

    QString via;
    clientSideRedirectHost(QByteArray("<meta http-equiv=\"refresh\" content=\"0;url=https://nullock-oob.test\">"), base, &via);
    chk("client: via meta-refresh", via == "meta-refresh");
    clientSideRedirectHost(QByteArray("<script>location.assign(\"https://nullock-oob.test\")</script>"), base, &via);
    chk("client: via js-location", via == "js-location");

    // ---- buildRequest: CR/LF guards (jwt_probe parity) -------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/r";
        const QByteArray ok = buildRequest(req, "url=x");
        chk("build: request line", ok.startsWith("GET /r?url=x HTTP/1.1\r\n"));
        chk("build: Host",         ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF header", !buildRequest(injHdr, "url=x").contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "url=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty",   buildRequest(badHost, "url=x").isEmpty());
        Request badPath = req; badPath.basePath = "/r\r\nX: y";
        chk("build: CRLF path -> empty",   buildRequest(badPath, "url=x").isEmpty());
    }

    std::fprintf(stderr, "open_redirect_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

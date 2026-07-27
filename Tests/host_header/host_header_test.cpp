// Regression corpus for the host-header probe's pure logic (no network):
//   - bodyHasUrl: the sentinel must sit as a real URL host -- scheme, quoted //,
//     or UNQUOTED attribute // (href=//s, the FN the audit found) -- but NOT a
//     bare // in a comment/JSON/prose (the FP the heuristic must avoid).
//   - locationIsUrl: a Location value is itself a URL, so bare //s counts.
//   - buildRequest: CR/LF guards on method/path/query/hostLine (the live
//     request-line injection the audit found) + carried-header dropping.
//
// Run via:  ctest -R host_header -V

#include "host_header.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::HostHeader;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const QString S = QStringLiteral("nullock-hhi-ab12cd34.test");
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- bodyHasUrl: true cases (sentinel is a real URL host) ------------
    chk("body: scheme URL",        bodyHasUrl("<a href=\"https://" + S + "/r\">x</a>", S));
    chk("body: quoted proto-rel",  bodyHasUrl("<a href=\"//" + S + "\">x</a>", S));
    chk("body: single-quoted",     bodyHasUrl("<a href='//" + S + "'>x</a>", S));
    chk("body: UNQUOTED attr (FN fix)", bodyHasUrl("<a href=//" + S + "/reset>x</a>", S));
    // ---- bodyHasUrl: false cases (bare reflection, not a URL) -------------
    chk("body: comment bare // (FP guard)", !bodyHasUrl("<!-- proxied via //" + S + " internal -->", S));
    chk("body: prose host (no URL)",        !bodyHasUrl("<p>requested host = " + S + "</p>", S));
    chk("body: absent",                     !bodyHasUrl("<p>nothing here</p>", S));

    // ---- locationIsUrl ---------------------------------------------------
    chk("loc: scheme",        locationIsUrl("https://" + S + "/welcome", S));
    chk("loc: bare proto-rel", locationIsUrl("//" + S + "/welcome", S));
    chk("loc: same-origin path (sentinel only in query) -> no",
        !locationIsUrl("/path?next=" + S, S));
    chk("loc: unrelated host -> no", !locationIsUrl("https://realhost/path", S));

    // ---- buildRequest: CR/LF guards (the live request-line injection) ----
    {
        Request req;
        req.method = "GET"; req.basePath = "/p"; req.query = "q=x";
        const QByteArray ok = buildRequest(req, "victim.tld", QString(), QString());
        chk("build: request line", ok.startsWith("GET /p?q=x HTTP/1.1\r\n"));
        chk("build: Host is hostLine", ok.contains("Host: victim.tld\r\n"));
        const QByteArray fwd = buildRequest(req, "victim.tld", "X-Forwarded-Host", S);
        chk("build: appends forwarding header", fwd.contains("X-Forwarded-Host: " + S.toUtf8() + "\r\n"));

        // A carried Host must be DROPPED: buildRequest emits its own Host: hostLine,
        // and a captured/HAR request commonly already carries a Host. Two Host lines
        // are an RFC-7230 violation (target 400s or front/back-end disagree, defeating
        // the probe). This dedup branch was untested.
        Request carriedHost = req;
        carriedHost.headers.append(qMakePair(QString("Host"), QString("original.example")));
        const QByteArray ch = buildRequest(carriedHost, "victim.tld", QString(), QString());
        chk("build: carried Host dropped -> exactly one Host line (victim.tld)",
            ch.count("Host: ") == 1 && ch.contains("Host: victim.tld\r\n") && !ch.contains("original.example"));

        // When we inject a forwarding header, a carried duplicate of the SAME name
        // must be dropped so the sentinel isn't fighting the real proxy value (a
        // target that honors the first/real value would defeat detection). Untested.
        Request carriedFwd = req;
        carriedFwd.headers.append(qMakePair(QString("X-Forwarded-Host"), QString("real-proxy.example")));
        const QByteArray cf = buildRequest(carriedFwd, "victim.tld", "X-Forwarded-Host", S);
        chk("build: carried forwarding header deduped -> sentinel wins, exactly once",
            cf.count("X-Forwarded-Host:") == 1
            && cf.contains("X-Forwarded-Host: " + S.toUtf8() + "\r\n")
            && !cf.contains("real-proxy.example"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "victim.tld", QString(), QString()).contains("X-Smuggled"));

        // webattack-01: this probe carries NO body, so a copied Content-Length /
        // Transfer-Encoding would strand the request (server waits for a body that
        // never comes) -- both must be dropped from the carried headers.
        Request carried = req;
        carried.headers.append(qMakePair(QString("Content-Length"), QString("123")));
        carried.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray cr = buildRequest(carried, "victim.tld", QString(), QString());
        chk("build: carried Content-Length dropped (bodyless probe won't strand)", !cr.contains("Content-Length"));
        chk("build: carried Transfer-Encoding dropped", !cr.contains("Transfer-Encoding"));

        // A carried Accept-Encoding must be dropped so line 44's forced "identity"
        // stands alone -- else the server gzips and the sentinel body-URL scan
        // (bodyHasUrl) runs on compressed bytes, missing a real //sentinel reflection
        // (host-header injection reported CLEAN). Sibling to the CL/TE drops above.
        Request carriedAE = req;
        carriedAE.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray ae = buildRequest(carriedAE, "victim.tld", QString(), QString());
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            ae.count("Accept-Encoding:") == 1
            && ae.contains("Accept-Encoding: identity\r\n") && !ae.contains("gzip"));

        Request badMethod = req; badMethod.method = "GET\r\nX-Injected: 1";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "victim.tld", QString(), QString()).isEmpty());
        Request badPath = req; badPath.basePath = "/p\r\nX: y";
        chk("build: CRLF path -> empty",   buildRequest(badPath, "victim.tld", QString(), QString()).isEmpty());
        Request badQuery = req; badQuery.query = "q=x\r\nX: y";
        chk("build: CRLF query -> empty",  buildRequest(badQuery, "victim.tld", QString(), QString()).isEmpty());
        chk("build: CRLF hostLine -> empty", buildRequest(req, "victim.tld\r\nX: y", QString(), QString()).isEmpty());
    }

    std::fprintf(stderr, "host_header_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

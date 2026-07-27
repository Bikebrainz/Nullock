// Regression corpus for the LDAP injection probe's pure logic (no network):
//   - matchError: engine-specific + generic LDAP error signatures; the bare
//     "LDAP error" alternative was REMOVED (matched WAF block pages -- the
//     audit's FP), and "search filter is invalid" (AD wording) was ADDED.
//   - isBlockStatus: the block-ish statuses a generic-only match is rejected on.
//   - buildRequest: CR/LF guards on method/host/path.
//
// Run via:  ctest -R ldap_injection -V

#include "ldap_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::LdapInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString eng(const char *body) { return matchError(QByteArray(body)).first; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- matchError: engine-specific (trusted on any status) -------------
    chk("sig: Java/JNDI", eng("x javax.naming.directory.InvalidSearchFilterException y") == "Java/JNDI");
    chk("sig: .NET",      eng("System.DirectoryServices.DirectoryServicesCOMException") == ".NET");
    chk("sig: PHP",       eng("Warning: ldap_search(): bad filter") == "PHP");
    chk("sig: Python",    eng("ldap.FILTER_ERROR: bad search filter") == "Python");
    // ---- matchError: generic (gated by status elsewhere) -----------------
    chk("sig: generic Bad search filter", eng("Bad search filter") == "generic");
    chk("sig: generic AD wording (added)", eng("The search filter is invalid.") == "generic");
    chk("sig: generic LDAP: error code",  eng("LDAP: error code 53 - unwilling") == "generic");
    // ---- matchError: the REMOVED bare "LDAP error" no longer matches ------
    chk("sig: bare 'LDAP error' -> NO match (FP fix)", eng("Request blocked: LDAP error detected").isEmpty());
    chk("sig: unrelated -> no match", eng("<html>0 results</html>").isEmpty());

    // ---- isBlockStatus ---------------------------------------------------
    chk("block: 403", isBlockStatus(403));
    chk("block: 406", isBlockStatus(406));
    chk("block: 429", isBlockStatus(429));
    chk("block: 503", isBlockStatus(503));
    chk("block: 200 not", !isBlockStatus(200));
    chk("block: 500 not (real backend error)", !isBlockStatus(500));
    chk("block: 404 not", !isBlockStatus(404));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/search";
        const QByteArray ok = buildRequest(req, "q=x");
        chk("build: request line", ok.startsWith("GET /search?q=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "q=x").contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "q=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "q=x").isEmpty());
        Request badPath = req; badPath.basePath = "/search\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "q=x").isEmpty());
        // audit-5: the query is spliced into the request line -> guard it too.
        chk("build: CRLF query -> empty", buildRequest(req, "q=x\r\nEvil: 1").isEmpty());
        // A carried Accept-Encoding must be dropped so only the forced "identity"
        // survives -- else the server may gzip and matchError scans compressed bytes,
        // missing the LDAP error fingerprint (false clean).
        Request ae = req;
        ae.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray aeb = buildRequest(ae, "q=x");
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            aeb.count("Accept-Encoding:") == 1
            && aeb.contains("Accept-Encoding: identity\r\n") && !aeb.contains("gzip"));
    }

    std::fprintf(stderr, "ldap_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

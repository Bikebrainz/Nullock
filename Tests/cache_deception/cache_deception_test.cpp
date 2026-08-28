// Regression corpus for the cache-deception probe's pure logic (no network):
//   - isCatchAll: the inert-control decision that suppresses catch-all / SPA
//     false positives (a bogus base also serving a length-similar 2xx).
//   - lenSimilar: the tightened body-length similarity test.
//   - buildGet: CR/LF guards on host / path / carried headers.
//   - randTok: sentinel shape.
//
// Run via:  ctest -R cache_deception -V

#include "cache_deception.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::CacheDeception;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- isCatchAll: the FP-suppression core ----------------------------
    // Bogus base ALSO returns a length-similar 2xx -> catch-all -> suppress.
    chk("catchAll: bogus 200 length-similar -> true",
        isCatchAll(/*ok*/true, /*status*/200, /*ctrlLen*/5000, /*baseLen*/5000));
    chk("catchAll: bogus 200 near length -> true",
        isCatchAll(true, 200, 5010, 5000));
    // Bogus base 404s -> NOT catch-all -> a real /<path>/x.css hit is meaningful.
    chk("catchAll: bogus 404 -> false (real deception possible)",
        !isCatchAll(true, 404, 80, 5000));
    chk("catchAll: bogus 200 but very different length -> false",
        !isCatchAll(true, 200, 200, 5000));
    chk("catchAll: control request failed -> false",
        !isCatchAll(false, 0, 0, 5000));
    chk("catchAll: bogus 301 redirect -> false",
        !isCatchAll(true, 301, 5000, 5000));

    // ---- lenSimilar: tightened threshold --------------------------------
    chk("len: identical", lenSimilar(5000, 5000));
    chk("len: small drift within 16 bytes", lenSimilar(5000, 5012));
    chk("len: <5% relative on large page", lenSimilar(10000, 9600));
    chk("len: >5% relative -> not similar", !lenSimilar(10000, 9000));
    // Two coincidentally-near short pages must NOT match (old 40-byte floor bug).
    chk("len: short pages 30 apart -> not similar (FP fix)", !lenSimilar(300, 330));
    chk("len: short pages within 16 -> similar", lenSimilar(300, 312));

    // ---- buildGet: CR/LF guards -----------------------------------------
    {
        Request req;
        req.host = "victim.tld";
        const QByteArray ok = buildGet(req, "/account/nlk123.css");
        chk("build: request line", ok.startsWith("GET /account/nlk123.css HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header",
            !buildGet(injHdr, "/account").contains("X-Smuggled"));

        // webattack-02: body-less GET probe -- a carried Content-Length /
        // Transfer-Encoding from the original request would strand it, so both
        // must be dropped.
        Request carried = req;
        carried.headers.append(qMakePair(QString("Content-Length"), QString("500")));
        carried.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray cg = buildGet(carried, "/account");
        chk("build: carried Content-Length dropped (GET probe)", !cg.contains("Content-Length"));
        chk("build: carried Transfer-Encoding dropped", !cg.contains("Transfer-Encoding"));

        // A carried Host must be dropped: buildGet emits its own Host, and a captured/
        // HAR request always carries a Host. Two Host lines (RFC-7230 violation) make
        // the target 400 or mis-route the probe -> a real cache-deception finding turns
        // into a silent false negative. This dedup branch (the most common carried
        // header) was untested while CL/TE drops were.
        Request carriedHost = req;
        carriedHost.headers.append(qMakePair(QString("Host"), QString("attacker.tld")));
        const QByteArray chg = buildGet(carriedHost, "/account");
        chk("build: carried Host dropped -> exactly one Host line (victim.tld)",
            chg.count("Host:") == 1 && chg.contains("Host: victim.tld\r\n") && !chg.contains("attacker.tld"));

        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildGet(badHost, "/account").isEmpty());
        chk("build: CRLF path -> empty",
            buildGet(req, "/account\r\nX-Smuggled: 1").isEmpty());
        // The guard is `contains('\r') || contains('\n')` but every bad case above
        // carries BOTH chars, leaving the LF half unpinned -- a bare LF still splits
        // a request line on lenient parsers.
        chk("build: bare-LF path -> empty", buildGet(req, "/account\nX-Smuggled2: 1").isEmpty());

        // A carried Accept-Encoding must be dropped so line 48's forced "identity"
        // stands alone -- else the server gzips, the body-length similarity compares
        // compressed sizes, and two conflicting Accept-Encoding lines can 400 the
        // probe. Mirrors the Host/CL/TE drops.
        Request carriedAE = req;
        carriedAE.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray aeg = buildGet(carriedAE, "/account");
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            aeg.count("Accept-Encoding:") == 1
            && aeg.contains("Accept-Encoding: identity\r\n") && !aeg.contains("gzip"));

        // CR/LF in the header NAME (not just the value) must also be dropped, else
        // "X-Evil\r\nX-Smuggled: 1" splices a second header line. The value case is
        // covered above; the crlf(h.first) name branch was not.
        Request injName = req;
        injName.headers.append(qMakePair(QString("X-Evil\r\nX-Smuggled: 1"), QString("v")));
        chk("build: drops CRLF header NAME", !buildGet(injName, "/account").contains("X-Smuggled"));
    }

    // ---- randTok --------------------------------------------------------
    {
        const QString t = randTok();
        chk("tok: nlk prefix + 9 chars", t.startsWith("nlk") && t.size() == 9);
    }

    std::fprintf(stderr, "cache_deception_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

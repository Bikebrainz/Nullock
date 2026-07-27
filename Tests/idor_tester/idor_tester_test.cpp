// Regression corpus for the IDOR/BOLA probe's pure logic (no network):
//   - controlUsable: the fail-closed gate (a failed discriminator -> skip).
//   - isAccessible: the enumeration-lead classification.
//   - formatId / neighbors: zero-padding preservation (/doc/00042 -> 00043).
//   - withMutatedId: id substitution in path segments and query params.
//   - buildRequest: CR/LF guards on method / host / path / carried headers.
//   - id recognition: looksLikeIdParam / looksLikeNonIdSegment / isNumeric.
//
// Run via:  ctest -R idor_tester -V

#include "idor_tester.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::IdorTester;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- controlUsable: fail-closed gate --------------------------------
    chk("control: usable when len>=0", controlUsable(0) && controlUsable(2048));
    chk("control: failed (len<0) -> NOT usable (fail-closed fix)", !controlUsable(-1));

    // ---- isAccessible: enumeration-lead classification ------------------
    chk("access: 2xx + distinct + not-mine -> lead", isAccessible(200, true, true));
    chk("access: not 2xx -> no", !isAccessible(404, true, true));
    chk("access: 3xx -> no", !isAccessible(302, true, true));
    chk("access: matches not-found template -> no", !isAccessible(200, false, true));
    chk("access: identical to own object -> no", !isAccessible(200, true, false));

    // ---- formatId / neighbors: zero-padding preservation ----------------
    chk("pad: plain id not padded", formatId(43, "42") == "43");
    chk("pad: zero-padded width preserved", formatId(43, "00042") == "00043");
    chk("pad: zero-padded carries to neighbor 41", formatId(41, "00042") == "00041");
    chk("pad: huge control id keeps full width (no truncation)",
        formatId(1000000049LL, "00042") == "1000000049");
    {
        const QStringList nb = neighbors("00042", 42, 6);
        chk("neighbors: padded set includes 00043 / 00041",
            nb.contains("00043") && nb.contains("00041"));
        chk("neighbors: none unpadded", !nb.contains("43") && !nb.contains("41"));
        const QStringList plain = neighbors("100", 100, 4);
        chk("neighbors: plain set 101/99", plain.contains("101") && plain.contains("99"));
    }

    // ---- withMutatedId --------------------------------------------------
    {
        IdLocation pseg; pseg.kind = IdLocation::PathSegment; pseg.segIndex = 3; pseg.originalValue = "1043";
        chk("mutate: path segment", withMutatedId("/api/orders/1043", pseg, "1044") == "/api/orders/1044");

        IdLocation qp; qp.kind = IdLocation::QueryParam; qp.paramName = "id"; qp.originalValue = "7";
        chk("mutate: query param replaced", withMutatedId("/view?id=7&t=x", qp, "8") == "/view?id=8&t=x");
        chk("mutate: other params preserved", withMutatedId("/view?id=7&t=x", qp, "8").contains("t=x"));
    }

    // ---- id recognition -------------------------------------------------
    chk("idparam: 'user_id' yes", looksLikeIdParam("user_id"));
    chk("idparam: 'orderId' yes (camelCase, capital-I suffix)", looksLikeIdParam("orderId"));
    chk("idparam: 'page' no", !looksLikeIdParam("page"));
    // The ".*Id" alternative must be CASE-SENSITIVE: a benign word merely ending in
    // the letters i,d ("grid"/"valid") is NOT an object id and must not trip IDOR
    // replays. (Before the (?-i:) fix, CaseInsensitiveOption made ".*Id" match these.)
    chk("idparam: 'grid' no (not a trailing-'Id' object id)", !looksLikeIdParam("grid"));
    chk("idparam: 'valid' no", !looksLikeIdParam("valid"));
    chk("idparam: 'hybrid' no", !looksLikeIdParam("hybrid"));
    // Snake_case and the capital-I camelCase forms still match (no regression).
    chk("idparam: 'USER_ID' yes (case-insensitive snake_case)", looksLikeIdParam("USER_ID"));
    chk("nonidseg: under /v1/ suppressed", looksLikeNonIdSegment("2", "v1"));
    chk("nonidseg: under /api/ suppressed", looksLikeNonIdSegment("3", "api"));
    chk("nonidseg: /orders/2024 still tested", !looksLikeNonIdSegment("2024", "orders"));
    chk("numeric: digits", isNumeric("00042") && isNumeric("7"));
    chk("numeric: non-digit rejected", !isNumeric("7a") && !isNumeric(""));
    chk("numeric: >18 digits rejected", !isNumeric("1234567890123456789"));

    // ---- buildRequest: CR/LF guards (the headline correctness fix) -------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET";
        const QByteArray ok = buildRequest(req, "/api/orders/1044");
        chk("build: request line", ok.startsWith("GET /api/orders/1044 HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header",
            !buildRequest(injHdr, "/x").contains("X-Smuggled"));

        // A carried Accept-Encoding must be dropped so ONLY our "identity" survives:
        // two Accept-Encoding lines combine (RFC 7230) to let the server gzip, and
        // the client doesn't inflate, so the length-based discriminator would run on
        // compressed noise. Exactly one Accept-Encoding line, == identity.
        Request aeReq = req;
        aeReq.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray ae = buildRequest(aeReq, "/api/orders/1043");
        chk("build: carried Accept-Encoding dropped -> exactly one, identity (length invariant)",
            ae.count("Accept-Encoding:") == 1
            && ae.contains("Accept-Encoding: identity\r\n") && !ae.contains("gzip"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "/x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "/x").isEmpty());
        chk("build: CRLF path -> empty", buildRequest(req, "/x\r\nX-Smuggled: 1").isEmpty());
    }

    std::fprintf(stderr, "idor_tester_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

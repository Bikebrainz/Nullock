// Regression corpus for the prototype-pollution probe's pure logic (no network):
//   - indentedByN: the structural exactly-N-space anchor (no run-of-spaces or
//     in-string-value false positive; LF and CRLF).
//   - looksJsonObject: leading-{ sniff.
//   - encodingUnreadable: the compressed-body inconclusive gate.
//   - buildGet / buildPollute: CR/LF guards on host and path; cache-buster.
//
// Run via:  ctest -R proto_pollution -V

#include "proto_pollution.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::ProtoPollution;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- indentedByN: structural exactly-7 anchor -----------------------
    chk("indent: 7-space LF top-level -> yes",
        indentedByN(QByteArray("{\n       \"a\":1}"), 7));
    chk("indent: 7-space CRLF top-level -> yes",
        indentedByN(QByteArray("{\r\n       \"b\":2}"), 7));
    chk("indent: compact -> no", !indentedByN(QByteArray("{\"a\":1}"), 7));
    chk("indent: 2-space (dev default) -> no",
        !indentedByN(QByteArray("{\n  \"a\":1}"), 7));
    chk("indent: 14-space (nested deeper level) at root -> no",
        !indentedByN(QByteArray("{\n              \"a\":1}"), 7));
    // A run of 7 spaces inside a string value must NOT match (no { newline anchor).
    chk("indent: 7 spaces inside a value -> no (FP guard)",
        !indentedByN(QByteArray("{\"note\":\"a       b\"}"), 7));

    // ---- looksJsonObject ------------------------------------------------
    chk("json: leading brace", looksJsonObject(QByteArray("  \n {\"a\":1}")));
    chk("json: array -> not an object", !looksJsonObject(QByteArray("[1,2]")));
    chk("json: html -> no", !looksJsonObject(QByteArray("<html>")));

    // ---- encodingUnreadable ---------------------------------------------
    chk("enc: gzip -> unreadable", encodingUnreadable("gzip"));
    chk("enc: br -> unreadable", encodingUnreadable(" BR "));
    chk("enc: identity -> readable", !encodingUnreadable("identity"));
    chk("enc: empty -> readable", !encodingUnreadable(""));

    // ---- withBuster -----------------------------------------------------
    chk("buster: adds __nlcb to empty query", withBuster(QString()).contains("__nlcb="));
    {
        const QString q = withBuster("a=1");
        chk("buster: preserves existing param", q.contains("a=1") && q.contains("__nlcb="));
    }

    // ---- buildGet / buildPollute: CR/LF guards --------------------------
    {
        Request req;
        req.host = "victim.tld";
        const QByteArray g = buildGet(req, "/api/me", QString());
        chk("get: request line + buster", g.startsWith("GET /api/me?__nlcb=") && g.contains(" HTTP/1.1\r\n"));
        chk("get: Host", g.contains("Host: victim.tld\r\n"));
        chk("get: identity encoding", g.contains("Accept-Encoding: identity\r\n"));

        const QByteArray body = "{\"__proto__\":{\"json spaces\":7}}";
        const QByteArray p = buildPollute(req, "/api/merge", body);
        chk("pollute: POST line", p.startsWith("POST /api/merge HTTP/1.1\r\n"));
        chk("pollute: Content-Type json", p.contains("Content-Type: application/json\r\n"));
        chk("pollute: Content-Length + body", p.contains("Content-Length: " + QByteArray::number(body.size()) + "\r\n") && p.endsWith(body));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("get: drops CRLF carried header",
            !buildGet(injHdr, "/api/me", QString()).contains("X-Smuggled"));

        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("get: CRLF host -> empty", buildGet(badHost, "/api/me", QString()).isEmpty());
        chk("pollute: CRLF host -> empty", buildPollute(badHost, "/api/merge", body).isEmpty());
        chk("get: CRLF path -> empty", buildGet(req, "/api\r\nX: y", QString()).isEmpty());
        chk("pollute: CRLF path -> empty", buildPollute(req, "/api\r\nX: y", body).isEmpty());

        // A carried Host / Content-Length must be dropped: buildPollute emits its
        // own computed Content-Length (and writeHeaders its own Host), so a carried
        // duplicate would produce two framing headers -> request smuggling/desync
        // against the merge endpoint. Only the Cookie-CRLF drop was exercised.
        Request dupFraming = req;
        dupFraming.headers.append(qMakePair(QString("Content-Length"), QString("999")));
        dupFraming.headers.append(qMakePair(QString("Host"), QString("evil.tld")));
        const QByteArray pd = buildPollute(dupFraming, "/api/merge", body);
        chk("pollute: carried Content-Length dropped -> exactly the computed one (no desync)",
            pd.count("Content-Length:") == 1
            && pd.contains("Content-Length: " + QByteArray::number(body.size()) + "\r\n")
            && !pd.contains("Content-Length: 999"));
        chk("pollute: carried Host dropped -> exactly one Host (framework's own)",
            pd.count("Host:") == 1 && pd.contains("Host: victim.tld\r\n") && !pd.contains("evil.tld"));

        // A carried Accept-Encoding must be dropped so writeHeaders' forced "identity"
        // stands alone -- else the server gzips the observation body, encodingUnreadable()
        // flags it, and test() bails vulnerable=false on a truly pollutable server.
        Request aeReq = req;
        aeReq.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray g2 = buildGet(aeReq, "/api/me", QString());
        chk("get: carried Accept-Encoding dropped -> exactly one, identity",
            g2.count("Accept-Encoding:") == 1
            && g2.contains("Accept-Encoding: identity\r\n") && !g2.contains("gzip"));

        // A carried Transfer-Encoding must be dropped: on buildPollute it would coexist
        // with the computed Content-Length -> a CL.TE-ambiguous request an intermediary
        // can desync (smuggling on the exact prototype-pollution write endpoint).
        Request teReq = req;
        teReq.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray p2 = buildPollute(teReq, "/api/merge", body);
        chk("pollute: carried Transfer-Encoding dropped -> only the computed Content-Length",
            !p2.contains("Transfer-Encoding") && p2.count("Content-Length:") == 1);
    }

    std::fprintf(stderr, "proto_pollution_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

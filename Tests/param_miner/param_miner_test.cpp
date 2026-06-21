// Regression corpus for the parameter-mining probe's pure logic (no network):
//   - statusFlipConfirmed: the re-confirmation that defeats a transient flap
//     mis-attributed to a random wordlist name (FP fix).
//   - canaryReflected: reflection in the body OR a response header (FN fix).
//   - buildRequest: CR/LF guards + no duplicate Content-Type/Content-Length.
//   - canaryFor: shape/uniqueness.
//
// Run via:  ctest -R param_miner -V

#include "param_miner.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::ParamMiner;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using HH = QList<QPair<QString, QString>>;
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- statusFlipConfirmed: the FP fix (flip must reproduce, no drift) -
    // (firstStatus, reBaselineStatus, reSendStatus, baseStatus)
    chk("flip: reproduced + baseline stable -> confirmed",
        statusFlipConfirmed(500, 200, 500, 200));
    chk("flip: did NOT reproduce on re-send -> rejected (transient flap)",
        !statusFlipConfirmed(500, 200, 200, 200));
    chk("flip: baseline drifted to the 'flip' value -> rejected (drift)",
        !statusFlipConfirmed(500, 500, 500, 200));
    chk("flip: first didn't flip -> rejected",
        !statusFlipConfirmed(200, 200, 500, 200));

    // ---- canaryReflected: body OR header (FN fix) -----------------------
    chk("reflect: in body", canaryReflected(QByteArray("<p>qm5zabcdef</p>"), {}, "qm5zabcdef"));
    chk("reflect: in a response header value",
        canaryReflected(QByteArray("ok"), HH{{"Set-Cookie", "last=qm5zabcdef"}}, "qm5zabcdef"));
    chk("reflect: in Location header",
        canaryReflected(QByteArray("ok"), HH{{"Location", "/x?r=qm5zabcdef"}}, "qm5zabcdef"));
    chk("reflect: absent -> false",
        !canaryReflected(QByteArray("nothing"), HH{{"Server", "nginx"}}, "qm5zabcdef"));

    // ---- canaryFor ------------------------------------------------------
    {
        const QString a = canaryFor(0), b = canaryFor(1);
        chk("canary: qm prefix + index", a.startsWith("qm0z") && b.startsWith("qm1z"));
        chk("canary: distinct", a != b);
    }

    // ---- buildRequest: CR/LF guards + framing ---------------------------
    {
        Request req; req.host = "victim.tld"; req.method = "GET"; req.basePath = "/api";
        const QByteArray g = buildRequest(req, {{ "debug", "qm0zaa" }});
        chk("build: GET appends query", g.startsWith("GET /api?debug=qm0zaa HTTP/1.1\r\n"));
        chk("build: Host", g.contains("Host: victim.tld\r\n"));

        Request post = req; post.method = "POST";
        const QByteArray p = buildRequest(post, {{ "x", "qm0zaa" }});
        chk("build: POST body + framing",
            p.contains("Content-Type: application/x-www-form-urlencoded\r\n")
            && p.contains("Content-Length: 8\r\n") && p.endsWith("x=qm0zaa"));

        // duplicate-header fix: a carried Content-Type/Length must be dropped
        Request dup = post;
        dup.headers.append(qMakePair(QString("Content-Type"), QString("application/json")));
        dup.headers.append(qMakePair(QString("Content-Length"), QString("999")));
        const QByteArray d = buildRequest(dup, {{ "x", "qm0zaa" }});
        chk("build: drops carried Content-Type (no dup)",
            d.count("Content-Type:") == 1 && !d.contains("application/json"));
        chk("build: drops carried Content-Length (no dup)", d.count("Content-Length:") == 1);

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Tok"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, {}).contains("X-Smuggled"));
        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, {}).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, {}).isEmpty());
        Request badPath = req; badPath.basePath = "/api\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, {}).isEmpty());
    }

    std::fprintf(stderr, "param_miner_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Regression corpus for the NoSQL injection probe's pure logic (no network):
//   - confirmsInjection: the 2x2 differential -- the two always-true operators
//     ($ne, $gt) must agree (over-match) while $eq tracks the literal, so a
//     validator/router/redirect keyed on the "$ne" NAME (the audit's FP class)
//     and a 200-with-different-body auth bypass (a latent FN) are both handled.
//   - lenDiffers/lenSimilar: the length-divergence partition.
//   - buildRequest: CR/LF guards on method/host/path.
//
// Run via:  ctest -R nosql_injection -V

#include "nosql_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::NoSqlInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// confirmsInjection(litLen,litStatus, eqLen,eqStatus, neLen,neStatus, gtLen,gtStatus)
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- lenDiffers / lenSimilar ----------------------------------------
    chk("len: 520 vs 1000 differs", lenDiffers(520, 1000));
    chk("len: 520 vs 520 similar",  lenSimilar(520, 520));
    chk("len: 520 vs 530 similar (<40)", lenSimilar(520, 530));
    chk("len: 100 vs 200 differs",  lenDiffers(100, 200));
    chk("len: 1000 vs 1030 similar (ratio)", lenSimilar(1000, 1030));

    // ---- confirmsInjection: TRUE-POSITIVES -------------------------------
    // Real over-match: $ne/$gt large & agree; $eq/literal small & agree; differ.
    chk("confirm: classic over-match",
        confirmsInjection(520,200, 520,200, 1000,200, 1000,200));
    // Auth bypass returning 200-with-different-body (length-only test missed this):
    // $ne/$gt = "welcome" (short, agree); $eq/literal = "invalid" (long, agree).
    chk("confirm: auth 200-both differing body",
        confirmsInjection(800,200, 800,200, 300,200, 300,200));

    // ---- confirmsInjection: FALSE-POSITIVES the 2x2 must REJECT -----------
    // Validator keyed on the "$ne" NAME only: $ne diverges (200 verbose page) but
    // $gt is untouched (tracks literal) -> the always-true ops DISAGREE.
    chk("confirm: $ne-name-deny (gt untouched) -> NO",
        !confirmsInjection(520,200, 520,200, 1000,200, 520,200));
    // Validator on ALL operators: $ne & $gt diverge, but $eq diverges too ->
    // $eq no longer tracks the literal.
    chk("confirm: all-ops-deny ($eq also diverges) -> NO",
        !confirmsInjection(520,200, 1000,200, 1000,200, 1000,200));
    // Redirect on $ne only: $ne flips to 302, $gt stays 200 -> ops disagree.
    chk("confirm: redirect-on-$ne (status flip) -> NO",
        !confirmsInjection(520,200, 520,200, 0,302, 520,200));
    // Type confusion: $ne errors (5xx) over an OK literal -> object rejection.
    chk("confirm: $ne 5xx over ok literal -> NO",
        !confirmsInjection(520,200, 520,200, 300,500, 1000,200));
    // Per-request jitter: $ne happens large but $gt (second sample) does not.
    chk("confirm: jitter ($gt disagrees) -> NO",
        !confirmsInjection(520,200, 520,200, 900,200, 520,200));
    // No injection: everything tracks -> groups don't differ.
    chk("confirm: no injection (all same) -> NO",
        !confirmsInjection(520,200, 520,200, 520,200, 520,200));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/api";
        const QByteArray ok = buildRequest(req, "q=x");
        chk("build: request line", ok.startsWith("GET /api?q=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "q=x").contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "q=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "q=x").isEmpty());
        Request badPath = req; badPath.basePath = "/api\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "q=x").isEmpty());
    }

    std::fprintf(stderr, "nosql_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

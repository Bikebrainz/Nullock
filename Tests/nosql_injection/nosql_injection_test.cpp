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
    // Isolate the two gates (d>40 AND ratio>0.25) -- prior cases had both agree.
    chk("len: 1000 vs 1060 similar (d=60>40 but ratio 0.06<0.25 -> ratio gate)",
        lenSimilar(1000, 1060));
    chk("len: 100 vs 135 similar (ratio 0.26>0.25 but d=35<=40 -> d gate)",
        lenSimilar(100, 135));

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
    // Type confusion where BOTH always-true ops error IDENTICALLY over an OK literal
    // (same 5xx, similar length) -- an object-where-a-string-was-wanted crash, NOT an
    // over-match. This is the type-confusion guard's actual job (two AGREEING errors);
    // the case above disagrees (gt=200) so trueGroupAgrees already blocks it. Removing
    // the guard makes THIS return true (a spurious injection) -- so it is discriminating.
    chk("confirm: $ne AND $gt error identically over an OK literal -> NO (type confusion)",
        !confirmsInjection(520,200, 520,200, 300,500, 300,500));
    // Per-request jitter: $ne happens large but $gt (second sample) does not.
    chk("confirm: jitter ($gt disagrees) -> NO",
        !confirmsInjection(520,200, 520,200, 900,200, 520,200));
    // No injection: everything tracks -> groups don't differ.
    chk("confirm: no injection (all same) -> NO",
        !confirmsInjection(520,200, 520,200, 520,200, 520,200));
    // STATUS-half coverage (prior TPs/FPs diverged by LENGTH). falseGroupTracksLit
    // requires eqStatus == litStatus: an app treating the $eq OBJECT specially
    // (403) while length tracks must NOT confirm.
    chk("confirm: $eq status diverges (len tracks) -> NO (falseGroup status half)",
        !confirmsInjection(520,200, 520,403, 1000,200, 1000,200));
    // groupsDiffer via the STATUS disjunct only: identical lengths, but the
    // always-true ops flip status (302) vs the literal (200) -> a real injection.
    chk("confirm: status-only divergence (lengths equal) -> YES (groupsDiffer status half)",
        confirmsInjection(520,200, 520,200, 520,302, 520,302));
    // trueGroupAgrees STATUS half (neStatus == gtStatus): the two ALWAYS-TRUE ops
    // have SIMILAR length but only $gt status-flips (302) -- a router/WAF keyed on
    // the $gt operator name, not a datastore over-match. They do NOT agree, so this
    // must NOT confirm. Every prior trueGroup FP diverged by LENGTH (lines 64/74/77),
    // so this status conjunct was unpinned; dropping it fabricates the finding.
    chk("confirm: only $gt status-flips (lengths similar) -> NO (trueGroup status half)",
        !confirmsInjection(520,200, 520,200, 1000,200, 1000,302));

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
        // The drop-guard must also cover the header NAME (not just the value).
        Request injName = req;
        injName.headers.append(qMakePair(QString("X-A\r\nX-Smuggled"), QString("1")));
        chk("build: drops CRLF in a carried header NAME",
            !buildRequest(injName, "q=x").contains("X-Smuggled"));
        // A carried Host is dropped so only the synthesized Host survives.
        Request dupHost = req;
        dupHost.headers.append(qMakePair(QString("Host"), QString("attacker.tld")));
        chk("build: drops carried Host (no duplicate)",
            buildRequest(dupHost, "q=x").count("Host:") == 1
            && !buildRequest(dupHost, "q=x").contains("attacker.tld"));

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

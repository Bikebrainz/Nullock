// Regression corpus for the SSTI tester's pure logic (no network):
//   - confirmsArithmetic: the two-expression confirmation that distinguishes a
//     real template engine (evaluates two delimited expressions, keeps the
//     literal separator) from a single-expression calculator (the headline
//     false positive the audit found) -- plus locale-grouping tolerance and
//     all-region scanning for double-reflected params.
//   - stripGroupingDigits: strips , . ' space NBSP NNBSP (FreeMarker locales).
//   - renderedRegions: returns ALL sentinel regions, not just the first.
//   - buildRequest: CR/LF guards on method/host/path/Content-Type.
//
// Run via:  ctest -R ssti_tester -V

#include "ssti_tester.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::Ssti;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- stripGroupingDigits --------------------------------------------
    chk("strip: US comma",     stripGroupingDigits("24,534,638") == "24534638");
    chk("strip: EU dot",       stripGroupingDigits("24.534.638") == "24534638");
    chk("strip: Swiss apos",   stripGroupingDigits("24'534'638") == "24534638");
    chk("strip: ASCII space",  stripGroupingDigits("24 534 638") == "24534638");
    chk("strip: NBSP",         stripGroupingDigits(QString("24") + QChar(0x00A0) + "534" + QChar(0x00A0) + "638") == "24534638");
    chk("strip: NNBSP",        stripGroupingDigits(QString("24") + QChar(0x202F) + "534") == "24534");

    // ---- renderedRegions -------------------------------------------------
    {
        const QString pre = "zPRE", suf = "SUFz";
        chk("regions: single", renderedRegions("aaazPREcontentSUFzbbb", pre, suf) == QStringList{"content"});
        // Double reflection: literal echo first, evaluated region second -> BOTH.
        const auto two = renderedRegions("xzPRE{{a*b}}SUFzy zPRE49SUFz", pre, suf);
        chk("regions: double count", two.size() == 2);
        chk("regions: double[0] literal", two.value(0) == "{{a*b}}");
        chk("regions: double[1] evaluated", two.value(1) == "49");
        // A region longer than 64 chars is skipped.
        QString big = "zPRE" + QString(80, 'x') + "SUFz";
        chk("regions: >64 skipped", renderedRegions(big, pre, suf).isEmpty());
    }

    // ---- confirmsArithmetic: the FP-killer + FN fixes --------------------
    const QString pA = "7006652", pB = "3210123", sep = "qwxyz";
    const QString eA = "1234*5678", eB = "3333*963";
    auto confirms = [&](const QStringList &regions) {
        return confirmsArithmetic(regions, pA, sep, pB, eA, eB);
    };
    chk("confirm: both products + sep",  confirms({ pA + sep + pB }));
    chk("confirm: with US grouping",     confirms({ "7,006,652" + sep + "3,210,123" }));
    chk("confirm: with NBSP grouping",   confirms({ QString("7") + QChar(0x00A0) + "006" + QChar(0x00A0) + "652" + sep + pB }));
    chk("confirm: with surrounding spaces", confirms({ " " + pA + " " + sep + " " + pB + " " }));
    // THE HEADLINE FP: a calculator yields ONE product -> must NOT confirm.
    chk("confirm: single product (calc) -> NO", !confirms({ pA }));
    chk("confirm: both products WRONG separator -> NO", !confirms({ pA + "XX" + pB }));
    chk("confirm: reflected exprA -> NO", !confirms({ eA + sep + eB }));
    // Isolate the exprB operand of the reflection-suppression ||: a region that
    // has BOTH products + sep (would confirm) yet also echoes the raw exprB but
    // NOT exprA must still be suppressed -- the prior negative echoed BOTH, so
    // the exprA operand alone satisfied the guard and exprB went unproven.
    chk("confirm: products present but exprB reflected -> NO (exprB operand)",
        !confirms({ pA + sep + pB + " " + eB }));
    chk("confirm: only productB -> NO",   !confirms({ pB }));
    chk("confirm: empty -> NO",           !confirms({}));
    // All-region scan: literal echo first, real eval second -> confirm.
    chk("confirm: double-reflection second region",
        confirms({ eA + sep + eB, pA + sep + pB }));

    // ---- engineLikelyFrom: fail-closed secondary signal (audit-5) --------
    // The syntax-break 5xx is only credited when the minimal-pair control
    // actually completed and did NOT itself 5xx.
    chk("engineLikely: control transport failure -> false (fail-closed)",
        !engineLikelyFrom(200, /*delimOk=*/true, 500, /*ctrlOk=*/false, 0));
    chk("engineLikely: control ok + 2xx -> true (template-specific 5xx)",
        engineLikelyFrom(200, true, 500, true, 200));
    chk("engineLikely: control also 5xx -> false (cancels)",
        !engineLikelyFrom(200, true, 500, true, 503));
    chk("engineLikely: delim did NOT 5xx -> false",
        !engineLikelyFrom(200, true, 404, true, 200));
    chk("engineLikely: baseline already 5xx -> false",
        !engineLikelyFrom(500, true, 500, true, 200));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/p";
        const QByteArray ok = buildRequest(req, req.basePath, "q=x", QByteArray());
        chk("build: request line", ok.startsWith("GET /p?q=x HTTP/1.1\r\n"));
        chk("build: Host",         ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF header", !buildRequest(injHdr, injHdr.basePath, "q=x", QByteArray()).contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, badMethod.basePath, "q=x", QByteArray()).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty",   buildRequest(badHost, badHost.basePath, "q=x", QByteArray()).isEmpty());
        chk("build: CRLF path -> empty",   buildRequest(req, "/p\r\nX: y", "q=x", QByteArray()).isEmpty());

        // Content-Type guard fires for body methods.
        Request post = req; post.method = "POST"; post.contentType = "application/json\r\nX: y";
        chk("build: CRLF content-type -> empty",
            buildRequest(post, post.basePath, "", QByteArray("{}")).isEmpty());
        Request postOk = req; postOk.method = "POST"; postOk.contentType = "application/json";
        chk("build: clean POST has Content-Type",
            buildRequest(postOk, postOk.basePath, "", QByteArray("{}")).contains("Content-Type: application/json\r\n"));
    }

    // ---- sstiEchoConfirms: the /audit battery's single-shot verdict ----
    // The battery reported ANY response containing "49" as critical RCE SSTI;
    // its own comment promised a baseline exclusion it never implemented. This
    // is that guard, extracted + locked.
    {
        // Real evaluation: 49 introduced by the payload, absent from baseline.
        chk("ssti-echo: 49 newly appears -> confirmed",
            sstiEchoConfirms(/*baseline*/"hello world", /*probe*/"hello world 49", "49"));
        // Static "49" already on the page (a price / year / id) -> NOT SSTI.
        chk("ssti-echo: 49 already in baseline ($49 price) -> NOT confirmed",
            !sstiEchoConfirms("Order total: $49.00", "Order total: $49.00 {{7*7}}", "49"));
        chk("ssti-echo: 49 in baseline (year 1949) -> NOT confirmed",
            !sstiEchoConfirms("Founded 1949", "Founded 1949", "49"));
        // Literal echo of an un-evaluated payload: no "49" appears at all.
        chk("ssti-echo: payload reflected but not evaluated (no 49) -> NOT confirmed",
            !sstiEchoConfirms("q=", "q={{7*7}}", "49"));
        // Signature genuinely absent.
        chk("ssti-echo: signature absent from probe -> NOT confirmed",
            !sstiEchoConfirms("hello", "hello there", "49"));
    }

    std::fprintf(stderr, "ssti_tester_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

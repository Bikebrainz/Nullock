// Regression corpus for the command-injection probe's pure logic (no network):
//   - commandProof: the proof token must wrap the arithmetic in a COMMAND
//     SUBSTITUTION ($(echo $((a*b)))) so a hit proves command execution, not
//     mere arithmetic expansion (the audit's high-severity calculator-class FP).
//   - renderedRegions: returns ALL sentinel regions, so a literal echo of the
//     payload preceding the executed output no longer masks the hit.
//   - buildRequest: CR/LF guards on method/host/path.
//
// Run via:  ctest -R cmd_injection -V

#include "cmd_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::CmdInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- commandProof: the FP-killer (command substitution, not bare math) --
    {
        const QString cp = commandProof("zPRE", "SUFz", 1234, 5678);
        chk("proof: exact shape", cp == "zPRE$(echo $((1234*5678)))SUFz");
        chk("proof: uses command substitution", cp.contains("$(echo $(("));
        // Must NOT be the old bare-arithmetic form an expander could satisfy.
        chk("proof: not bare arithmetic", cp != "zPRE$((1234*5678))SUFz");
    }

    // ---- renderedRegions: all regions (double-reflection FN fix) ------------
    {
        const QString pre = "zPRE", suf = "SUFz";
        chk("regions: single", renderedRegions("xxzPREcontentSUFzyy", pre, suf) == QStringList{"content"});

        // Literal echo of the payload FIRST, executed product SECOND.
        const QString body =
            "head zPRE$(echo $((1234*5678)))SUFz mid zPRE7006652SUFz tail";
        const auto regs = renderedRegions(body, pre, suf);
        chk("regions: double count", regs.size() == 2);
        chk("regions: literal region != product", regs.value(0).trimmed() != "7006652");
        // The confirm logic test() uses: ANY region equals the product.
        bool hit = false;
        for (const QString &r : regs) if (r.trimmed() == "7006652") hit = true;
        chk("regions: confirms via the SECOND region (FN fix)", hit);

        // A region longer than 64 chars is skipped.
        chk("regions: >64 skipped",
            renderedRegions("zPRE" + QString(80, 'x') + "SUFz", pre, suf).isEmpty());
        // ...but an oversized region must not STOP the scan: a LATER valid product
        // region is still found (the double-reflection FN fix relies on continue-
        // after-skip, not break). A skip->break regression returns [] here.
        chk("regions: oversized region skipped, a later valid region still found",
            renderedRegions("zPRE" + QString(80, 'x') + "SUFz mid zPRE7006652SUFz", pre, suf)
                == QStringList{"7006652"});
    }

    // ---- buildRequest: CR/LF guards ---------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/run";
        const QByteArray ok = buildRequest(req, "cmd=x");
        chk("build: request line", ok.startsWith("GET /run?cmd=x HTTP/1.1\r\n"));
        chk("build: Host",         ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF header", !buildRequest(injHdr, "cmd=x").contains("X-Smuggled"));
        // The above covers only the VALUE CR/LF guard (clean name, tainted value).
        // A CR/LF in the header NAME is a separate guard and was untested -- its
        // removal would splice an attacker header into every probe shot (the probe
        // becomes a request-smuggling vector). Clean value, so this isolates the
        // name guard.
        Request injName = req;
        injName.headers.append(qMakePair(QString("X-Foo\r\nX-NameSmuggled: 1"), QString("1")));
        chk("build: drops CRLF in header NAME",
            !buildRequest(injName, "cmd=x").contains("X-NameSmuggled"));
        // Positive coverage for the emit + Host-dedup paths (only the CR/LF-drop was
        // tested): a clean carried header IS emitted, and a carried Host is dropped
        // in favor of the one canonical Host. A regression dropping benign headers
        // would silently scan authenticated targets UNauthenticated (false clean).
        Request carried = req;
        carried.headers.append(qMakePair(QString("Cookie"), QString("session=abc")));
        carried.headers.append(qMakePair(QString("Host"), QString("attacker.tld")));
        const QByteArray cb = buildRequest(carried, "cmd=x");
        chk("build: a clean carried header IS emitted", cb.contains("Cookie: session=abc\r\n"));
        chk("build: a carried Host is deduped to the one canonical Host",
            cb.count("Host: ") == 1 && cb.contains("Host: victim.tld\r\n") && !cb.contains("attacker.tld"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "cmd=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty",   buildRequest(badHost, "cmd=x").isEmpty());
        Request badPath = req; badPath.basePath = "/run\r\nX: y";
        chk("build: CRLF path -> empty",   buildRequest(badPath, "cmd=x").isEmpty());
        // audit-5: the query is spliced into the request line -> guard it too.
        chk("build: CRLF query -> empty",  buildRequest(req, "cmd=x\r\nEvil: 1").isEmpty());
    }

    std::fprintf(stderr, "cmd_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

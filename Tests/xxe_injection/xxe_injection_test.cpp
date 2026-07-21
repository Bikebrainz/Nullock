// Regression corpus for the XXE probe's pure logic (no network):
//   - confirmReadSig: confirms a real external-entity read only when the file
//     signature is in the SYSTEM response (status < 500) AND absent from both the
//     benign baseline and the inert-DOCTYPE control -- so a hardened
//     disallow-doctype server whose error page carries a passwd-shaped line is
//     NOT flagged (the audit's false positive). It also FAILS CLOSED when the
//     inert control did not run (inertOk=false): with the FP defeater unrun a
//     read is unproven, so it is not reported (was previously fail-open).
//   - matchSig: the file-content fingerprints.
//   - buildRequest: CR/LF guards on method/host/path AND Content-Type (the live
//     contentType header-injection the audit found).
//
// Run via:  ctest -R xxe_injection -V

#include "xxe_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QRegularExpression>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::XxeInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const QByteArray PASSWD = "<r>root:x:0:0:root:/root:/bin/bash</r>";
const QByteArray OKBODY = "<r>ok</r>";
// The hardened disallow-doctype error page that carries a passwd-shaped line.
const QByteArray REJECT = "<error>DOCTYPE disallowed; env root:x:0:0:root:/root:/bin/bash</error>";
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const QRegularExpression passwd("root:[^:\\n]*:0:0:[^:\\n]*:[^:\\n]*:");
    const QRegularExpression winini("\\[(?:fonts|extensions|mci extensions)\\]",
                                    QRegularExpression::CaseInsensitiveOption);

    // ---- matchSig --------------------------------------------------------
    chk("sig: passwd matches",   !matchSig(passwd, PASSWD).isEmpty());
    chk("sig: passwd no-match",   matchSig(passwd, OKBODY).isEmpty());
    chk("sig: winini [fonts]",   !matchSig(winini, "[fonts]\r\nx=1").isEmpty());
    chk("sig: winini [Extensions] case", !matchSig(winini, "[Extensions]").isEmpty());
    chk("sig: winini no-match",   matchSig(winini, "<r>ok</r>").isEmpty());

    // ---- confirmReadSig: the FP-hardening core --------------------------
    // (`inertOk` = did the inert-DOCTYPE control request actually run.)
    // Genuine read: sig in SYSTEM (200), absent from baseline + inert (which ran).
    chk("confirm: real read",
        !confirmReadSig(passwd, PASSWD, 200, OKBODY, true, OKBODY).isEmpty());
    // FP GUARD: a disallow-doctype server returns the SAME passwd-shaped error
    // page for the inert control AND the SYSTEM payload -> must NOT confirm.
    chk("confirm: doctype-reject error page -> NO (FP fix)",
        confirmReadSig(passwd, REJECT, 400, OKBODY, true, REJECT).isEmpty());
    // Present at baseline (server always returns it) -> not attributable.
    chk("confirm: present at baseline -> NO",
        confirmReadSig(passwd, PASSWD, 200, PASSWD, true, OKBODY).isEmpty());
    // Server-error body (5xx stack trace) -> not a read.
    chk("confirm: 5xx body -> NO",
        confirmReadSig(passwd, PASSWD, 500, OKBODY, true, OKBODY).isEmpty());
    // No signature in the SYSTEM response -> nothing.
    chk("confirm: no sig -> NO",
        confirmReadSig(passwd, OKBODY, 200, OKBODY, true, OKBODY).isEmpty());
    // Control RAN cleanly (ok, empty body) + a real read present -> confirms.
    chk("confirm: successful clean inert + real read -> YES",
        !confirmReadSig(passwd, PASSWD, 200, OKBODY, true, QByteArray()).isEmpty());
    // THE FIX (fail-closed): the inert control request FAILED (inertOk=false), so
    // the FP defeater could not run -- a genuine-looking read is NOT confirmed
    // (previously this failed OPEN and reported the finding).
    chk("confirm: FAILED inert control -> NO (fail-closed fix)",
        confirmReadSig(passwd, PASSWD, 200, OKBODY, false, QByteArray()).isEmpty());

    // ---- buildRequest: CR/LF guards (incl. the live contentType vector) --
    {
        Request req;
        req.host = "victim.tld"; req.method = "POST"; req.basePath = "/parse";
        const QByteArray ok = buildRequest(req, "<r>x</r>");
        chk("build: request line", ok.startsWith("POST /parse HTTP/1.1\r\n"));
        chk("build: default content-type", ok.contains("Content-Type: application/xml\r\n"));
        chk("build: Host + body", ok.contains("Host: victim.tld\r\n") && ok.endsWith("<r>x</r>"));

        Request badCt = req; badCt.contentType = "application/xml\r\nX-Injected: 1";
        chk("build: CRLF contentType -> empty (FP/injection fix)", buildRequest(badCt, "<r>x</r>").isEmpty());
        Request badMethod = req; badMethod.method = "POST\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "<r>x</r>").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "<r>x</r>").isEmpty());
        Request badPath = req; badPath.basePath = "/p\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "<r>x</r>").isEmpty());

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "<r>x</r>").contains("X-Smuggled"));
    }

    std::fprintf(stderr, "xxe_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

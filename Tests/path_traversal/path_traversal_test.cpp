// Regression corpus for the path-traversal probe's pure logic (no network):
//   - matchSig: the file-content fingerprints (passwd line shape rejects a prose
//     mention; win.ini section header).
//   - buildRequest: CR/LF guards on method/host/path.
// (The shaped/inert-control FP guard is exercised live in probe_smoke via the
// value-keyed "template" mock.)
//
// Run via:  ctest -R path_traversal -V

#include "path_traversal.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QRegularExpression>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::PathTraversal;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const QRegularExpression passwd("root:[^:\\n]*:0:0:[^:\\n]*:[^:\\n]*:");
    const QRegularExpression winini("\\[(?:fonts|extensions|mci extensions)\\]",
                                    QRegularExpression::CaseInsensitiveOption);

    // ---- matchSig: passwd line shape -------------------------------------
    chk("sig: passwd line", !matchSig(passwd, "root:x:0:0:root:/root:/bin/bash\n").isEmpty());
    chk("sig: passwd prose mention rejected", matchSig(passwd, "Log in as the root: user to continue").isEmpty());
    chk("sig: passwd absent", matchSig(passwd, "<html>file not found</html>").isEmpty());

    // ---- matchSig: win.ini section ---------------------------------------
    chk("sig: win.ini [fonts]", !matchSig(winini, "[fonts]\r\nvga=1").isEmpty());
    chk("sig: win.ini [Extensions] case", !matchSig(winini, "[Extensions]").isEmpty());
    chk("sig: win.ini absent", matchSig(winini, "<html>ok</html>").isEmpty());

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/dl";
        const QByteArray ok = buildRequest(req, "file=x");
        chk("build: request line", ok.startsWith("GET /dl?file=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "file=x").contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "file=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "file=x").isEmpty());
        Request badPath = req; badPath.basePath = "/dl\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "file=x").isEmpty());
    }

    std::fprintf(stderr, "path_traversal_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

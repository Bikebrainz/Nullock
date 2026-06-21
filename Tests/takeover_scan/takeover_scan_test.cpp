// Regression corpus for the subdomain-takeover probe's pure logic (no network):
//   - match(): branded fingerprints fire; the pruned generic 404 strings (the
//     stock Apache 404 = old "Unbounce" FP, bare "Repository not found",
//     "project not found", a generic 404 title) must NOT fire.
//   - buildGet(): CR/LF guards on host / basePath.
//
// Run via:  ctest -R takeover_scan -V

#include "takeover_scan.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::TakeoverScan;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool hits(const char *body, const char *service) {
    for (const auto &h : match(QString::fromUtf8(body)))
        if (h.service == QString::fromLatin1(service)) return true;
    return false;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- branded fingerprints fire -------------------------------------
    chk("fp: GitHub Pages", hits("<html>There isn't a GitHub Pages site here.</html>", "GitHub Pages"));
    chk("fp: S3 NoSuchBucket", hits("<Error><Code>NoSuchBucket</Code></Error>", "AWS/S3"));
    chk("fp: Fastly", hits("Fastly error: unknown domain: foo.example.com", "Fastly"));
    chk("fp: Pantheon", hits("The gods are wise, but do not know of the site which you seek", "Pantheon"));
    chk("fp: Cargo branded kept", hits("If you're moving your domain away from Cargo, ...", "Cargo"));
    chk("fp: WordPress.com .wordpress.com anchored",
        hits("<p>Do you want to register foo.wordpress.com?</p>", "WordPress.com"));
    chk("fp: LaunchRock", hits("It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.", "LaunchRock"));
    chk("fp: Teamwork", hits("Oops - We didn't find your site.", "Teamwork"));

    // ---- pruned generic strings must NOT fire (the FP fixes) ------------
    chk("FP fix: stock Apache 404 not flagged (was Unbounce)",
        match(QString("<html><body><h1>Not Found</h1><p>The requested URL was not found "
                      "on this server.</p></body></html>")).isEmpty());
    chk("FP fix: bare 'Repository not found' not flagged (was Bitbucket)",
        match(QString("<html>Repository not found</html>")).isEmpty());
    chk("FP fix: bare 'project not found' not flagged (was Surge)",
        match(QString("{\"error\":\"project not found\"}")).isEmpty());
    chk("FP fix: generic 404 title not flagged (was Cargo alt)",
        match(QString("<title>404 &mdash; File not found</title>")).isEmpty());
    chk("clean page -> no hits", match(QString("<html><body>Welcome to my site</body></html>")).isEmpty());
    // WordPress.com anchor: a generic 'Do you want to register' without wordpress.com must not fire
    chk("FP fix: WordPress.com requires .wordpress.com anchor",
        match(QString("Do you want to register your account today?")).isEmpty());

    // ---- buildGet: CR/LF guards ----------------------------------------
    {
        Request req; req.host = "sub.victim.tld"; req.basePath = "/";
        const QByteArray g = buildGet(req);
        chk("build: request line", g.startsWith("GET / HTTP/1.1\r\n"));
        chk("build: Host", g.contains("Host: sub.victim.tld\r\n"));
        Request badHost = req; badHost.host = "sub.victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildGet(badHost).isEmpty());
        Request badPath = req; badPath.basePath = "/\r\nX: y";
        chk("build: CRLF path -> empty", buildGet(badPath).isEmpty());
    }

    std::fprintf(stderr, "takeover_scan_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

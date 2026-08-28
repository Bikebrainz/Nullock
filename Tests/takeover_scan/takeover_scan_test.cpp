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
    // The AWS/S3 fingerprint has a SECOND alternative -- the human-readable
    // message a dangling bucket surfaces without the <Code>NoSuchBucket</Code>
    // element. The case above only exercises the first; pin the message form so
    // corrupting/dropping it (a silent loss of message-only S3 takeover) is caught.
    chk("fp: S3 message-only alternative",
        hits("<Error><Message>The specified bucket does not exist</Message></Error>", "AWS/S3"));
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

    // ---- status-aware grading (maybefix #10) ---------------------------
    // A branded phrase on an ERROR status (a real dangling service) keeps its
    // curated confidence; the SAME phrase on a live 2xx/3xx (quoted content) is
    // demoted to "possible" so a healthy page can't produce a HIGH takeover.
    {
        const QString ghBody = "<html>There isn't a GitHub Pages site here.</html>";
        const auto err = match(ghBody, 404);
        chk("status: GitHub phrase on 404 -> high (real dangling page)",
            err.size() == 1 && err.at(0).confidence == "high");
        const auto ok200 = match(ghBody, 200);
        chk("status: SAME phrase on 200 -> demoted to 'possible' (quoted content, not takeover)",
            ok200.size() == 1 && ok200.at(0).confidence == "possible");
        const auto redir = match(ghBody, 302);
        chk("status: phrase on 3xx -> demoted to 'possible'",
            redir.size() == 1 && redir.at(0).confidence == "possible");
        const auto err503 = match("Fastly error: unknown domain: x", 503);
        chk("status: Fastly phrase on 503 -> keeps high",
            err503.size() == 1 && err503.at(0).confidence == "high");
    }

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

        // The forced "Accept-Encoding: identity" is load-bearing: if it were weakened
        // to admit gzip, match() would scan compressed bytes and a genuine takeover
        // page (e.g. Heroku "No such app") would never match -> false-clean. Lock it.
        chk("build: forces identity encoding (no gzip)",
            g.contains("Accept-Encoding: identity\r\n") && !g.toLower().contains("gzip"));

        // The host/basePath CR/LF guards are per-character (contains '\r'/'\n'), so a
        // LONE LF or LONE CR (no full "\r\n") must also abort -- guards against a
        // regression that only checks for the "\r\n" substring.
        Request loneLf = req; loneLf.host = "sub.victim.tld\nX: y";
        chk("build: lone-LF host -> empty", buildGet(loneLf).isEmpty());
        Request loneCr = req; loneCr.basePath = "/\rX: y";
        chk("build: lone-CR path -> empty", buildGet(loneCr).isEmpty());
    }

    // ---- severityForTakeoverConfidence: the finding-severity map -------
    // The /api/takeover/test handler mapped confidence with `== "high" ? high :
    // medium`, so a "possible" hit (a vendor phrase quoted on a healthy 200,
    // demoted by the status-aware match) became a MEDIUM takeover finding -- the
    // exact false positive the demotion exists to prevent.
    {
        chk("severity: high -> high", severityForTakeoverConfidence("high") == "high");
        chk("severity: medium -> medium", severityForTakeoverConfidence("medium") == "medium");
        // The fix: 'possible' must NOT be medium.
        chk("severity: possible -> info, NOT medium",
            severityForTakeoverConfidence("possible") == "info");
        chk("severity: unrecognized -> info (fail low)",
            severityForTakeoverConfidence("weird") == "info");
        // End-to-end intent: a 'possible' hit from a 2xx body match (the demoted
        // tier) is reported at info, matching the passive path's 200-restraint.
        {
            const QList<Hit> h = match("There isn't a GitHub Pages site here.", 200);
            const bool anyPossibleIsMedium = [&]{
                for (const Hit &x : h)
                    if (x.confidence == "possible"
                        && severityForTakeoverConfidence(x.confidence) == "medium")
                        return true;
                return false;
            }();
            chk("severity: a 200-body 'possible' hit never maps to medium", !anyPossibleIsMedium);
        }
    }

    std::fprintf(stderr, "takeover_scan_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

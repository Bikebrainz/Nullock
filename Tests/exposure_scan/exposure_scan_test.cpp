// Regression corpus for the sensitive-file exposure scanner's pure logic (no
// network):
//   - matchSignature: real files match; the tightened weak signatures (.env
//     case-sensitive + >=2 lines; .svn >=3 numeric lines; config files reject
//     an HTML shell) no longer FP; secret-bearing matches are redacted.
//   - looksHtml; buildGet CR/LF guards.
//
// Run via:  ctest -R exposure_scan -V

#include "exposure_scan.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::ExposureScan;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const Signature &sig(const char *path) {
    static Signature none;
    for (const auto &s : signatures()) if (s.path == QString::fromLatin1(path)) return s;
    return none;
}
QString m(const char *path, const char *body) { return matchSignature(QByteArray(body), sig(path)); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- real files still match ----------------------------------------
    chk("git/config matches", !m("/.git/config", "[core]\nrepositoryformatversion = 0\n").isEmpty());
    chk("server-status matches", !m("/server-status", "<h1>Apache Server Status for x</h1>").isEmpty());
    chk("env real (>=2 KEY=val lines) matches",
        !m("/.env", "DB_PASSWORD=secret123\nAPI_KEY=abcdef\nDEBUG=true\n").isEmpty());
    chk("aws creds matches", !m("/.aws/credentials", "[default]\naws_access_key_id=AKIA...\n").isEmpty());

    // ---- the FP fixes ---------------------------------------------------
    // .env: a single UPPERCASE= line is NOT enough (minMatches=2)
    chk("env one-line -> NOT flagged (minMatches FP fix)",
        m("/.env", "VERSION=1.2.0\n(just a build page)").isEmpty());
    // .env: case-sensitive -> lowercase 'width=' / 'href=' don't count
    chk("env lowercase assignments -> NOT flagged (case-sensitive FP fix)",
        m("/.env", "width=100px\nhref=foo\ndata=loaded\nname=value\n").isEmpty());
    // config files reject an HTML app shell (catch-all serving index at /.env)
    chk("env served as HTML shell -> NOT flagged (rejectHtml FP fix)",
        m("/.env", "<!doctype html><html><head><script>var X=1</script></head>"
                   "<body>APP_VERSION=1\nMODE_PROD=2</body></html>").isEmpty());
    chk("git/config served as HTML shell -> NOT flagged",
        m("/.git/config", "<html><body>[core] welcome, repositoryformatversion</body></html>").isEmpty());
    // .svn: a couple of stray number lines are not enough (minMatches=3)
    chk("svn two number lines -> NOT flagged", m("/.svn/entries", "404\n2024\n").isEmpty());
    chk("svn real (>=3 numeric lines) -> flagged",
        !m("/.svn/entries", "12\n\n34\n\n56\n\n78\n").isEmpty());
    // docker: a single 'image:' in prose isn't enough (minMatches=2)
    chk("docker single image: line -> NOT flagged",
        m("/docker-compose.yml", "Our blog about image: tags").isEmpty());

    // ---- evidence redaction (secret-bearing files) ----------------------
    chk("env evidence redacted (no value dumped)",
        m("/.env", "DB_PASSWORD=hunter2\nAPI_KEY=zzz\n").contains("redacted"));
    chk("aws evidence redacted", m("/.aws/credentials", "aws_access_key_id=AKIAZ\n").contains("redacted"));
    chk("git/config evidence NOT redacted (not secret)",
        !m("/.git/config", "[core]\nrepositoryformatversion=0\n").contains("redacted"));

    // ---- looksHtml ------------------------------------------------------
    chk("html: doctype", looksHtml(QByteArray("<!DOCTYPE html><html>")));
    chk("html: script", looksHtml(QByteArray("  <script>x</script>")));
    chk("html: plain text -> not html", !looksHtml(QByteArray("DB_PASSWORD=x\nAPI_KEY=y")));

    // ---- buildGet: CR/LF guards ----------------------------------------
    {
        Request req; req.host = "victim.tld";
        chk("build: request line", buildGet(req, "/.env").startsWith("GET /.env HTTP/1.1\r\n"));
        chk("build: Host", buildGet(req, "/.env").contains("Host: victim.tld\r\n"));
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildGet(badHost, "/.env").isEmpty());
        chk("build: CRLF path -> empty", buildGet(req, "/.env\r\nX: y").isEmpty());
        // The custom-header loop (Host-skip + per-header CR/LF drop) was untested --
        // no test populated req.headers, though that is where attacker-influenced
        // auth/cookie values arrive. Lock all three behaviors.
        Request evilVal = req;
        evilVal.headers.append(qMakePair(QString("X-Custom"), QString("a\r\nEvil-Header: injected")));
        chk("build: CR/LF in a carried header value -> injected line dropped",
            !buildGet(evilVal, "/.env").contains("Evil-Header: injected"));
        Request evilName = req;
        evilName.headers.append(qMakePair(QString("X-A\r\nEvil-Header"), QString("1")));
        chk("build: CR/LF in a carried header name -> dropped",
            !buildGet(evilName, "/.env").contains("Evil-Header"));
        Request dupHost = req;
        dupHost.headers.append(qMakePair(QString("Host"), QString("attacker.tld")));
        const QByteArray dh = buildGet(dupHost, "/.env");
        chk("build: a carried Host is skipped (exactly one canonical Host line)",
            dh.count("Host: ") == 1 && dh.contains("Host: victim.tld\r\n") && !dh.contains("attacker.tld"));
        Request clean = req;
        clean.headers.append(qMakePair(QString("X-Trace"), QString("ok")));
        chk("build: a clean carried header IS emitted (guard not over-broad)",
            buildGet(clean, "/.env").contains("X-Trace: ok\r\n"));
    }

    std::fprintf(stderr, "exposure_scan_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

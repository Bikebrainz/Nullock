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

    // ---- previously-untested probes ------------------------------------
    // Six signatures had no regression coverage; a regex/flag regression would
    // silently stop flagging these exposed files.
    chk("git/HEAD real ref -> flagged", !m("/.git/HEAD", "ref: refs/heads/main\n").isEmpty());
    chk("git/HEAD served as HTML shell -> NOT flagged (rejectHtml)",
        m("/.git/HEAD", "<html><body>ref: refs/heads/main</body></html>").isEmpty());

    chk("phpinfo.php page -> flagged",
        !m("/phpinfo.php", "<html><head><title>PHP 8.1.2 - phpinfo()</title></head></html>").isEmpty());
    chk("phpinfo.php without the marker -> NOT flagged",
        m("/phpinfo.php", "<html><body>welcome home</body></html>").isEmpty());

    chk("DS_Store magic (Bud1) -> flagged", !m("/.DS_Store", "Bud1 mac directory metadata").isEmpty());

    chk("wp-config.php.bak with DB creds -> flagged",
        !m("/wp-config.php.bak", "<?php\ndefine('DB_PASSWORD', 'p@ssw0rd');\n").isEmpty());
    chk("wp-config.php.bak served as HTML shell -> NOT flagged (rejectHtml)",
        m("/wp-config.php.bak", "<html><body>docs about DB_PASSWORD define()</body></html>").isEmpty());

    chk("actuator/env json -> flagged",
        !m("/actuator/env", "{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"env\"}]}").isEmpty());

    chk("config.php.bak with credentials -> flagged",
        !m("/config.php.bak", "<?php define('DB_PASSWORD','x'); mysql_connect('db');").isEmpty());

    // secret-bearing probes redact their evidence.
    chk("wp-config.php.bak evidence redacted",
        m("/wp-config.php.bak", "<?php\ndefine('DB_PASSWORD', 'p@ssw0rd');\n").contains("redacted"));
    chk("actuator/env evidence redacted",
        m("/actuator/env", "{\"activeProfiles\":[\"prod\"]}").contains("redacted"));

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

        // Carried framing/encoding headers must be dropped so the ones this body-less
        // GET forces stand alone (prior tests never carried them):
        //  - Accept-Encoding: else the server gzips and the file-content signature
        //    matcher scans compressed bytes -> a real exposed .env reads CLEAN.
        Request aeReq = req;
        aeReq.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray ae = buildGet(aeReq, "/.env");
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            ae.count("Accept-Encoding:") == 1
            && ae.contains("Accept-Encoding: identity\r\n") && !ae.contains("gzip"));
        //  - Connection: a carried keep-alive contradicts the forced close.
        Request cnReq = req;
        cnReq.headers.append(qMakePair(QString("Connection"), QString("keep-alive")));
        const QByteArray cn = buildGet(cnReq, "/.env");
        chk("build: carried Connection dropped -> exactly one, close",
            cn.count("Connection:") == 1 && cn.contains("Connection: close\r\n") && !cn.contains("keep-alive"));
        //  - Content-Length / Transfer-Encoding: a body-less GET must not advertise a body.
        Request frReq = req;
        frReq.headers.append(qMakePair(QString("Content-Length"), QString("27")));
        frReq.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray fr = buildGet(frReq, "/.env");
        chk("build: carried Content-Length/Transfer-Encoding dropped (body-less GET)",
            !fr.contains("Content-Length:") && !fr.contains("Transfer-Encoding:"));
    }

    // ---- suppressAsCatchAll: the report-vs-suppress verdict ------------
    // Decides whether a matched exposure is reported or dropped as a soft-404
    // catch-all. Was inline in scan() and untested. A regression here either
    // suppresses EVERY real .env/.git/AWS-cred hit on any host that 200s a
    // random path (SPAs -- FN), or reports a catch-all shell as vulnerable (FP).
    {
        const QByteArray gitCfg("[core]\nrepositoryformatversion = 0\n");
        const QByteArray envBody("DB_PASSWORD=x\nAPI_KEY=y\n");
        const QByteArray htmlShell("<!DOCTYPE html><html><body>welcome</body></html>");
        // No catch-all (control not 2xx) -> never suppress, even if bodies match.
        chk("suppress: no 2xx control -> a real /.git/config hit is reported",
            !suppressAsCatchAll(false, gitCfg, sig("/.git/config")));
        // Catch-all AND the control serves the same signature -> suppress.
        chk("suppress: bogus path also serves git config -> catch-all, suppressed",
            suppressAsCatchAll(true, gitCfg, sig("/.git/config")));
        // Catch-all but the control body does NOT match this signature -> report.
        chk("suppress: 2xx control is an HTML shell (no git match) -> real hit reported",
            !suppressAsCatchAll(true, htmlShell, sig("/.git/config")));
        chk("suppress: 2xx control has no env markers -> real /.env hit reported",
            !suppressAsCatchAll(true, htmlShell, sig("/.env")));
        // rejectHtml coupling: an HTML control shell must NOT suppress a
        // plain-text config signature (matchSignature rejects HTML for it), even
        // if the shell text happens to contain the signature's phrase.
        chk("suppress: rejectHtml -- HTML control quoting '[core] repositoryformatversion' does NOT suppress",
            !suppressAsCatchAll(true,
                QByteArray("<html><body>[core]\nrepositoryformatversion = 0</body></html>"),
                sig("/.git/config")));
    }

    std::fprintf(stderr, "exposure_scan_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

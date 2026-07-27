// Regression corpus for the client-side secret scanner's pure logic (no
// network):
//   - scanText / acceptSecret: documented EXAMPLE keys are now filtered (the
//     looksPlaceholder fix applies to EVERY match, not just the generic rule);
//     real high-entropy keys still hit; the assigned-secret '=' fix; severity
//     downgrades (twilio SID / JWT -> low); masking never leaks the value.
//   - buildGet CR/LF guards; sameOriginScripts host/scheme/port check.
//
// (AWS-shaped keys are built by concatenation so no literal AKIA+16 appears in
// source -- they are synthetic test values, not real or example credentials.)
//
// Run via:  ctest -R secret_scanner -V

#include "secret_scanner.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>
#include <QUrl>

#include <cstdio>

using namespace Nullock::Core::SecretScanner;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool hasType(const QList<Hit> &hits, const char *type) {
    for (const auto &h : hits) if (h.type == QString::fromLatin1(type)) return true;
    return false;
}
const Hit *findType(const QList<Hit> &hits, const char *type) {
    for (const auto &h : hits) if (h.type == QString::fromLatin1(type)) return &h;
    return nullptr;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QString awsExample = QStringLiteral("AKIA") + "EXAMPLE0123QWXYZ";   // 16, contains EXAMPLE
    const QString awsReal    = QStringLiteral("AKIA") + "Z7XK2QPLM4NWJR58";   // 16, no placeholder word

    // ---- the headline FP fix: example keys filtered on PROVIDER patterns ----
    chk("aws EXAMPLE key -> NOT flagged (looksPlaceholder now applies to providers)",
        !hasType(scanText("creds = \"" + awsExample + "\"", "x"), "aws-access-key-id"));
    chk("aws real-shaped key -> flagged",
        hasType(scanText("creds = \"" + awsReal + "\"", "x"), "aws-access-key-id"));
    chk("acceptSecret: example rejected", !acceptSecret(awsExample, false));
    chk("acceptSecret: real accepted", acceptSecret(awsReal, false));

    // ---- looksPlaceholder breadth (distinctive tokens only) -------------
    chk("placeholder: example", looksPlaceholder("AKIAEXAMPLEKEYHERE"));
    chk("placeholder: your-key", looksPlaceholder("your-api-key"));
    chk("placeholder: deadbeef", looksPlaceholder("deadbeefdeadbeefdead"));
    chk("placeholder: 6+ char run", looksPlaceholder("aaaaaaXYZ"));
    chk("placeholder: NOT a generic real key", !looksPlaceholder("Z7XK2QpLm4NwJr58Qv"));
    chk("placeholder: 'bar' substring NOT dropped (no short-token FN)",
        !looksPlaceholder("Z7barXK2QpLm4NwJr58"));

    // ---- assigned-secret: entropy gate + '=' padding fix ----------------
    chk("assigned high-entropy secret -> flagged",
        hasType(scanText("password = \"aB3xK9mQ2pL7vR4nT8wZ\"", "x"), "assigned-secret"));
    chk("assigned base64 with = padding -> captured & flagged (= class fix)",
        hasType(scanText("secret = \"YWJjZGVmZ2hpamtsbXFz9Q==\"", "x"), "assigned-secret"));
    chk("assigned placeholder value -> NOT flagged",
        !hasType(scanText("api_key = \"your_api_key_placeholder_here\"", "x"), "assigned-secret"));
    chk("assigned low-entropy value -> NOT flagged",
        !hasType(scanText("password = \"aaaaaaaaaaaaaaaaaaaa\"", "x"), "assigned-secret"));

    // ---- severity downgrades --------------------------------------------
    {
        // a JWT shape (public-ish token) -> low
        const QString jwt = "eyJhbGciOiJ.eyJzdWIiOiAx.SflKxwRJSMeKKF2QT4";
        const Hit *j = findType(scanText("var t = \"" + jwt + "\"", "x"), "json-web-token");
        chk("jwt severity downgraded to low", j && j->severity == "low");
        // SID built by concatenation so no literal AC+32hex appears in source
        // (it would trip provider secret scanners) -- synthetic, not a real SID.
        const QString sid = QStringLiteral("AC") + "abf39d2e71c4508d6b9a3f0e2d18c47a";
        const Hit *t = findType(scanText("sid = \"" + sid + "\"", "x"), "twilio-account-sid");
        // (this SID is all-hex; not a placeholder, so it matches) -> low severity
        chk("twilio SID severity is low (identifier, not secret)", t && t->severity == "low");
    }

    // ---- masking never leaks the value ----------------------------------
    {
        const auto h = scanText("creds = \"" + awsReal + "\"", "x");
        const Hit *a = findType(h, "aws-access-key-id");
        chk("mask shows prefix+len, not the full key",
            a && a->masked.startsWith("AKIA") && a->masked.contains("(len 20)")
              && !a->masked.contains("NWJR58") && !a->context.contains(awsReal));
    }

    // ---- buildGet: CR/LF guards ----------------------------------------
    {
        Request req; req.host = "victim.tld";
        chk("build: request line", buildGet(req, "/app.js", QString()).startsWith("GET /app.js HTTP/1.1\r\n"));
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildGet(badHost, "/app.js", QString()).isEmpty());
        chk("build: CRLF path -> empty", buildGet(req, "/a\r\nX: y", QString()).isEmpty());
        // audit-3: query is spliced into the request line raw -> guard it (parity).
        chk("build: CRLF query -> empty", buildGet(req, "/search", "q=a\r\nX-Injected: 1").isEmpty());
        chk("build: bare-LF query -> empty", buildGet(req, "/search", "q=a\nX: y").isEmpty());
        // audit-3: a body-less GET must drop a carried Content-Length/Transfer-
        // Encoding, else a strict origin blocks awaiting a body that never comes
        // and the page (+ its same-origin scripts) is never scanned -> secrets missed.
        Request carried; carried.host = "victim.tld";
        carried.headers.append(qMakePair(QString("Content-Length"), QString("137")));
        carried.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
        const QByteArray cg = buildGet(carried, "/app", QString());
        chk("build: carried Content-Length dropped (body-less GET won't strand)", !cg.contains("Content-Length"));
        chk("build: carried Transfer-Encoding dropped", !cg.contains("Transfer-Encoding"));
        // The per-carried-header CR/LF drop (name AND value) was untested -- the loop
        // only ever saw Content-Length/Transfer-Encoding, dropped earlier by name, so
        // control never reached the CR/LF guard. A regression removing it would splice
        // an injected header straight into the request bytes.
        Request crlfVal; crlfVal.host = "victim.tld";
        crlfVal.headers.append(qMakePair(QString("X-Foo"), QString("bar\r\nEvil-Injected: 1")));
        chk("build: CR/LF in a carried header VALUE dropped (no header injection)",
            !buildGet(crlfVal, "/app", QString()).contains("Evil-Injected"));
        Request crlfName; crlfName.host = "victim.tld";
        crlfName.headers.append(qMakePair(QString("X-A\r\nEvil-Injected"), QString("1")));
        chk("build: CR/LF in a carried header NAME dropped",
            !buildGet(crlfName, "/app", QString()).contains("Evil-Injected"));
    }

    // ---- sameOriginScripts: same host/scheme/port only ------------------
    {
        QUrl base("https://app.victim.tld/");
        const QString html =
            "<script src=\"/a.js\"></script>"
            "<script src=\"https://cdn.other.tld/b.js\"></script>"     // different host -> excluded
            "<script src=\"https://app.victim.tld/c.js\"></script>";
        const QStringList s = sameOriginScripts(html, base, 12);
        chk("scripts: same-origin kept", s.contains("/a.js") && s.contains("/c.js"));
        chk("scripts: cross-origin excluded", !s.filter("b.js").size());
        // scheme + port axes (only the host axis was exercised above):
        //  - a different explicit PORT is excluded by the port check (line 142);
        //  - a cross-SCHEME script at the SAME effective port (http on :443) is
        //    excluded ONLY by the scheme check (line 141) -- the port check, seeing
        //    equal ports, can't catch it, so this discriminates the scheme axis.
        //  - a same-scheme/same-port control confirms the guard isn't over-broad.
        chk("scripts: a different explicit port is excluded (port axis)",
            sameOriginScripts("<script src=\"https://app.victim.tld:8443/x.js\"></script>", base, 12).isEmpty());
        chk("scripts: a cross-scheme http-on-443 script is excluded (scheme axis)",
            sameOriginScripts("<script src=\"http://app.victim.tld:443/z.js\"></script>", base, 12).isEmpty());
        chk("scripts: a same-scheme same-port script IS kept (guard not over-broad)",
            sameOriginScripts("<script src=\"https://app.victim.tld/ok.js\"></script>", base, 12).contains("/ok.js"));
    }

    std::fprintf(stderr, "secret_scanner_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

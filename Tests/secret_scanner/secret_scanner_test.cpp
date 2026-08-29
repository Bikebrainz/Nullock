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

    // ---- provider secret patterns (previously untested) -----------------
    // Only aws / jwt / twilio / assigned had coverage; the 8 provider patterns
    // below (github, google, stripe, slack, sendgrid, npm, private-key) had
    // none -- a regex regression would silently stop flagging leaked creds.
    // Each value is ASSEMBLED from fragments + a generic high-entropy pool so
    // no literal provider-shaped secret sits in source (would trip push-
    // protection + our own secret-scan). Synthetic, not real keys.
    {
        // 48 chars, alnum only, no placeholder word, no 6+ same-char run.
        const QString ent  = QStringLiteral("Z7XKpLm4NwJr58Qv3Bd9Ck1Fg6Hj0Ln2PqRt8Sw5Uy7Vx0Ea");
        const QString ent2 = ent + ent;
        auto flagged = [](const QString &secret, const char *type) {
            return hasType(scanText("k = \"" + secret + "\"", "x"), type);
        };
        chk("github-token flagged",
            flagged(QStringLiteral("ghp") + "_" + ent.left(36), "github-token"));
        chk("github-pat flagged",
            flagged(QStringLiteral("github") + "_pat_" + ent.left(22), "github-pat"));
        chk("google-api-key flagged",
            flagged(QStringLiteral("AI") + "za" + ent.left(35), "google-api-key"));
        // A key whose 35th char is '-' (in the key charset) must STILL flag: the
        // old trailing \b couldn't hold a boundary after '-' and the fixed {35}
        // count can't backtrack, so ~1/64 of real keys were dropped. (Mutation:
        // revert the tail to \b and this case goes absent.)
        chk("google-api-key ending in '-' flagged",
            flagged(QStringLiteral("AI") + "za" + ent.left(34) + "-", "google-api-key"));
        chk("stripe-secret-key flagged",
            flagged(QStringLiteral("sk") + "_live_" + ent.left(24), "stripe-secret-key"));
        chk("slack-token flagged",
            flagged(QStringLiteral("xox") + "b-" + ent.left(20), "slack-token"));
        chk("sendgrid-key flagged",
            flagged(QStringLiteral("SG") + "." + ent.left(22) + "." + ent2.left(43), "sendgrid-key"));
        chk("npm-token flagged",
            flagged(QStringLiteral("npm") + "_" + ent.left(36), "npm-token"));
        chk("private-key-block flagged",
            flagged(QStringLiteral("-----") + "BEGIN " + "RSA " + "PRIVATE KEY-----",
                    "private-key-block"));
        // private-key-block is the ONLY 'critical' pattern; its RSA form above was
        // the sole coverage. The regex's optional-prefix group also accepts the
        // OPENSSH alternative and the bare (unprefixed PKCS#8) header -- pin both
        // so silently dropping the OPENSSH alt, or forcing the prefix (deleting
        // the trailing '?'), which would stop flagging modern ssh-keygen keys and
        // PKCS#8 keys, is caught. (Headers assembled from fragments -- synthetic.)
        chk("private-key-block OPENSSH form flagged",
            flagged(QStringLiteral("-----") + "BEGIN " + "OPENSSH " + "PRIVATE KEY-----",
                    "private-key-block"));
        chk("private-key-block bare PKCS#8 form flagged",
            flagged(QStringLiteral("-----") + "BEGIN " + "PRIVATE KEY-----",
                    "private-key-block"));

        // length discriminator: a 35-char github-token body is not a match.
        chk("github-token one char short -> NOT flagged",
            !flagged(QStringLiteral("ghp") + "_" + ent.left(35), "github-token"));
        // the placeholder filter applies to provider patterns too.
        chk("google-api-key placeholder value -> NOT flagged",
            !flagged(QStringLiteral("AI") + "za" + "your_google_api_key_placeholder_123",
                     "google-api-key"));
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
        // A carried Accept-Encoding must be dropped so the forced identity stands alone
        // (else the server gzips and the raw compressed body is scanned as UTF-8 -> a
        // real leaked secret is missed); a carried Connection must be dropped too
        // (hop-by-hop, and it duplicates/conflicts with the forced Connection: close).
        Request enc; enc.host = "victim.tld";
        enc.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, br")));
        enc.headers.append(qMakePair(QString("Connection"), QString("keep-alive")));
        const QByteArray eg = buildGet(enc, "/app", QString());
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            eg.count("Accept-Encoding:") == 1 && eg.contains("Accept-Encoding: identity\r\n") && !eg.contains("gzip"));
        chk("build: carried Connection dropped -> exactly one, close",
            eg.count("Connection:") == 1 && eg.contains("Connection: close\r\n") && !eg.contains("keep-alive"));
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

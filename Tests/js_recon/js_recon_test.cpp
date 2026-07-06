// Regression corpus for js_recon's pure extraction (no network). Locks the
// soundness fixes from the adversarial audit:
//   - API tokens are PATH-SEGMENT-anchored ("/therapist/" is not an "api" path,
//     "restore.js" is not a "rest" route);
//   - relative api paths (no leading slash) are matched;
//   - import()/Worker/sendBeacon/EventSource/WebSocket + ws(s):// are mined;
//   - xhr.open(method,url) captures the URL not the verb; bare .open ids dropped;
//   - template literals keep their static prefix;
//   - the third-party filter matches the HOST suffix (look-alikes survive);
//   - an api-shaped .map survives the asset filter;
//   - sourceMappingURL takes the LAST (effective) directive.
//
// Run via:  ctest -R js_recon -V

#include "js_recon.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QSet>

#include <cstdio>

using namespace Nullock::Core::JsRecon;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QStringList eps(const QString &js) {
    QSet<QString> s; extractEndpoints(js, s);
    QStringList l = s.values(); l.sort(); return l;
}
bool has(const QString &js, const QString &want) { return eps(js).contains(want); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== api-token anchoring (the headline FP) ========================
    chk("anchor: /api/users is an endpoint", has("x=\"/api/users\"", "/api/users"));
    chk("anchor: /admin/panel is an endpoint", has("x=\"/admin/panel\"", "/admin/panel"));
    chk("anchor: /v2/orders is an endpoint", has("x=\"/v2/orders\"", "/v2/orders"));
    chk("anchor: /therapist/profile is NOT an api endpoint (was 'api' substring)",
        !has("x=\"/therapist/profile\"", "/therapist/profile"));
    chk("anchor: /authentication/login is NOT an api endpoint", !has("x=\"/authentication/login\"", "/authentication/login"));
    chk("anchor: /author/bio is NOT an api endpoint", !has("x=\"/author/bio\"", "/author/bio"));
    chk("anchor: /administrator/x is NOT an admin endpoint", !has("x=\"/administrator/x\"", "/administrator/x"));
    chk("anchor: /badminton/court is NOT an admin endpoint", !has("x=\"/badminton/court\"", "/badminton/court"));
    chk("anchor: /restaurants/list is NOT a rest endpoint", !has("x=\"/restaurants/list\"", "/restaurants/list"));

    // ===== .js / .map carve-outs ========================================
    chk("js: /static/js/restore.js is NOT an endpoint (was 'rest')", !has("x=\"/static/js/restore.js\"", "/static/js/restore.js"));
    chk("js: /api/conf.js (api-shaped) IS kept", has("x=\"/api/conf.js\"", "/api/conf.js"));
    chk("map: /api/tiles/region.map (api-shaped) survives the asset filter", has("x=\"/api/tiles/region.map\"", "/api/tiles/region.map"));
    chk("map: /static/sprite.map (not api) is dropped", !has("x=\"/static/sprite.map\"", "/static/sprite.map"));

    // ===== relative api paths (leading slash optional) ==================
    chk("relative: api/v1/orders matched", has("routes=[\"api/v1/orders\"]", "api/v1/orders"));
    chk("relative: admin/flags matched", has("routes=[\"admin/flags\"]", "admin/flags"));
    chk("relative: users/me (no api token) NOT auto-listed from a route table",
        !has("routes=[\"users/me\"]", "users/me"));

    // ===== call shapes (fetch/axios/import/Worker/sendBeacon/WS) ========
    chk("call: fetch path", has("fetch(\"/data/feed\")", "/data/feed"));
    chk("call: import() route chunk", has("import(\"/account/settings\")", "/account/settings"));
    chk("call: navigator.sendBeacon", has("navigator.sendBeacon(\"/collect\", b)", "/collect"));
    chk("call: new EventSource", has("new EventSource(\"/stream/events\")", "/stream/events"));
    chk("abs: new WebSocket wss:// captured", has("new WebSocket(\"wss://x.test/socket\")", "wss://x.test/socket"));
    chk("abs: https URL captured", has("var u=\"https://api.example.com/v1/me\"", "https://api.example.com/v1/me"));

    // ===== xhr.open(method, url) + bare .open ===========================
    chk("xhr.open: captures the URL (2nd arg), not the verb",
        has("xhr.open(\"GET\", \"/data/feed\")", "/data/feed"));
    chk("xhr.open: the verb GET is NOT an endpoint", !has("xhr.open(\"GET\", \"/data/feed\")", "GET"));
    chk("open: indexedDB.open db name is NOT an endpoint", !has("indexedDB.open(\"myDatabase\")", "myDatabase"));
    chk("open: window.open modal id is NOT an endpoint", !has("dlg.open(\"settings-modal\")", "settings-modal"));

    // ===== url: key anchoring + bare-identifier drop ====================
    chk("url-key: avatarurl suffix does NOT mislabel (bare value dropped)",
        !has("avatarurl: \"default\"", "default"));
    chk("url-key: a real url: path is kept", has("url: \"/api/login\"", "/api/login"));

    // ===== template literal prefix ======================================
    chk("template: keeps the static prefix before ${}",
        has("fetch(`/api/users/${id}/items`)", "/api/users/"));

    // ===== third-party HOST filter (not whole-URL substring) ============
    chk("3p: a real googleapis CDN host is dropped",
        !has("s=\"https://ajax.googleapis.com/jquery.js\"", "https://ajax.googleapis.com/jquery.js"));
    chk("3p: a look-alike host (mygoogleapis.com.evil.test) is NOT dropped",
        has("s=\"https://api.mygoogleapis.com.evil.test/v1/steal\"", "https://api.mygoogleapis.com.evil.test/v1/steal"));
    chk("3p: a same-target path that contains a CDN name is NOT dropped",
        has("s=\"https://myapp.com/googleapis.com/proxy\"", "https://myapp.com/googleapis.com/proxy"));

    // ===== sourceMappingUrl: LAST wins ==================================
    chk("sourcemap: single directive",
        sourceMappingUrl("a()\n//# sourceMappingURL=app.js.map\n") == "app.js.map");
    chk("sourcemap: the LAST directive is the effective one (FN fix)",
        sourceMappingUrl("//# sourceMappingURL=old.removed.map\nx()\n//# sourceMappingURL=real.abc.js.map\n")
            == "real.abc.js.map");
    chk("sourcemap: none -> empty", sourceMappingUrl("just some code()").isEmpty());

    // ===== extractSecrets (redacted credential mining) =================
    // Fixtures are assembled by concatenation so no literal secret shape ever
    // appears in this source file.
    auto secrets = [](const QString &js) { QList<JsSecret> s; extractSecrets(js, s); return s; };
    auto hasKind = [](const QList<JsSecret> &s, const QString &kind) {
        for (const auto &x : s) if (x.kind == kind) return true;
        return false;
    };
    auto redactedOf = [](const QList<JsSecret> &s, const QString &kind) {
        for (const auto &x : s) if (x.kind == kind) return x.redacted;
        return QString();
    };
    {
        const QString awsKey = QString("AKIA") + "ABCDEFGHIJKLMNOP";   // AKIA + 16 chars
        const QString js = "var creds = { id: '" + awsKey + "' };";
        const auto s = secrets(js);
        chk("secret: AWS access key detected", hasKind(s, "aws-access-key"));
        const QString red = redactedOf(s, "aws-access-key");
        chk("secret: AWS key is REDACTED (prefix + length only)",
            red.startsWith("AKIA") && red.contains("chars]") && !red.contains(awsKey.mid(4)));
        for (const auto &x : s) if (x.kind == "aws-access-key")
            chk("secret: AWS severity is high", x.severity == "high");
    }
    {
        const QString stripeKey = QString("sk_") + "live_" + "0123456789abcdefABCDEFgh";   // 24 chars
        const auto s = secrets("const key='" + stripeKey + "';");
        chk("secret: Stripe live key detected", hasKind(s, "stripe-secret"));
        for (const auto &x : s) if (x.kind == "stripe-secret")
            chk("secret: Stripe severity is critical", x.severity == "critical");
    }
    {
        const QString gh = QString("ghp_") + "0123456789abcdefABCDEF0123456789abcd";   // 36 chars
        chk("secret: GitHub PAT detected", hasKind(secrets("token: '" + gh + "'"), "github-pat"));
    }
    {
        const QString jwt = QString("eyJ") + "abcdefghij" + ".eyJ" + "klmnopqrst" + "." + "uvwxyz0123";
        chk("secret: JWT shape detected (low)", hasKind(secrets("var t='" + jwt + "'"), "jwt"));
    }
    {
        const QString pk = QString("-----BEGIN ") + "RSA PRIVATE KEY" + "-----";
        const auto s = secrets("const k=`" + pk + "\\nMIIE...`;");
        chk("secret: private key header detected", hasKind(s, "private-key"));
        for (const auto &x : s) if (x.kind == "private-key")
            chk("secret: private key severity is critical", x.severity == "critical");
    }
    {
        const auto s = secrets("const config = { apiKey: \"AbCdEf0123456789GhIjKl\" };");
        chk("secret: generic high-entropy assignment -> info lead", hasKind(s, "generic-secret"));
        for (const auto &x : s) if (x.kind == "generic-secret")
            chk("secret: generic severity is info (lead)", x.severity == "info");
    }
    chk("secret: a clean bundle yields no secrets",
        secrets("function add(a,b){return a+b;} const x=fetch('/api/x');").isEmpty());

    // ===== buildGet: request-line / Host CRLF guard (the sweep fix) =====
    {
        Request r; r.host = "t.example";
        const QByteArray ok = buildGet(r, "/app.js");
        chk("get: well-formed", ok.startsWith("GET /app.js HTTP/1.1\r\n") && ok.contains("\r\nHost: t.example\r\n"));
        chk("get: terminated", ok.endsWith("Connection: close\r\n\r\n"));
    }
    {
        // path is a scan-DISCOVERED URL (script/source-map) -> response-influenced.
        Request r; r.host = "t.example";
        chk("get: CR/LF in path -> empty (request-line injection)", buildGet(r, "/x\r\nX-I: 1").isEmpty());
        chk("get: bare LF in path -> empty", buildGet(r, "/x\nq").isEmpty());
    }
    { Request r; r.host = "t.example\r\nX-I: 1"; chk("get: CR/LF in host -> empty", buildGet(r, "/x").isEmpty()); }
    {
        // the header-loop CR/LF skip unique to this builder is now closed.
        Request r; r.host = "t.example"; r.headers = { {"X-Bad", "v\r\nX-Smug: 1"} };
        const QByteArray out = buildGet(r, "/x");
        chk("get: CR/LF carried-header skipped (request still built)", !out.isEmpty() && !out.contains("X-Bad"));
        chk("get: no smuggled header leaks from a CRLF header value", !out.contains("X-Smug"));
    }

    // ===== timed ReDoS guard: extractEndpoints runs its URL/path regexes over
    // ATTACKER-controlled JS response bodies. The patterns are linear by
    // construction today (bounded [^"'`]{1,2048} captures; the (?:[\w.@-]+/)+
    // path group has a MANDATORY '/' delimiter, so its partition is unambiguous
    // -- no catastrophic backtracking). Lock that: a large hostile body must
    // scan fast, so a future regex edit that reintroduces a nested unbounded
    // quantifier trips this instead of freezing the scan on a real target. =====
    {
        QString hostile;
        hostile.reserve(300000);
        hostile += QLatin1Char('"');
        for (int i = 0; i < 20000; ++i) hostile += QLatin1String("abc/");  // path-group iterations
        hostile += QLatin1String("\" \"");
        for (int i = 0; i < 60000; ++i) hostile += QLatin1Char('a');       // slash-free run -> backtrack-and-fail
        hostile += QLatin1String("\" ");
        for (int i = 0; i < 20000; ++i) hostile += QLatin1String("\"x\""); // dense quote pairs (many start positions)

        QSet<QString> sink;
        QElapsedTimer t; t.start();
        extractEndpoints(hostile, sink);                                   // must not hang
        const qint64 ms = t.elapsed();
        std::fprintf(stderr, "  [timing] extractEndpoints on %d KB hostile JS: %lld ms\n",
                     int(hostile.size() / 1024), static_cast<long long>(ms));
        chk("redos-guard: large hostile JS body scans well under 2s (linear, not catastrophic)",
            ms < 2000);
    }

    std::fprintf(stderr, "js_recon_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

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
    // A version embedded in a FILENAME (name.vN.ext) is NOT an API version segment:
    // the '.'-left-boundary previously set apiShaped=true and slipped a static bundle
    // past the .js / asset carve-outs. It must be dropped like restore.js / sprite.map.
    chk("version-in-filename: /static/js/jquery.v2.min.js is NOT an endpoint",
        !has("x=\"/static/js/jquery.v2.min.js\"", "/static/js/jquery.v2.min.js"));
    chk("version-in-filename: /assets/app.v3.js is dropped (.js, not an api version)",
        !has("x=\"/assets/app.v3.js\"", "/assets/app.v3.js"));
    chk("version-in-filename: /img/sprite.v2.png is dropped as an asset",
        !has("x=\"/img/sprite.v2.png\"", "/img/sprite.v2.png"));
    // A path-SEGMENT version (bounded by '/') still counts, incl. a dotted one.
    chk("version-segment: /v2.1/orders (slash-bounded version) IS an endpoint",
        has("x=\"/v2.1/orders\"", "/v2.1/orders"));

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
    // axios / jQuery .ajax / Worker: the header comment claimed these are mined
    // but nothing exercised them -- a break in the rxCall alternation would pass.
    chk("call: axios.get path", has("axios.get(\"/data/feed\")", "/data/feed"));
    chk("call: axios (bare) path", has("axios(\"/data/feed\")", "/data/feed"));
    chk("call: jQuery .ajax path", has("$.ajax(\"/data/feed\")", "/data/feed"));
    chk("call: axios verb-arg not an endpoint", !has("axios.get(\"GET\")", "GET"));
    // Use a non-api-shaped path so ONLY the call-shape miner (not the anchor
    // miner) can capture it -- isolates the Worker rxCall alternation.
    chk("call: new Worker path", has("new Worker(\"/rt/channel\")", "/rt/channel"));
    chk("call: new SharedWorker path", has("new SharedWorker(\"/rt/channel\")", "/rt/channel"));
    chk("call: new Widget is NOT a mined constructor", !has("new Widget(\"/rt/channel\")", "/rt/channel"));
    chk("abs: https URL captured", has("var u=\"https://api.example.com/v1/me\"", "https://api.example.com/v1/me"));
    // recon-1: the authority accepts an explicit :port and the path/query accepts
    // any non-quote/non-space char, so a ported endpoint or a path with special
    // chars ( , + @ ; ) isn't truncated by the extractor (old pattern dropped them).
    chk("abs: an explicit :port is kept (recon-1)",
        has("var u=\"https://api.example.com:8443/v1/me\"", "https://api.example.com:8443/v1/me"));
    chk("abs: a path/query with special chars (, +) is not truncated (recon-1)",
        has("x=\"https://h.test/v1/list?ids=1,2,3+4\"", "https://h.test/v1/list?ids=1,2,3+4"));
    chk("abs: a wss:// with an explicit port is kept (recon-1)",
        has("new WebSocket(\"wss://h.test:9001/rt\")", "wss://h.test:9001/rt"));

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
    // Provider patterns that had no dedicated positive (assembled from fragments;
    // no literal secret shape appears in source).
    {
        const QString g = QString("AI") + "za" + "0123456789abcdefghijABCDEFGHIJ12345";  // AIza + 35
        const auto s = secrets("var k=\"" + g + "\";");
        chk("secret: google-api-key detected", hasKind(s, "google-api-key"));
        for (const auto &x : s) if (x.kind == "google-api-key")
            chk("secret: google-api-key severity high", x.severity == "high");
        // one char short of the {35} tail -> not a google key.
        chk("secret: AIza too short -> NOT google-api-key",
            !hasKind(secrets("var k=\"" + QString("AI") + "za" + "0123456789abcdefghij\";"), "google-api-key"));
        // A real 39-char key whose final (35th) char is '-' (in the key's own
        // charset) must STILL fire. The old trailing \b couldn't hold a boundary
        // after '-', and the fixed {35} count can't backtrack, so ~1/64 of keys
        // (dash-terminated) were silently dropped. (Mutation: revert the tail to
        // \b and this case goes absent.)
        const QString gd = QString("AI") + "za" + "0123456789abcdefghijABCDEFGHIJ1234" + "-"; // AIza + 34 + '-'
        chk("secret: google-api-key ending in '-' still detected",
            hasKind(secrets("var k=\"" + gd + "\";"), "google-api-key"));
        // ...but AIza followed by 36 charset chars is an over-long run, not a key.
        chk("secret: AIza + 36 charset chars -> NOT google-api-key (over-long)",
            !hasKind(secrets("var k=\"" + QString("AI") + "za" + "0123456789abcdefghijABCDEFGHIJ12345" + "6\";"), "google-api-key"));
    }
    {
        const QString gl = QString("glp") + "at-" + "0123456789abcdefABCD";  // glpat- + 20
        chk("secret: gitlab-pat detected", hasKind(secrets("token='" + gl + "'"), "gitlab-pat"));
        chk("secret: glpat too short -> NOT gitlab-pat",
            !hasKind(secrets("token='" + QString("glp") + "at-" + "0123456789abcdef'"), "gitlab-pat"));
    }
    {
        const QString sk = QString("xox") + "b-" + "0123456789ab";  // xoxb- + 12 (>=10)
        chk("secret: slack-token detected", hasKind(secrets("const t=\"" + sk + "\""), "slack-token"));
        // type char must be one of [baprs]: 'z' is not.
        chk("secret: xoxz- -> NOT slack-token",
            !hasKind(secrets("const t=\"" + QString("xox") + "z-" + "0123456789ab\""), "slack-token"));
        // The [baprs] type-prefix class covers Slack's five token families; only
        // xoxb above was exercised, so dropping a sibling from the class silently
        // stops detecting that family's tokens. Pin the other four (fragment-built).
        chk("secret: slack xoxp- (user) detected",
            hasKind(secrets("const t=\"" + QString("xox") + "p-" + "0123456789ab\""), "slack-token"));
        chk("secret: slack xoxa- (app) detected",
            hasKind(secrets("const t=\"" + QString("xox") + "a-" + "0123456789ab\""), "slack-token"));
        chk("secret: slack xoxr- (refresh) detected",
            hasKind(secrets("const t=\"" + QString("xox") + "r-" + "0123456789ab\""), "slack-token"));
        chk("secret: slack xoxs- (workspace) detected",
            hasKind(secrets("const t=\"" + QString("xox") + "s-" + "0123456789ab\""), "slack-token"));
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

// Regression corpus for the passive scanner.
//
// Each case is a (label, kind-expected-to-fire?, synthetic-request,
// synthetic-response) tuple. The runner feeds the request/response
// into a fresh PassiveScanner and asserts whether the expected finding
// kind appears.
//
// Two-sided tests per detector:
//   * positive: vulnerable response should raise the finding
//   * negative: safe response should NOT raise it
// Negative cases are the FP control. The aggregate FP score across
// all detectors is reported at the end.
//
// Run after every change to passive_scanner.cpp:
//   ctest -R scanner_regression -V
// or
//   ./Tests/scanner_regression/scanner_regression_test

#include "passive_scanner.hpp"
#include "proxy_server.hpp"

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstring>

using namespace Nullock::Core;
using namespace Nullock::Proxy;

namespace {

struct TestCase {
    const char *label;
    const char *expectedKind;
    bool        negative;       // true -> assert the kind does NOT appear
    HttpRequest  req;
    HttpResponse resp;
};

HttpRequest makeReq(const QString &method, const QString &host,
                    const QString &path,
                    QList<QPair<QString, QString>> headers = {},
                    const QByteArray &body = {},
                    quint16 port = 443, bool /*wasTls*/ = true) {
    HttpRequest r;
    r.method = method;
    r.host   = host;
    r.port   = port;
    r.path   = path;
    r.target = path;
    r.httpVersion = "HTTP/1.1";
    r.headers.append({ "Host", host });
    for (const auto &h : headers) r.headers.append(h);
    r.body = body;
    return r;
}

HttpResponse makeResp(int status, const QString &contentType,
                      const QByteArray &body = {},
                      QList<QPair<QString, QString>> extraHeaders = {},
                      bool wasTls = true) {
    HttpResponse r;
    r.httpVersion = "HTTP/1.1";
    r.statusCode  = status;
    r.reasonPhrase = "OK";
    r.wasTls       = wasTls;
    if (!contentType.isEmpty())
        r.headers.append({ "Content-Type", contentType });
    for (const auto &h : extraHeaders) r.headers.append(h);
    r.body = body;
    return r;
}

QList<TestCase> buildCorpus() {
    QList<TestCase> tc;

    // Each entry: { label, expectedKind, negative, req, resp }
    //   negative=false: assert finding kind appears
    //   negative=true : assert it does NOT appear

    // ---- Missing security headers ---------------------------------------
    tc.append({ "missing-csp on plain HTML", "missing-csp", false,
        makeReq("GET", "example.test", "/index.html"),
        makeResp(200, "text/html", "<html>hi</html>") });

    tc.append({ "csp present -> no missing-csp", "missing-csp", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'"}}) });

    tc.append({ "missing-hsts on TLS HTML", "missing-hsts", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>") });

    tc.append({ "missing-hsts NOT raised on plain HTTP", "missing-hsts", true,
        makeReq("GET", "example.test", "/", {}, {}, 80, false),
        makeResp(200, "text/html", "<html>x</html>", {}, /*wasTls=*/false) });

    // ---- Subresource Integrity (cross-origin scripts) ------------------
    tc.append({ "cross-origin script without SRI", "sri-missing", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><head><script src=\"https://cdn.other.test/lib.js\"></script></head></html>") });

    tc.append({ "cross-origin script WITH integrity -> no sri-missing", "sri-missing", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><head><script src=\"https://cdn.other.test/lib.js\" "
                 "integrity=\"sha384-abc\" crossorigin=\"anonymous\"></script></head></html>") });

    tc.append({ "same-origin script -> no sri-missing", "sri-missing", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><head><script src=\"https://example.test/app.js\"></script></head></html>") });

    // ---- Mass-email outbound (the pii-email-mass ReDoS-fix regression) --
    tc.append({ "3+ emails outbound to public host -> pii-email-mass", "pii-email-mass", false,
        makeReq("POST", "analytics.public.test", "/collect", {},
                "a@one.com b@two.com c@three.com"),
        makeResp(200, "application/json", "{}") });

    tc.append({ "only 2 emails -> no pii-email-mass", "pii-email-mass", true,
        makeReq("POST", "analytics.public.test", "/collect", {},
                "a@one.com b@two.com"),
        makeResp(200, "application/json", "{}") });

    // ReDoS regression: a 30KB near-miss body (incomplete emails, no TLD) must
    // NOT fire AND must complete fast -- the old (?:email.*?){3,} mega-pattern
    // would catastrophically backtrack here; the linear count-based one does not.
    tc.append({ "30KB near-miss email body -> no pii-email-mass, no ReDoS", "pii-email-mass", true,
        makeReq("POST", "analytics.public.test", "/collect", {},
                QByteArray("user@host ").repeated(3000)),
        makeResp(200, "application/json", "{}") });

    // ---- Cloud-bucket detection + the O(n^2) ReDoS-fix regression ------
    tc.append({ "S3 bucket URL in HTML -> cloud-s3-bucket", "cloud-s3-bucket", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>see https://my-bucket.s3.us-east-1.amazonaws.com/k</body></html>") });

    // ReDoS regression: 500KB of dense ".s3." anchors with NO amazonaws tail must
    // NOT fire AND must complete fast -- the old unbounded [..]+ ... [..]* runs were
    // O(n^2) here (~35s at 500KB); the length-bounded runs are linear.
    tc.append({ "500KB dense .s3. body -> no cloud-s3-bucket, no ReDoS", "cloud-s3-bucket", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 QByteArray("<html><body>https://") + QByteArray("x.s3.").repeated(100000)
                     + QByteArray("</body></html>")) });

    // ---- Subdomain-takeover cargo FP removed ---------------------------
    tc.append({ "default 404 body must NOT fire takeover-cargo", "takeover-cargo", true,
        makeReq("GET", "example.test", "/missing"),
        makeResp(404, "text/html",
                 "<html><head><title>404 Not Found</title></head>"
                 "<body><h1>404 Not Found</h1><hr>nginx</body></html>") });

    // ---- Cookie hardening ----------------------------------------------
    tc.append({ "cookie missing HttpOnly", "cookie-no-httponly", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Set-Cookie", "session=abc; Path=/; Secure; SameSite=Lax"}}) });

    tc.append({ "cookie has HttpOnly", "cookie-no-httponly", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Set-Cookie", "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}}) });

    tc.append({ "__Host- prefix violated (has Domain=)",
                "cookie-host-prefix-violation", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "x",
                 {{"Set-Cookie", "__Host-id=abc; Path=/; Domain=example.test; Secure"}}) });

    // ---- CSP granular --------------------------------------------------
    tc.append({ "csp-unsafe-inline raised", "csp-unsafe-inline", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Content-Security-Policy", "default-src 'self' 'unsafe-inline'"}}) });

    tc.append({ "csp-unsafe-inline absent on clean CSP",
                "csp-unsafe-inline", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Content-Security-Policy", "default-src 'self'; script-src 'self'"}}) });

    tc.append({ "csp-no-frame-ancestors raised",
                "csp-no-frame-ancestors", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Content-Security-Policy", "default-src 'self'; script-src 'self'"}}) });

    // ---- HSTS strength -------------------------------------------------
    tc.append({ "hsts-short-max-age raised", "hsts-short-max-age", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Strict-Transport-Security", "max-age=300"}}) });

    tc.append({ "hsts > 1y -> no short flag", "hsts-short-max-age", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "ok",
                 {{"Strict-Transport-Security",
                   "max-age=63072000; includeSubDomains; preload"}}) });

    // ---- Leaked secrets ------------------------------------------------
    tc.append({ "leaked AWS key in body", "leaked-aws-key", false,
        makeReq("GET", "example.test", "/api/me"),
        makeResp(200, "application/json",
                 "{\"key\":\"AKIAIOSFODNN7EXAMPLE\"}") });

    tc.append({ "no leaked AWS key when body benign", "leaked-aws-key", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "application/json", "{\"key\":\"AKIANOTREAL\"}") });

    tc.append({ "leaked GitHub PAT", "leaked-gh-token", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "application/json",
                 "{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"}") });

    // GitHub push-protection scans for hardcoded API key shapes, so we
    // build a Stripe-shaped probe at runtime instead of writing the
    // literal. Same detector input; no triggering of upstream scanners.
    {
        QByteArray fake;
        fake += "stripe_key=";
        fake += "sk";  fake += "_"; fake += "live"; fake += "_";
        fake += "AbCdEfGhIjKlMnOpQrStUvWxYz";
        tc.append({ "leaked Stripe key", "leaked-stripe", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", fake) });
    }

    // ---- Exposed dev files --------------------------------------------
    tc.append({ "exposed .git/HEAD", "git-head-exposed", false,
        makeReq("GET", "example.test", "/.git/HEAD"),
        makeResp(200, "text/plain", "ref: refs/heads/main\n") });

    tc.append({ "exposed .env", "exposed-dev-file", false,
        makeReq("GET", "example.test", "/.env"),
        makeResp(200, "text/plain", "AWS_SECRET=...\n") });

    tc.append({ "normal /api/users -> no exposed-dev finding",
                "exposed-dev-file", true,
        makeReq("GET", "example.test", "/api/users"),
        makeResp(200, "application/json", "[]") });

    // ---- Dev tooling ---------------------------------------------------
    tc.append({ "spring-actuator", "spring-actuator", false,
        makeReq("GET", "api.example.test", "/actuator/health"),
        makeResp(200, "application/json", "{\"status\":\"UP\"}") });

    tc.append({ "tomcat-manager", "tomcat-manager", false,
        makeReq("GET", "example.test", "/manager/html"),
        makeResp(200, "text/html", "<title>Tomcat Manager</title>") });

    tc.append({ "swagger-ui", "swagger-ui", false,
        makeReq("GET", "api.example.test", "/swagger-ui/index.html"),
        makeResp(200, "text/html", "<title>Swagger UI</title>") });

    // ---- CORS ----------------------------------------------------------
    tc.append({ "cors-origin-reflection w/ creds",
                "cors-origin-reflection", false,
        makeReq("GET", "api.example.test", "/me",
                {{"Origin", "https://evil.example"}}),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "https://evil.example"},
                  {"Access-Control-Allow-Credentials", "true"}}) });

    tc.append({ "no CORS reflection finding when origin matches host",
                "cors-origin-reflection", true,
        makeReq("GET", "api.example.test", "/me",
                {{"Origin", "https://api.example.test"}}),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "https://api.example.test"}}) });

    tc.append({ "cors-null-origin", "cors-null-origin", false,
        makeReq("GET", "api.example.test", "/me"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "null"}}) });

    // ---- WAF detection -------------------------------------------------
    tc.append({ "Cloudflare via CF-RAY", "waf-cloudflare", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"CF-RAY", "12abc-LAX"}}) });

    // ---- Cloud bucket references --------------------------------------
    tc.append({ "S3 bucket URL referenced", "cloud-s3-bucket", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<img src=\"https://uploads-bucket.s3.us-east-1.amazonaws.com/x.png\">") });

    // ---- Deserialization ----------------------------------------------
    tc.append({ "Java serialized in request body", "deser-java", false,
        makeReq("POST", "example.test", "/api",
                {{"Content-Type", "application/octet-stream"}},
                "rO0ABXNyAA8jY29tLmV4YW1wbGUuVGVzdAAAAAAA..."),
        makeResp(200, "text/html", "ok") });

    tc.append({ "PHP serialized in response only -> no finding",
                "deser-php", true,
        makeReq("POST", "example.test", "/api"),
        makeResp(200, "text/html", "data=O:8:\"stdClass\":0:{}") });

    tc.append({ "PHP serialized in request body -> finding",
                "deser-php", false,
        makeReq("POST", "example.test", "/api", {},
                "obj=O:8:\"stdClass\":0:{}"),
        makeResp(200, "text/html", "ok") });

    // ---- CSP report-only when nothing enforced ------------------------
    tc.append({ "csp-report-only with no enforcing CSP",
                "csp-report-only", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "x",
                 {{"Content-Security-Policy-Report-Only", "default-src 'self'"}}) });

    // ---- ETag predictable ---------------------------------------------
    tc.append({ "small int ETag", "etag-predictable", false,
        makeReq("GET", "example.test", "/api/users/42"),
        makeResp(200, "application/json", "{}",
                 {{"ETag", "\"42\""}}) });

    tc.append({ "weak ETag -> no finding", "etag-predictable", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "application/json", "{}",
                 {{"ETag", "W/\"abc123def\""}}) });

    // ---- CMS / framework ----------------------------------------------
    tc.append({ "WordPress via wp-content", "cms-wordpress", false,
        makeReq("GET", "blog.example.test", "/"),
        makeResp(200, "text/html",
                 "<link rel='stylesheet' href='/wp-content/themes/twentytwentyfour/style.css'>") });

    tc.append({ "Drupal via X-Generator", "cms-drupal", false,
        makeReq("GET", "example.test", "/node/1"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"X-Generator", "Drupal 10 (https://www.drupal.org)"}}) });

    tc.append({ "ASP.NET via header", "fw-aspnet", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "x",
                 {{"X-AspNet-Version", "4.0.30319"},
                  {"X-Powered-By", "ASP.NET"}}) });

    tc.append({ "Next.js via __NEXT_DATA__", "fw-nextjs", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>x<script id=\"__NEXT_DATA__\" type=\"application/json\">{}</script></body></html>") });

    tc.append({ "Sitecore via /sitecore/ path", "cms-sitecore", false,
        makeReq("GET", "example.test", "/sitecore/login"),
        makeResp(200, "text/html", "<html>...</html>") });

    tc.append({ "Magento via X-Magento-Vary", "cms-magento", false,
        makeReq("GET", "shop.example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"X-Magento-Vary", "abc123"}}) });

    tc.append({ "Salesforce via Aura marker", "cms-salesforce", false,
        makeReq("GET", "example.my.salesforce.com", "/"),
        makeResp(200, "text/html",
                 "<html><body><script>Aura.Component=...</script></body></html>") });

    // ---- Negative controls ---------------------------------------------
    tc.append({ "marketing page -> no exposed-dev finding",
                "exposed-dev-file", true,
        makeReq("GET", "example.com", "/about"),
        makeResp(200, "text/html",
                 "<html><body><h1>About</h1></body></html>",
                 {{"Server", "nginx"}}) });

    tc.append({ "JSON API -> no missing-csp finding",
                "missing-csp", true,
        makeReq("GET", "api.example.test", "/v1/users/42"),
        makeResp(200, "application/json", "{\"id\":42}") });

    return tc;
}

const QString containsKind(const QList<Finding> &findings, const QString &kind) {
    for (const auto &f : findings) {
        if (f.kind == kind) return f.evidence;
    }
    return QString();
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("Nullock");
    QCoreApplication::setApplicationName("scanner-regression");

    int pass = 0, fail = 0;
    QStringList failures;

    for (const auto &t : buildCorpus()) {
        // Fresh scanner per case so finding counters don't bleed.
        PassiveScanner scanner;
        scanner.setNextRowId(1);
        scanner.onResponseReceived(t.req, t.resp);
        const auto findings = scanner.findings(200);

        const QString expected = QString::fromLatin1(t.expectedKind);
        const QString evidence = containsKind(findings, expected);
        const bool present = !evidence.isNull();
        const bool ok = t.negative ? !present : present;

        if (ok) {
            std::fprintf(stderr, "  PASS  %s\n", t.label);
            ++pass;
        } else {
            std::fprintf(stderr, "  FAIL  %s  (%s kind=%s, got %s)\n",
                         t.label,
                         t.negative ? "did not expect" : "expected",
                         t.expectedKind,
                         present ? "present" : "absent");
            ++fail;
            failures << QString::fromLatin1(t.label);
        }
    }

    std::fprintf(stderr,
        "\n========================================\n"
        "Scanner regression: %d passed, %d failed\n"
        "========================================\n",
        pass, fail);
    if (fail > 0) {
        std::fprintf(stderr, "Failures:\n");
        for (const QString &f : failures)
            std::fprintf(stderr, "  - %s\n", f.toLocal8Bit().constData());
    }
    return fail == 0 ? 0 : 1;
}

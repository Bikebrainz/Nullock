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
#include <QElapsedTimer>
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

    // ---- Other cloud-storage endpoints (were untested) -----------------
    // Only cloud-s3-bucket had coverage; GCS / Azure Blob / Firebase RTDB /
    // Firebase Storage did not, so a broken bucket-URL regex would have
    // silently stopped surfacing exposed public storage. These are gated on
    // an HTML content-type and run WITHOUT a first-match break, so each body
    // carries exactly one bucket URL for a clean assertion.
    tc.append({ "GCS bucket URL in HTML -> cloud-gcs-bucket", "cloud-gcs-bucket", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>dump at "
                 "https://storage.googleapis.com/my-bucket/key.json</body></html>") });

    tc.append({ "Azure Blob URL in HTML -> cloud-azure-blob", "cloud-azure-blob", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>see "
                 "https://myacct.blob.core.windows.net/container/blob.txt</body></html>") });

    tc.append({ "Firebase RTDB URL in HTML -> cloud-firebase", "cloud-firebase", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>db "
                 "https://myapp-default-rtdb.firebaseio.com/users.json</body></html>") });

    tc.append({ "Firebase Storage URL in HTML -> cloud-firebase-storage",
                "cloud-firebase-storage", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>img "
                 "https://firebasestorage.googleapis.com/v0/b/app.appspot.com/o/f.png"
                 "</body></html>") });

    // Content-type gate: a GCS URL in a NON-HTML body (JSON) must NOT fire --
    // the cloud detector only scans HTML/XHTML responses.
    tc.append({ "GCS URL in a JSON body must NOT fire cloud-gcs-bucket",
                "cloud-gcs-bucket", true,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json",
                 "{\"url\":\"https://storage.googleapis.com/my-bucket/key.json\"}") });

    // Precision: a look-alike host that merely *contains* the real host as a
    // prefix (storage.googleapis.com.evil.test) must NOT fire -- the regex
    // requires the exact host immediately followed by a path separator, so a
    // suffix-append phishing domain is not a match.
    tc.append({ "look-alike storage.googleapis.com.evil host must NOT fire cloud-gcs-bucket",
                "cloud-gcs-bucket", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><body>https://storage.googleapis.com.evil.test/x</body></html>") });

    // ---- Inline-JS DOM-XSS sinks + credential storage (were untested) --
    // Gated on an HTML content-type. The dom-* table is first-match-wins with
    // a break, so each positive body carries exactly one sink pattern and none
    // listed above it (this also pins the table ordering). storage-of-secrets
    // is a separate detector under the same HTML gate.
    tc.append({ "innerHTML <- location -> dom-xss-innerhtml-location",
                "dom-xss-innerhtml-location", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>el.innerHTML = location.hash;</script></html>") });

    tc.append({ "setTimeout(location...) -> dom-xss-eval-location",
                "dom-xss-eval-location", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>setTimeout(location.hash, 100);</script></html>") });

    tc.append({ "postMessage(_, '*') -> dom-postmessage-wildcard",
                "dom-postmessage-wildcard", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>win.postMessage(payload, '*');</script></html>") });

    tc.append({ "eval(xhr.responseText) -> dom-eval-of-fetch",
                "dom-eval-of-fetch", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>eval(xhr.responseText);</script></html>") });

    tc.append({ "localStorage.setItem('token',...) -> storage-of-secrets",
                "storage-of-secrets", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>localStorage.setItem('token', t);</script></html>") });

    // Content-type gate: the same innerHTML<-location sink in a NON-HTML body
    // (an external script served as application/javascript) must NOT fire --
    // the DOM-sink scan only runs on HTML/XHTML responses.
    tc.append({ "innerHTML<-location in a JS body must NOT fire dom-xss-innerhtml-location",
                "dom-xss-innerhtml-location", true,
        makeReq("GET", "example.test", "/app.js"),
        makeResp(200, "application/javascript",
                 "el.innerHTML = location.hash;") });

    // Precision: postMessage with an EXPLICIT target origin (not '*') must NOT
    // fire -- the detector keys on the wildcard origin, not on postMessage.
    tc.append({ "postMessage with explicit origin must NOT fire dom-postmessage-wildcard",
                "dom-postmessage-wildcard", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>win.postMessage(payload, 'https://example.test');"
                 "</script></html>") });

    // Precision: innerHTML assigned a STATIC string (no location/referrer/name
    // source) must NOT fire -- the sink keys on a tainted source.
    tc.append({ "innerHTML = static string must NOT fire dom-xss-innerhtml-location",
                "dom-xss-innerhtml-location", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>el.innerHTML = 'hello world';</script></html>") });

    // ---- Outbound PII to public hosts (were untested; email-mass covered)
    // The pii-* block is OUTBOUND-only: it scans req.path + req.body and only
    // when the destination host is PUBLIC (not 127./10./192.168./172. prefix,
    // not .local/.internal/.corp suffix). Each token below is chosen to match
    // exactly one kind.
    {
        // Build the test PAN from fragments so no 16-digit card-shaped literal
        // sits in the source. 4111... is a classic NON-LIVE test Visa; the
        // detector matches the card SHAPE, not a live/Luhn-valid number.
        const QByteArray pan = QByteArray("card=") + "4" + QByteArray("1").repeated(15);

        tc.append({ "outbound SSN to public host -> pii-ssn-outbound",
                    "pii-ssn-outbound", false,
            makeReq("POST", "analytics.public.test", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });

        tc.append({ "outbound test-PAN to public host -> pii-cc-outbound",
                    "pii-cc-outbound", false,
            makeReq("POST", "analytics.public.test", "/collect", {}, pan),
            makeResp(200, "application/json", "{}") });

        tc.append({ "outbound US phone to public host -> pii-phone-us",
                    "pii-phone-us", false,
            makeReq("POST", "analytics.public.test", "/collect", {}, "phone=415-555-2671"),
            makeResp(200, "application/json", "{}") });

        tc.append({ "outbound IBAN to public host -> pii-iban",
                    "pii-iban", false,
            makeReq("POST", "analytics.public.test", "/collect", {},
                    "iban=DE89370400440532013000"),
            makeResp(200, "application/json", "{}") });

        // Private-host gate (two arms): the SAME SSN to a private / internal
        // destination must NOT fire -- the detector only flags exfiltration to
        // PUBLIC hosts.
        tc.append({ "SSN to a 10.x host must NOT fire pii-ssn-outbound",
                    "pii-ssn-outbound", true,
            makeReq("POST", "10.0.0.5", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });

        tc.append({ "SSN to a .internal host must NOT fire pii-ssn-outbound",
                    "pii-ssn-outbound", true,
            makeReq("POST", "db.internal", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });

        // RFC-1918 172.16.0.0/12 is ONLY 172.16.x - 172.31.x. Public 172.x hosts
        // (172.0-15.x, 172.32-255.x) must be treated as PUBLIC so exfiltration to
        // them is flagged. These lock the corrected second-octet boundary.
        tc.append({ "SSN to public 172.200.x host -> FIRES pii-ssn-outbound (172 quirk fix)",
                    "pii-ssn-outbound", false,
            makeReq("POST", "172.200.1.1", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });
        tc.append({ "SSN to 172.15.x (just below private range) -> FIRES",
                    "pii-ssn-outbound", false,
            makeReq("POST", "172.15.255.255", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });
        tc.append({ "SSN to 172.32.x (just above private range) -> FIRES",
                    "pii-ssn-outbound", false,
            makeReq("POST", "172.32.0.1", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });

        // ...but the genuine RFC-1918 172.16-31.x range stays private (no fire).
        tc.append({ "SSN to 172.16.x (RFC-1918 private) -> NOT fire",
                    "pii-ssn-outbound", true,
            makeReq("POST", "172.16.0.5", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });
        tc.append({ "SSN to 172.31.x (RFC-1918 private upper bound) -> NOT fire",
                    "pii-ssn-outbound", true,
            makeReq("POST", "172.31.255.255", "/collect", {}, "ssn=123-45-6789"),
            makeResp(200, "application/json", "{}") });
    }

    // ---- Verbose 4xx error leaks (were untested) -----------------------
    // Gate: 400 <= status < 500 AND body < 256KB. The needle table is scanned
    // first-match-wins with a break and matched CASE-SENSITIVELY, so each body
    // uses the exact needle case and carries no needle listed above it. One
    // positive per needle (11) locks each row independently -- a typo in any one
    // needle silently kills that leak detector.
    // verbose-sql-err (6 needles):
    tc.append({ "Oracle ORA- error 400 -> verbose-sql-err", "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain", "ORA-00933: SQL command not properly ended") });

    tc.append({ "MySQL error 400 -> verbose-sql-err", "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain",
                 "You have an error in your SQL syntax; check the manual that "
                 "corresponds to your MySQL server version") });

    tc.append({ "Postgres 'syntax error at or near' 400 -> verbose-sql-err",
                "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain", "ERROR: syntax error at or near \"FROM\"") });

    tc.append({ "MSSQL OLE DB error 400 -> verbose-sql-err", "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain",
                 "Microsoft OLE DB Provider for SQL Server error '80040e14'") });

    tc.append({ "MSSQL ODBC driver error 400 -> verbose-sql-err", "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain",
                 "[ODBC SQL Server Driver][SQL Server]Unclosed quotation mark") });

    tc.append({ "SQLite OperationalError 400 -> verbose-sql-err", "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(400, "text/plain", "sqlite3.OperationalError: no such table: users") });

    // verbose-php-err (2 needles -- note the trailing space in the needle):
    tc.append({ "PHP Warning 400 -> verbose-php-err", "verbose-php-err", false,
        makeReq("GET", "api.example.test", "/p"),
        makeResp(400, "text/html",
                 "Warning: mysqli_connect(): Access denied for user") });

    tc.append({ "PHP Notice 400 -> verbose-php-err", "verbose-php-err", false,
        makeReq("GET", "api.example.test", "/p"),
        makeResp(400, "text/html",
                 "Notice: Undefined variable: id in /var/www/app.php on line 12") });

    // verbose-debug-page (3 needles):
    tc.append({ "Werkzeug debug page 400 -> verbose-debug-page", "verbose-debug-page", false,
        makeReq("GET", "api.example.test", "/x"),
        makeResp(400, "text/html", "<title>Werkzeug Debugger</title>") });

    tc.append({ "Whoops error page 404 -> verbose-debug-page", "verbose-debug-page", false,
        makeReq("GET", "api.example.test", "/x"),
        makeResp(404, "text/html", "<h1>Whoops! There was an error.</h1>") });

    tc.append({ "Symfony exception page 404 -> verbose-debug-page", "verbose-debug-page", false,
        makeReq("GET", "api.example.test", "/x"),
        makeResp(404, "text/html", "<title>Symfony Exception</title>") });

    // Per-needle status policy (Q3 fix). SQL-error signatures are specific
    // enough to flag on ANY status: an app that catches the DB error and echoes
    // it in a 200 IS leaking it, and a 5xx that dumps it is too.
    tc.append({ "ORA- error echoed in a 200 body -> FIRES verbose-sql-err",
                "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(200, "text/plain", "ORA-00933: SQL command not properly ended") });
    tc.append({ "ORA- error in a 500 body -> FIRES verbose-sql-err",
                "verbose-sql-err", false,
        makeReq("GET", "api.example.test", "/q"),
        makeResp(500, "text/plain", "ORA-00933: SQL command not properly ended") });

    // Framework DEBUG pages render on 5xx too (not only 4xx) -- must fire there.
    tc.append({ "Werkzeug debug page on a 500 -> FIRES verbose-debug-page",
                "verbose-debug-page", false,
        makeReq("GET", "api.example.test", "/x"),
        makeResp(500, "text/html", "<title>Werkzeug Debugger</title>") });

    // CRITICAL FP guards: the php Warning/Notice needles are ordinary English
    // that appears in normal 200 content -- they must stay 4xx-only and NOT fire
    // on a 200. (If a future edit widens them, these fail.)
    tc.append({ "'Warning: low battery' in a 200 body must NOT fire verbose-php-err",
                "verbose-php-err", true,
        makeReq("GET", "api.example.test", "/status"),
        makeResp(200, "text/html", "<p>Warning: low battery. Please charge.</p>") });
    tc.append({ "'Notice: cookies' in a 200 body must NOT fire verbose-php-err",
                "verbose-php-err", true,
        makeReq("GET", "api.example.test", "/"),
        makeResp(200, "text/html", "<div>Notice: this site uses cookies.</div>") });

    // ...and php Warning/Notice stays 4xx-only on the 5xx side too.
    tc.append({ "'Warning: ' in a 500 body must NOT fire verbose-php-err (4xx-only)",
                "verbose-php-err", true,
        makeReq("GET", "api.example.test", "/x"),
        makeResp(500, "text/html", "Warning: something happened server-side") });

    // Debug-page needles are error-page markers: the LITERAL needle in a 200
    // body must NOT fire (debug pages are 4xx/5xx only). Same needle as the
    // 4xx positive above -- only the 200 status suppresses it.
    tc.append({ "literal Symfony marker in a 200 body must NOT fire verbose-debug-page",
                "verbose-debug-page", true,
        makeReq("GET", "api.example.test", "/blog"),
        makeResp(200, "text/html", "<title>Symfony Exception</title>") });

    // ---- Subdomain-takeover cargo FP removed ---------------------------
    tc.append({ "default 404 body must NOT fire takeover-cargo", "takeover-cargo", true,
        makeReq("GET", "example.test", "/missing"),
        makeResp(404, "text/html",
                 "<html><head><title>404 Not Found</title></head>"
                 "<body><h1>404 Not Found</h1><hr>nginx</body></html>") });

    // ---- Subdomain-takeover POSITIVE locks (were untested) -------------
    // Each vendor error-page needle raises a HIGH takeover finding, but ONLY
    // on a 404/503 response. One positive per vendor, plus a 503-branch lock
    // (s3 at 503) and a status-gate negative (same needle in a 200 body must
    // NOT fire). Bodies each contain exactly one vendor needle so the first-
    // match-wins break resolves to that vendor's kind.
    tc.append({ "S3 NoSuchBucket at 503 -> takeover-s3", "takeover-s3", false,
        makeReq("GET", "assets.example.test", "/logo.png"),
        makeResp(503, "application/xml",
                 "<Error><Code>NoSuchBucket</Code>"
                 "<Message>The specified bucket does not exist</Message></Error>") });

    tc.append({ "NoSuchBucket in a 200 body must NOT fire takeover-s3",
                "takeover-s3", true,
        makeReq("GET", "assets.example.test", "/"),
        makeResp(200, "application/xml",
                 "<Error><Code>NoSuchBucket</Code></Error>") });

    tc.append({ "Heroku 'No such app' 404 -> takeover-heroku", "takeover-heroku", false,
        makeReq("GET", "app.example.test", "/"),
        makeResp(404, "text/html",
                 "<html><body><h1>No such app</h1>"
                 "<p>There's nothing here, yet.</p></body></html>") });

    tc.append({ "GitHub Pages 404 -> takeover-github", "takeover-github", false,
        makeReq("GET", "docs.example.test", "/"),
        makeResp(404, "text/html",
                 "<html><body><h1>404</h1>"
                 "<p>There isn't a GitHub Pages site here.</p></body></html>") });

    tc.append({ "Azure 'Web Site not found' 404 -> takeover-azure", "takeover-azure", false,
        makeReq("GET", "svc.example.test", "/"),
        makeResp(404, "text/html",
                 "<html><body>404 Web Site not found.</body></html>") });

    tc.append({ "Fastly unknown domain 404 -> takeover-fastly", "takeover-fastly", false,
        makeReq("GET", "cdn.example.test", "/"),
        makeResp(404, "text/plain",
                 "Fastly error: unknown domain: cdn.example.test") });

    tc.append({ "Shopify shop unavailable 404 -> takeover-shopify", "takeover-shopify", false,
        makeReq("GET", "shop.example.test", "/"),
        makeResp(404, "text/html",
                 "<html><body>Sorry, this shop is currently unavailable.</body></html>") });

    tc.append({ "Tumblr 'Whatever you were looking' 404 -> takeover-tumblr",
                "takeover-tumblr", false,
        makeReq("GET", "blog.example.test", "/"),
        makeResp(404, "text/html",
                 "<html><body>Whatever you were looking for doesn't currently "
                 "exist at this address.</body></html>") });

    // ---- CORS misconfiguration (were untested) -------------------------
    // Four independent CORS shapes, each its own severity. The wildcard/creds
    // pair is an if/else in the scanner -- ACAO:* WITH Allow-Credentials is the
    // HIGH finding, ACAO:* ALONE is the INFO one -- so the discriminating
    // negatives below pin that mutual exclusivity: neither may fire for the
    // other's shape, and a specific echoed origin is not a wildcard at all.
    tc.append({ "ACAO:* + Allow-Credentials:true -> cors-wildcard-creds",
                "cors-wildcard-creds", false,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "*"},
                  {"Access-Control-Allow-Credentials", "true"}}) });

    // Same ACAO:* response, no credentials -> the HIGH creds finding must NOT
    // fire (pins the Allow-Credentials condition, not just the ACAO one).
    tc.append({ "ACAO:* without credentials must NOT fire cors-wildcard-creds",
                "cors-wildcard-creds", true,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "*"}}) });

    tc.append({ "ACAO:* alone -> cors-wildcard (info)", "cors-wildcard", false,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "*"}}) });

    // With credentials the info-level cors-wildcard must NOT ALSO fire (it is
    // the else branch of the creds check) ...
    tc.append({ "ACAO:* + creds must NOT ALSO fire the info cors-wildcard",
                "cors-wildcard", true,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "*"},
                  {"Access-Control-Allow-Credentials", "true"}}) });

    // ... and a specific echoed origin is not a wildcard.
    tc.append({ "specific ACAO origin must NOT fire cors-wildcard",
                "cors-wildcard", true,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}",
                 {{"Access-Control-Allow-Origin", "https://app.example.test"}}) });

    tc.append({ "Allow-Methods contains * -> cors-methods-wildcard",
                "cors-methods-wildcard", false,
        makeReq("OPTIONS", "api.example.test", "/data"),
        makeResp(204, "", "",
                 {{"Access-Control-Allow-Methods", "GET, POST, *"}}) });

    tc.append({ "Allow-Methods without * must NOT fire cors-methods-wildcard",
                "cors-methods-wildcard", true,
        makeReq("OPTIONS", "api.example.test", "/data"),
        makeResp(204, "", "",
                 {{"Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"}}) });

    tc.append({ "Allow-Headers contains * -> cors-headers-wildcard",
                "cors-headers-wildcard", false,
        makeReq("OPTIONS", "api.example.test", "/data"),
        makeResp(204, "", "",
                 {{"Access-Control-Allow-Headers", "*"}}) });

    tc.append({ "Allow-Headers without * must NOT fire cors-headers-wildcard",
                "cors-headers-wildcard", true,
        makeReq("OPTIONS", "api.example.test", "/data"),
        makeResp(204, "", "",
                 {{"Access-Control-Allow-Headers", "Content-Type, Authorization"}}) });

    // ---- Cookie flag hygiene (were untested) ---------------------------
    // cookie-no-secure / cookie-no-samesite / cookie-secure-prefix-violation
    // had no coverage; each Set-Cookie is walked and flag-checked. A regression
    // here silently stops flagging insecure session cookies.

    // cookie-no-secure fires only on TLS responses whose cookie lacks Secure.
    tc.append({ "TLS Set-Cookie without Secure -> cookie-no-secure",
                "cookie-no-secure", false,
        makeReq("GET", "example.test", "/login"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; HttpOnly; SameSite=Lax"}}) });

    tc.append({ "TLS Set-Cookie WITH Secure must NOT fire cookie-no-secure",
                "cookie-no-secure", true,
        makeReq("GET", "example.test", "/login"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; Secure; HttpOnly; SameSite=Lax"}}) });

    // wasTls gate: the SAME insecure cookie over plaintext HTTP must NOT fire
    // cookie-no-secure (a plaintext connection has no Secure channel to demand).
    tc.append({ "plaintext Set-Cookie without Secure must NOT fire cookie-no-secure",
                "cookie-no-secure", true,
        makeReq("GET", "example.test", "/login", {}, {}, 80, false),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; HttpOnly; SameSite=Lax"}}, /*wasTls=*/false) });

    tc.append({ "Set-Cookie without SameSite -> cookie-no-samesite",
                "cookie-no-samesite", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; Secure; HttpOnly"}}) });

    tc.append({ "Set-Cookie WITH SameSite must NOT fire cookie-no-samesite",
                "cookie-no-samesite", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; Secure; HttpOnly; SameSite=Strict"}}) });

    // __Secure- prefix demands the Secure attribute.
    tc.append({ "__Secure- cookie without Secure -> cookie-secure-prefix-violation",
                "cookie-secure-prefix-violation", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "__Secure-sid=abc123; HttpOnly; SameSite=Lax"}}) });

    tc.append({ "__Secure- cookie WITH Secure must NOT fire the prefix violation",
                "cookie-secure-prefix-violation", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "__Secure-sid=abc123; Secure; HttpOnly; SameSite=Lax"}}) });

    // Prefix gate: a non-__Secure- cookie lacking Secure must NOT raise the
    // prefix violation (that shape is cookie-no-secure's job, not this one's).
    tc.append({ "non-prefixed insecure cookie must NOT fire the prefix violation",
                "cookie-secure-prefix-violation", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "sid=abc123; HttpOnly; SameSite=Lax"}}) });

    // ---- Cross-origin isolation headers (were untested) ----------------
    // missing-{permissions-policy,coop,coep,corp} fire on an html 2xx/3xx that
    // omits the header. Each negative supplies the header so it must not fire;
    // permissions-policy also honours the legacy Feature-Policy fallback. Two
    // gate negatives pin html-only + 2xx/3xx-only (a JSON body or a 5xx skips).
    tc.append({ "html without Permissions-Policy -> missing-permissions-policy",
                "missing-permissions-policy", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>") });

    // legacy Feature-Policy satisfies the check (the scanner &&s both).
    tc.append({ "legacy Feature-Policy must NOT fire missing-permissions-policy",
                "missing-permissions-policy", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Feature-Policy", "geolocation 'none'"}}) });

    tc.append({ "html without COOP -> missing-coop", "missing-coop", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>") });

    tc.append({ "COOP present must NOT fire missing-coop", "missing-coop", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Cross-Origin-Opener-Policy", "same-origin"}}) });

    tc.append({ "html without COEP -> missing-coep", "missing-coep", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>") });

    tc.append({ "COEP present must NOT fire missing-coep", "missing-coep", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Cross-Origin-Embedder-Policy", "require-corp"}}) });

    tc.append({ "html without CORP -> missing-corp", "missing-corp", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>") });

    tc.append({ "CORP present must NOT fire missing-corp", "missing-corp", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Cross-Origin-Resource-Policy", "same-origin"}}) });

    // html gate: a JSON response with no isolation headers must NOT fire.
    tc.append({ "non-html response must NOT fire missing-coop", "missing-coop", true,
        makeReq("GET", "api.example.test", "/data"),
        makeResp(200, "application/json", "{}") });

    // status gate: a 5xx html response is out of the 2xx/3xx window.
    tc.append({ "5xx html must NOT fire missing-coop", "missing-coop", true,
        makeReq("GET", "example.test", "/boom"),
        makeResp(500, "text/html", "<html>err</html>") });

    // ---- CSP granular weaknesses (were untested) -----------------------
    // A present CSP can still be weak. Each directive check is independent;
    // csp-unsafe-eval / csp-wildcard-src / csp-no-form-action / csp-no-base-uri
    // had no coverage. All gated on a non-empty Content-Security-Policy header.
    tc.append({ "CSP with 'unsafe-eval' -> csp-unsafe-eval", "csp-unsafe-eval", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy",
                   "default-src 'self'; script-src 'self' 'unsafe-eval'"}}) });

    tc.append({ "CSP without 'unsafe-eval' must NOT fire csp-unsafe-eval",
                "csp-unsafe-eval", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'; script-src 'self'"}}) });

    tc.append({ "CSP with a bare '*' source -> csp-wildcard-src", "csp-wildcard-src", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'; img-src *"}}) });

    // Discriminator: a wildcard SUBDOMAIN (*.host) is not a bare '*' -- the
    // detector flags only a standalone any-origin '*', so this must NOT fire.
    tc.append({ "CSP wildcard subdomain must NOT fire csp-wildcard-src",
                "csp-wildcard-src", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy",
                   "default-src 'self'; img-src 'self' *.cdn.example.test"}}) });

    tc.append({ "CSP missing form-action -> csp-no-form-action", "csp-no-form-action", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'"}}) });

    tc.append({ "CSP with form-action must NOT fire csp-no-form-action",
                "csp-no-form-action", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'; form-action 'self'"}}) });

    tc.append({ "CSP missing base-uri -> csp-no-base-uri", "csp-no-base-uri", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'"}}) });

    tc.append({ "CSP with base-uri must NOT fire csp-no-base-uri",
                "csp-no-base-uri", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Content-Security-Policy", "default-src 'self'; base-uri 'self'"}}) });

    // ---- Server-error stack-trace fingerprints (were untested) ---------
    // A 5xx body leaking an internal stack trace tells an attacker which
    // framework + line numbers to hit. Gated on statusCode >= 500; the
    // needle table is scanned first-match-wins with a break, so each fixture
    // below is crafted to contain EXACTLY its own vendor needle and none of
    // the needles listed above it -- if the table is ever reordered so an
    // earlier row shadows a later one, that vendor's case flips to the wrong
    // kind and fails here.
    tc.append({ "Python traceback 500 -> stack-python", "stack-python", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "Traceback (most recent call last):\n"
                 "  File /app/views.py line 42 in get\n"
                 "    raise ValueError\nValueError: boom\n") });

    // Status gate: the same traceback in a 200 body must NOT fire (a 200 that
    // merely quotes a stack trace, e.g. a docs/paste page, is not a leak).
    tc.append({ "Python traceback in a 200 body must NOT fire stack-python",
                "stack-python", true,
        makeReq("GET", "docs.example.test", "/paste"),
        makeResp(200, "text/plain",
                 "Traceback (most recent call last):\n"
                 "  File /app/views.py line 42 in get\n") });

    tc.append({ "Java stack 500 -> stack-java", "stack-java", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "java.lang.NullPointerException\n"
                 "\tat com.example.Service.handle(Service.java:88)\n") });

    tc.append({ ".NET stack 500 -> stack-dotnet", "stack-dotnet", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "System.NullReferenceException: Object reference not set.\n"
                 "   at System.Web.Mvc.ActionMethodDispatcher.Execute()\n") });

    tc.append({ "PHP stack 500 -> stack-php", "stack-php", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "Fatal error: Uncaught Exception: boom in /var/www/index.php:10\n"
                 "Stack trace:\n#0 /var/www/app.php(5): doThing()\n") });

    tc.append({ "Ruby stack 500 -> stack-ruby", "stack-ruby", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "NoMethodError: undefined method foo for nil:NilClass\n"
                 "\tfrom /usr/lib/ruby/3.0.0/app.rb:22\n") });

    tc.append({ "Node stack 500 -> stack-node", "stack-node", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "TypeError: Cannot read properties of undefined\n"
                 "    at Object.<anonymous> (/app/index.js:5:10)\n") });

    tc.append({ "Rails stack 500 -> stack-rails", "stack-rails", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "ActionController::RoutingError (No route matches [GET] /foo):\n"
                 "  actionpack (7.0.0) lib/action_dispatch/middleware/debug.rb:1\n") });

    tc.append({ "Django URLconf leak 500 -> stack-django", "stack-django", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/html",
                 "Using the URLconf defined in myproject.urls, "
                 "Django tried these URL patterns, in this order:\n"
                 "1. admin/\n2. api/\n") });

    // Django's DEBUG page renders the URLconf resolver on a 404 (not only 5xx),
    // so the real-world exposure IS a 404 -- the detector must fire there. This
    // is the previously-dead-row fix: with the old >=500 gate this case did not
    // fire at all.
    tc.append({ "Django URLconf leak 404 -> stack-django (dead-row fix)",
                "stack-django", false,
        makeReq("GET", "api.example.test", "/missing"),
        makeResp(404, "text/html",
                 "Page not found (404)\n"
                 "Using the URLconf defined in myproject.urls, "
                 "Django tried these URL patterns, in this order:\n"
                 "1. admin/\n2. api/\n") });

    // Gate precision: the 404 arm is Django-ONLY. A generic 404 page that merely
    // mentions a framework stack token ("java.lang.") must NOT fire -- otherwise
    // every not-found page quoting a class name becomes a false stack leak.
    tc.append({ "generic 404 mentioning java.lang. must NOT fire stack-java",
                "stack-java", true,
        makeReq("GET", "api.example.test", "/missing"),
        makeResp(404, "text/html",
                 "<html><body>Not found. Contact support re: "
                 "java.lang.NullPointerException tickets.</body></html>") });

    tc.append({ "Spring stack 500 -> stack-spring", "stack-spring", false,
        makeReq("GET", "api.example.test", "/boom"),
        makeResp(500, "text/plain",
                 "org.springframework.beans.factory.BeanCreationException: "
                 "Error creating bean userService\n"
                 "\tat org.springframework.beans.factory.support."
                 "AbstractAutowireCapableBeanFactory.doCreateBean()\n") });

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

    // The other 7 leaked-* patterns had NO test -- lock them here. Each secret is
    // BUILT AT RUNTIME from fragments so no literal secret-shaped string sits in
    // the source (trips push-protection / our own secret scan otherwise).
    {
        const QByteArray a36(36, 'a'), a35(35, 'a'), a40(40, 'a'),
                         a22(22, 'a'), a43(43, 'a'), a20(20, 'a');
        auto j = [](const QByteArray &v) { return QByteArray("{\"k\":\"") + v + "\"}"; };
        const QByteArray us("_"), dot(".");
        tc.append({ "leaked GitHub App token", "leaked-gh-app", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", j(QByteArray("ghs") + us + a36)) });
        tc.append({ "leaked Slack bot token", "leaked-slack", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", j(QByteArray("xox") + "b" + "-1234567890-abcdef")) });
        tc.append({ "leaked SendGrid API key", "leaked-sendgrid", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", j(QByteArray("SG") + dot + a22 + dot + a43)) });
        tc.append({ "leaked Mapbox token", "leaked-mapbox", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", j(QByteArray("pk") + dot + "eyJ" + a20 + dot + a20)) });
        tc.append({ "leaked Google API key", "leaked-google-api", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json", j(QByteArray("AI") + "za" + a35)) });
        tc.append({ "leaked PEM private key block", "leaked-private-key", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "text/plain",
                     QByteArray("-----") + "BEGIN " + "PRIVATE KEY" + "-----\n" + a40) });
        tc.append({ "leaked AWS secret (with aws/secret/access context)", "leaked-aws-secret", false,
            makeReq("GET", "example.test", "/"),
            makeResp(200, "application/json",
                     QByteArray("{\"aws_secret_access_key\":\"") + a40 + "\"}") });
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

    // The dev-tool table is scanned first-match-wins with a break, so a generic
    // needle above a specific one silently kills the specific row. "/actuator/"
    // used to sit above these two, which made BOTH unreachable for every input:
    // a leaked heapdump reported as a plain actuator hit and lost its critical
    // severity. These two cases fail if the table is ever reordered back.
    tc.append({ "spring-actuator-env is not shadowed by the generic /actuator/ row",
                "spring-actuator-env", false,
        makeReq("GET", "api.example.test", "/actuator/env"),
        makeResp(200, "application/json", "{\"propertySources\":[]}") });

    tc.append({ "spring-actuator-heap is not shadowed by the generic /actuator/ row",
                "spring-actuator-heap", false,
        makeReq("GET", "api.example.test", "/actuator/heapdump"),
        makeResp(200, "application/octet-stream", "JAVA PROFILE 1.0.2") });

    tc.append({ "tomcat-manager", "tomcat-manager", false,
        makeReq("GET", "example.test", "/manager/html"),
        makeResp(200, "text/html", "<title>Tomcat Manager</title>") });

    // ---- Cookie broad-path ---------------------------------------------
    // The finding text asserts the cookie is "scoped to whole origin", so the
    // Path test must be the tokenized one. contains("path=/") also matches
    // Path=/app, which is NOT origin-wide -- and the __Host- branch a few
    // lines above already tokenizes correctly, so the file disagreed with
    // itself about the same idiom.
    tc.append({ "cookie Path=/app + no SameSite is not origin-wide",
                "cookie-broad-path-no-samesite", true,
        makeReq("GET", "shop.example.test", "/app/cart"),
        makeResp(200, "text/html", "<html></html>",
                 { { "Set-Cookie", "sid=abc123; Path=/app; Secure" } }) });

    tc.append({ "cookie Path=/ + no SameSite still fires",
                "cookie-broad-path-no-samesite", false,
        makeReq("GET", "shop.example.test", "/"),
        makeResp(200, "text/html", "<html></html>",
                 { { "Set-Cookie", "sid=abc123; Path=/; Secure" } }) });

    // ---- Reflected file download --------------------------------------
    // The needle is the first query param's VALUE. A valueless param yields an
    // empty needle, and QString::contains(QString()) is TRUE -- so without an
    // emptiness guard these two fire against a filename that mirrors nothing.
    // A valueless flag param is ordinary in download endpoints, so this was a
    // live FP source.
    tc.append({ "RFD: valueless param does not mirror anything",
                "reflected-file-download", true,
        makeReq("GET", "files.example.test", "/export?csv"),
        makeResp(200, "text/csv", "a,b\n1,2\n",
                 { { "Content-Disposition", "attachment; filename=\"quarterly.csv\"" } }) });

    tc.append({ "RFD: empty first param value does not mirror anything",
                "reflected-file-download", true,
        makeReq("GET", "files.example.test", "/dl?a=&b=x"),
        makeResp(200, "application/pdf", "%PDF-1.4",
                 { { "Content-Disposition", "attachment; filename=\"statement.pdf\"" } }) });

    // Not over-broad: a filename that genuinely mirrors the param value fires.
    tc.append({ "RFD: filename mirroring the param value still fires",
                "reflected-file-download", false,
        makeReq("GET", "files.example.test", "/dl?name=payroll"),
        makeResp(200, "application/octet-stream", "x",
                 { { "Content-Disposition", "attachment; filename=\"payroll.exe\"" } }) });

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

    // Python pickle / Ruby Marshal / .NET BinaryFormatter magic prefixes were
    // untested. Each keys off a base64 magic prefix in the REQUEST body; each
    // negative is a one-char-off near-miss that pins the exact (deliberately
    // narrow) needle -- e.g. pickle matches "gASV" but not "gASX".
    tc.append({ "Python pickle magic in request body -> deser-pickle",
                "deser-pickle", false,
        makeReq("POST", "example.test", "/api", {},
                "state=gASVEAAAAAAAAACMBWhlbGxvlC4="),
        makeResp(200, "application/json", "{}") });

    tc.append({ "near-miss gASX must NOT fire deser-pickle", "deser-pickle", true,
        makeReq("POST", "example.test", "/api", {},
                "state=gASXEAAAAAAAAACMBWhlbGxvlC4="),
        makeResp(200, "application/json", "{}") });

    tc.append({ "Ruby Marshal magic in request body -> deser-ruby",
                "deser-ruby", false,
        makeReq("POST", "example.test", "/api", {},
                "m=BAhJIgpoZWxsbwY6BkVU"),
        makeResp(200, "application/json", "{}") });

    tc.append({ "near-miss BAg must NOT fire deser-ruby", "deser-ruby", true,
        makeReq("POST", "example.test", "/api", {},
                "m=BAgJIgpoZWxsbwY6BkVU"),
        makeResp(200, "application/json", "{}") });

    tc.append({ ".NET BinaryFormatter magic in request body -> deser-dotnet",
                "deser-dotnet", false,
        makeReq("POST", "example.test", "/api", {},
                "d=AAEAAAD/////AQAAAAAAAAAMAgAAAA=="),
        makeResp(200, "application/json", "{}") });

    tc.append({ "near-miss AAEAAAA must NOT fire deser-dotnet", "deser-dotnet", true,
        makeReq("POST", "example.test", "/api", {},
                "d=AAEAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
        makeResp(200, "application/json", "{}") });

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

    // ---- Framework fingerprints (were untested) ------------------------
    // Header-, cookie-, and body-marker fingerprints. The cookie-based ones
    // (rails/laravel/django) use REALISTIC responses that set the framework
    // cookie as a SEPARATE Set-Cookie header (often not the first) -- the shape
    // real servers emit -- to cover the scan-all-Set-Cookies path.
    tc.append({ "Express via X-Powered-By -> fw-express", "fw-express", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>", {{"X-Powered-By", "Express"}}) });

    tc.append({ "Nuxt via window.__NUXT__ -> fw-nuxt", "fw-nuxt", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>window.__NUXT__={data:[]}</script></html>") });

    tc.append({ "AngularJS via ng-app -> fw-angularjs", "fw-angularjs", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html ng-app=\"myApp\"><body>x</body></html>") });

    tc.append({ "React via data-reactroot -> fw-react", "fw-react", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<div data-reactroot=\"\">x</div>") });

    tc.append({ "Vue via data-server-rendered -> fw-vue", "fw-vue", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<div id=\"app\" data-server-rendered=\"true\">x</div>") });

    tc.append({ "Rails via _session_id (non-first cookie) -> fw-rails", "fw-rails", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "remember_token=z; Path=/"},
                  {"Set-Cookie", "_session_id=abc123; HttpOnly; Path=/"}}) });

    tc.append({ "Laravel via laravel_session (non-first cookie) -> fw-laravel", "fw-laravel", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "XSRF-TOKEN=z; Path=/"},
                  {"Set-Cookie", "laravel_session=abc123; HttpOnly; Path=/"}}) });

    tc.append({ "Django via csrftoken + sessionid (separate cookies) -> fw-django", "fw-django", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "csrftoken=abc; Path=/"},
                  {"Set-Cookie", "sessionid=def; HttpOnly; Path=/"}}) });

    // Django needs BOTH cookies: csrftoken alone must NOT fire.
    tc.append({ "csrftoken WITHOUT sessionid must NOT fire fw-django", "fw-django", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>",
                 {{"Set-Cookie", "csrftoken=abc; Path=/"}}) });

    tc.append({ "Symfony via X-Debug-Token -> fw-symfony", "fw-symfony", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html>x</html>", {{"X-Debug-Token", "a1b2c3"}}) });

    tc.append({ "Inlined initial-state JSON -> fw-spa-state-leak", "fw-spa-state-leak", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html",
                 "<html><script>window.__INITIAL_STATE__={user:1}</script></html>") });

    // FP control: a plain page with no framework markers fires none of them.
    tc.append({ "plain page must NOT fire fw-react", "fw-react", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html><body>hello</body></html>") });

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

    // ---- audit-4: internal-ip-leak on the two most common private ranges ----
    // (the old regex required a spurious 5th octet, so 192.168.x.x / 172.16-31.x.x
    //  never matched -- only 10.x and 127.x did.)
    tc.append({ "192.168.x.x private IP in HTML body -> internal-ip-leak",
                "internal-ip-leak", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html><body>gateway at 192.168.1.1</body></html>") });

    tc.append({ "172.16.x.x private IP in HTML body -> internal-ip-leak",
                "internal-ip-leak", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html><body>host 172.16.0.1 internal</body></html>") });

    tc.append({ "public IP 8.8.8.8 -> no internal-ip-leak",
                "internal-ip-leak", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "<html><body>resolver 8.8.8.8</body></html>") });

    // ---- audit-4: CSWSH sibling-domain must not slip past a dot-anchor -------
    tc.append({ "101 WS accept from attacker sibling origin -> ws-cross-origin-accepted",
                "ws-cross-origin-accepted", false,
        makeReq("GET", "example.com", "/socket", {{"Origin", "https://evil-example.com"}}),
        makeResp(101, "", {}) });

    tc.append({ "101 WS accept from a true subdomain origin -> no ws-cross-origin-accepted",
                "ws-cross-origin-accepted", true,
        makeReq("GET", "example.com", "/socket", {{"Origin", "https://app.example.com"}}),
        makeResp(101, "", {}) });

    // ---- audit-4: __Host- cookie with a non-root Path is a prefix violation --
    tc.append({ "__Host- cookie with Path=/app (non-root) -> cookie-host-prefix-violation",
                "cookie-host-prefix-violation", false,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "x",
                 {{"Set-Cookie", "__Host-sid=abc; Secure; Path=/app"}}) });

    tc.append({ "__Host- cookie Secure + Path=/ (valid) -> no violation",
                "cookie-host-prefix-violation", true,
        makeReq("GET", "example.test", "/"),
        makeResp(200, "text/html", "x",
                 {{"Set-Cookie", "__Host-sid=abc; Secure; Path=/"}}) });

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

    // A linear scan of even the 500KB ReDoS-regression bodies is well under this;
    // a reintroduced catastrophic / O(n^2) regex on the MAIN-thread passive
    // scanner blows past it. This turns the "must complete fast" ReDoS-regression
    // cases into an ENFORCED timed guard instead of only a finding-absence check.
    constexpr qint64 kPerCaseBudgetMs = 2000;
    for (const auto &t : buildCorpus()) {
        // Fresh scanner per case so finding counters don't bleed.
        PassiveScanner scanner;
        scanner.setNextRowId(1);
        QElapsedTimer caseTimer;
        caseTimer.start();
        scanner.onResponseReceived(t.req, t.resp);
        const qint64 caseMs = caseTimer.elapsed();
        const auto findings = scanner.findings(200);

        const QString expected = QString::fromLatin1(t.expectedKind);
        const QString evidence = containsKind(findings, expected);
        const bool present = !evidence.isNull();
        const bool findingOk = t.negative ? !present : present;
        const bool timeOk = caseMs <= kPerCaseBudgetMs;

        if (findingOk && timeOk) {
            std::fprintf(stderr, "  PASS  %s  (%lldms)\n", t.label, (long long)caseMs);
            ++pass;
        } else {
            if (!timeOk)
                std::fprintf(stderr, "  FAIL  %s  (%lldms > %lldms budget -- possible ReDoS)\n",
                             t.label, (long long)caseMs, (long long)kPerCaseBudgetMs);
            else
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

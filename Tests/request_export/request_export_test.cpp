// Regression corpus for RequestExport (CSRF PoC + copy-as-curl).
//
// These are pure transforms, so they unit-test directly (no headless server)
// -- locking in the escaping/structure that the /api/csrf/poc and
// /api/request/curl endpoints depend on.
//
// Run via:  ctest -R request_export -V
// or:       ./Tests/request_export/request_export_test

#include "request_export.hpp"

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QList>
#include <QPair>

#include <cstdio>

using namespace Nullock::Core;

namespace {

int pass = 0, fail = 0;
QStringList failures;

void chk(const char *label, bool ok) {
    if (ok) { ++pass; }
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; failures << label; }
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- CSRF PoC: form-urlencoded POST -------------------------------
    {
        QString note;
        const QString h = RequestExport::csrfPoc(
            "POST", "http://victim.test/account/role",
            "application/x-www-form-urlencoded", "user=admin&role=super\"x", note);
        chk("csrf form: POST form to action",
            h.contains("<form id=\"nlk\" action=\"http://victim.test/account/role\" method=\"POST\">"));
        chk("csrf form: hidden user=admin",
            h.contains("name=\"user\" value=\"admin\""));
        chk("csrf form: value HTML-escaped (super&quot;x)",
            h.contains("value=\"super&quot;x\""));
        chk("csrf form: auto-submits",
            h.contains("getElementById('nlk').submit()"));
        chk("csrf form: note set", !note.isEmpty());
    }

    // ---- CSRF PoC: form '+' decodes to space (x-www-form-urlencoded) ----
    {
        QString note;
        const QString h = RequestExport::csrfPoc(
            "POST", "http://victim.test/x",
            "application/x-www-form-urlencoded", "q=hello+world", note);
        chk("csrf form: '+' decoded to space (reproduces the captured value)",
            h.contains("name=\"q\" value=\"hello world\"") && !h.contains("value=\"hello+world\""));
    }

    // ---- CSRF PoC: GET (query -> hidden fields, action stripped) -------
    {
        QString note;
        const QString h = RequestExport::csrfPoc(
            "GET", "http://victim.test/x?a=1&b=2", "", "", note);
        chk("csrf GET: method=GET, action has no query",
            h.contains("action=\"http://victim.test/x\" method=\"GET\""));
        chk("csrf GET: hidden a=1 and b=2",
            h.contains("name=\"a\" value=\"1\"") && h.contains("name=\"b\" value=\"2\""));
    }

    // ---- CSRF PoC: JSON -> credentialed fetch, < neutralized ----------
    {
        QString note;
        const QString h = RequestExport::csrfPoc(
            "POST", "http://victim.test/api", "application/json",
            "{\"x\":\"</script><b>\"}", note);
        chk("csrf json: credentialed fetch", h.contains("fetch(") && h.contains("credentials: 'include'"));
        chk("csrf json: no raw </script breakout", !h.contains("</script><b>"));
    }

    // ---- curl: POST with headers --------------------------------------
    {
        QList<QPair<QString, QString>> hdrs = {
            { "Cookie", "s=1" }, { "Content-Type", "application/json" },
            { "Content-Length", "7" }, { "Host", "victim.test" },
        };
        const QString c = RequestExport::curlCommand(
            "POST", "http://victim.test/x", hdrs, "{\"a\":1}");
        chk("curl: -X 'POST' (method single-quoted)", c.contains("curl -X 'POST' "));
        chk("curl: url single-quoted", c.contains("'http://victim.test/x'"));
        chk("curl: Cookie header", c.contains("-H 'Cookie: s=1'"));
        chk("curl: Content-Type header", c.contains("-H 'Content-Type: application/json'"));
        chk("curl: Content-Length skipped", !c.contains("Content-Length"));
        chk("curl: Host header skipped", !c.contains("-H 'Host:"));
        chk("curl: --data-raw body", c.contains("--data-raw '{\"a\":1}'"));
    }

    // ---- curl: GET (no -X, no body) + single-quote escaping -----------
    {
        const QString g = RequestExport::curlCommand("GET", "http://victim.test/g?a=1", {}, "");
        chk("curl GET: bare (no -X, no --data)", !g.contains("-X") && !g.contains("--data"));

        QList<QPair<QString, QString>> hdrs = { { "X-Q", "a'b" } };
        const QString q = RequestExport::curlCommand("POST", "http://victim.test/x", hdrs, "z");
        // POSIX escape of  a'b  inside single quotes is  a'\''b
        chk("curl: single-quote escaped to close-escape-reopen",
            q.contains("'X-Q: a'\\''b'"));
        // audit-8: the METHOD must be shell-escaped too (it was the one field that
        // wasn't) -- a metachar-bearing method stays an inert single-quoted token.
        chk("curl: a metachar method is single-quote escaped",
            RequestExport::curlCommand("GET;ID", "http://x/", {}, "").contains("-X 'GET;ID'"));
        chk("curl: a metachar method does NOT break out unquoted",
            !RequestExport::curlCommand("GET;ID", "http://x/", {}, "").contains("-X GET;ID "));
        // audit-9: a URL that starts with '-' must be emitted after --url, else curl
        // parses "-K/tmp/evil" as --config /tmp/evil (argument injection) instead of a URL.
        chk("curl: a dash-leading URL is guarded with --url (no curl argument injection)",
            RequestExport::curlCommand("GET", "-K/tmp/evil", {}, "").contains("--url '-K/tmp/evil'"));
        // audit-9: the fetch()-PoC URL is script-escaped (jsStr) so a url with </script>
        // cannot close Nullock's own <script> and inject into the analyst's browser.
        QString nt;
        const QString xh = RequestExport::csrfPoc(
            "POST", "http://x/a</script><script>alert(1)</script>", "application/json", "{}", nt);
        chk("csrfPoc: fetch-branch URL is script-escaped (no </script> breakout)",
            xh.contains("fetch(") && !xh.contains("</script><script>alert(1)"));
    }

    std::fprintf(stderr,
        "\n========================================\n"
        "RequestExport regression: %d passed, %d failed\n"
        "========================================\n",
        pass, fail);
    if (fail > 0) {
        std::fprintf(stderr, "Failures:\n");
        for (const QString &f : failures)
            std::fprintf(stderr, "  - %s\n", f.toLocal8Bit().constData());
    }
    return fail == 0 ? 0 : 1;
}

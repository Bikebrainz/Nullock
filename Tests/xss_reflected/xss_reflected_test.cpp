// Regression corpus for the reflected-XSS probe's pure logic (no network). The
// load-bearing piece is inExecutingHtmlContext -- a reduced HTML5 tokenizer that
// decides whether a reflected <marker> sits in runnable element content. An
// adversarial audit found a HIGH-severity false positive (a '>' inside a quoted
// attribute value prematurely ended the tag, so an in-attribute marker was
// reported as executable) plus several FP/FN gaps. This locks them all down:
//
//   FP fixes (must NOT run):
//     - marker inside an open tag's attribute, incl. when an earlier quoted
//       attribute value contains a literal '>' (the headline bug);
//     - marker inside script/style/comment;
//     - marker inside plaintext (irreversible) / noframes / noembed;
//     - a "</scriptx>" non-delimiter must NOT close the raw-text element.
//   FN fixes (must run):
//     - a later element-content reflection when the first is inert (title);
//     - case-normalized (uppercased) reflection;
//     - "</script >" (delimiter) and "<!-- .. --!>" (bogus close) DO end the
//       raw/comment region, so a following content reflection runs.
//   Plus isHtmlContentType, queryWith, and buildRequest's CR/LF guards.
//
// Run via:  ctest -R xss_reflected -V

#include "xss_reflected.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::XssReflected;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Mirror test()'s detection loop exactly: every occurrence, case-insensitive.
const QString MARK = QStringLiteral("nlk0a1b2c3d");
const QString TAG  = "<" + MARK + ">";
bool runs(const char *b) {
    const QString body = QString::fromUtf8(b);
    for (int at = body.indexOf(TAG, 0, Qt::CaseInsensitive); at >= 0;
         at = body.indexOf(TAG, at + 1, Qt::CaseInsensitive))
        if (inExecutingHtmlContext(body, at)) return true;
    return false;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== POSITIVES: marker runs in element content =====================
    chk("plain element content -> runs",
        runs("<div>hello <nlk0a1b2c3d> world</div>"));
    chk("after a tag whose quoted attr value contains '>' -> still content -> runs",
        runs("<a title=\"x => y\">link <nlk0a1b2c3d></a>"));
    chk("after a closed <script> -> content -> runs",
        runs("<script>var x=1;</script><div><nlk0a1b2c3d></div>"));
    chk("later content reflection when first is inert (title) -> runs (multi-occurrence)",
        runs("<title><nlk0a1b2c3d></title><body><nlk0a1b2c3d></body>"));
    chk("case-normalized (uppercased) reflection -> runs",
        runs("<div><NLK0A1B2C3D></div>"));
    chk("'</script >' with trailing space DOES close -> following content runs",
        runs("<script>a</script ><div><nlk0a1b2c3d></div>"));
    chk("comment closed by bogus '--!>' -> following content runs",
        runs("<!-- note --!><div><nlk0a1b2c3d></div>"));
    // FN fix: a "<!...":  markup declaration that is NOT "<!--" is a BOGUS COMMENT
    // -- it ends at the very next '>' with NO attribute quote-tracking. Routing it
    // through the tag branch let a '"' inside open a fake quoted value that
    // swallowed the terminating '>' and hid the following <div> (false negative).
    chk("FN fix: bogus comment '<!x=\">' ends at first '>' -> following content runs",
        runs("<!x=\"><div><nlk0a1b2c3d></div>"));
    chk("FN fix: PI-like '<?x=\">' ends at first '>' -> following content runs",
        runs("<?x=\"><div><nlk0a1b2c3d></div>"));
    chk("DOCTYPE does not swallow the following content -> marker runs",
        runs("<!DOCTYPE html><div><nlk0a1b2c3d></div>"));

    // ===== FALSE-POSITIVE FIXES: marker is inert, must NOT run ============
    chk("HEADLINE FP: marker in attribute, earlier quoted attr has '>' -> NOT run",
        !runs("<input data-x=\">\" value=<nlk0a1b2c3d>>"));
    chk("marker inside a quoted attribute value -> NOT run",
        !runs("<img alt=\"a>b\" src=\"<nlk0a1b2c3d>\">"));
    chk("marker in an open tag (unquoted attr position) -> NOT run",
        !runs("<input value=<nlk0a1b2c3d>>"));
    chk("marker inside <script> -> NOT run",
        !runs("<script>var a=<nlk0a1b2c3d>;</script>"));
    chk("marker inside <style> -> NOT run",
        !runs("<style>.x{a:<nlk0a1b2c3d>}</style>"));
    chk("marker inside an HTML comment -> NOT run",
        !runs("<!-- <nlk0a1b2c3d> --></html>"));
    chk("marker inside <textarea> -> NOT run",
        !runs("<textarea><nlk0a1b2c3d></textarea>"));
    chk("FP fix #2: marker inside <plaintext> (irreversible) -> NOT run",
        !runs("<html><body><plaintext><nlk0a1b2c3d>"));
    chk("FP fix #2: even a fake </plaintext> can't reopen markup -> NOT run",
        !runs("<plaintext></plaintext><nlk0a1b2c3d>"));
    chk("FP fix #2: marker inside <noframes> -> NOT run",
        !runs("<noframes><nlk0a1b2c3d></noframes>"));
    chk("FP fix #2: marker inside <noembed> -> NOT run",
        !runs("<noembed><nlk0a1b2c3d></noembed>"));
    chk("FP fix #10: '</scriptx>' is not a close -> marker still in script -> NOT run",
        !runs("<script><nlk0a1b2c3d></scriptx>"));
    chk("unterminated comment swallows the marker -> NOT run",
        !runs("<!-- unterminated <nlk0a1b2c3d>"));
    chk("a bogus comment still SUPPRESSES a marker sitting inside it -> NOT run",
        !runs("<div>text<!note <nlk0a1b2c3d> more>tail</div>"));

    // ===== isHtmlContentType (caller lower-cases the value) ===============
    chk("CT empty -> sniffable HTML", isHtmlContentType(""));
    chk("CT text/html -> HTML", isHtmlContentType("text/html; charset=utf-8"));
    chk("CT application/xhtml+xml -> HTML", isHtmlContentType("application/xhtml+xml"));
    chk("CT application/json -> NOT HTML", !isHtmlContentType("application/json"));
    chk("CT text/plain -> NOT HTML", !isHtmlContentType("text/plain"));

    // ===== queryWith: preserve others, replace target, percent-encode =====
    chk("queryWith replaces target, keeps others, encodes",
        [](){ const QString q = queryWith("a=1&b=2", "b", "<nlk>");
              return q.contains("a=1") && q.contains("b=%3Cnlk%3E") && !q.contains("b=2"); }());
    chk("queryWith on empty existing -> single encoded pair",
        queryWith("", "q", "<nlk>") == "q=%3Cnlk%3E");

    // ===== buildRequest: CR/LF guard parity (method/host/path/query) =====
    {
        Request req; req.host = "victim.tld"; req.basePath = "/"; req.method = "GET";
        chk("build: request line", buildRequest(req, "a=1").startsWith("GET /?a=1 HTTP/1.1\r\n"));
        chk("build: Host", buildRequest(req, "").contains("Host: victim.tld\r\n"));
        Request bh = req; bh.host = "victim.tld\r\nEvil: 1";
        chk("build: CRLF host -> no injected header", !buildRequest(bh, "").contains("\r\nEvil: 1"));
        Request bm = req; bm.method = "GET\r\nEvil: 1";
        chk("build: CRLF method -> no injected header", !buildRequest(bm, "").contains("\r\nEvil: 1"));
        Request bp = req; bp.basePath = "/a\r\nEvil: 1";
        chk("build: CRLF basePath -> no injected header", !buildRequest(bp, "").contains("\r\nEvil: 1"));
        chk("build: CRLF query -> no injected header", !buildRequest(req, "a=1\r\nEvil: 1").contains("\r\nEvil: 1"));
        Request bhe = req; bhe.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("build: CRLF carried header dropped", !buildRequest(bhe, "").contains("Evil: 1"));
    }

    std::fprintf(stderr, "xss_reflected_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

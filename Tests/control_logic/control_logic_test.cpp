// Regression corpus for the ControlServer pre-dispatch SECURITY GATE.
//
// The control server exposes PRIVATE state (proxy history, captured creds) and
// is defended ONLY by same-origin policy + these three predicates. This locks
// the boundary so a refactor can't silently widen it:
//   * isHostAllowed  -- DNS-rebinding defence (loopback Host allowlist).
//   * isMethodAllowed-- known-verb allowlist.
//   * isRequestAuthorized -- CSRF: writes need a same-origin Origin or the
//     X-Nullock-UI token; reads pass.
// The adversarial cases below are the actual attacker inputs: a rebinded Host, a
// cross-origin Origin, a look-alike origin/host, a wrong port, a bogus token.
//
// Run via:  ctest -R control_logic -V

#include "control_logic.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>

#include <cstdio>

using namespace Nullock::Control::ControlLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const quint16 P = 8731;  // a representative listening port
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== method allowlist =============================================
    chk("method: GET allowed",     isMethodAllowed("GET"));
    chk("method: POST allowed",    isMethodAllowed("POST"));
    chk("method: PUT allowed",     isMethodAllowed("PUT"));
    chk("method: PATCH allowed",   isMethodAllowed("PATCH"));

    // ===== severity mapping (audit-8: SARIF level + rank) ================
    chk("sarif: critical -> error (not warning)", sarifLevelForSeverity("critical") == "error");
    chk("sarif: high -> error",      sarifLevelForSeverity("high") == "error");
    chk("sarif: medium -> warning",  sarifLevelForSeverity("medium") == "warning");
    chk("sarif: low -> note",        sarifLevelForSeverity("low") == "note");
    chk("sarif: info -> note",       sarifLevelForSeverity("info") == "note");
    chk("sarif: unknown -> warning", sarifLevelForSeverity("bogus") == "warning");
    // Severity reaches the SARIF sink as a free QString (not guaranteed lowercased);
    // the toLower gate must map a capitalized Critical/High to "error", else a
    // critical finding emits level "warning" and a CI gate on level=="error" passes.
    chk("sarif: mixed-case 'Critical' -> error (toLower gate)", sarifLevelForSeverity("Critical") == "error");
    chk("sarif: mixed-case 'High' -> error", sarifLevelForSeverity("High") == "error");
    chk("rank: critical>high>medium>low>info>unknown",
        severityRank("critical") > severityRank("high")
        && severityRank("high") > severityRank("medium")
        && severityRank("medium") > severityRank("low")
        && severityRank("low") > severityRank("info")
        && severityRank("info") > severityRank("bogus"));
    chk("method: DELETE allowed",  isMethodAllowed("DELETE"));
    chk("method: HEAD allowed",    isMethodAllowed("HEAD"));
    chk("method: OPTIONS allowed", isMethodAllowed("OPTIONS"));
    chk("method: TRACE rejected",  !isMethodAllowed("TRACE"));
    chk("method: CONNECT rejected",!isMethodAllowed("CONNECT"));
    chk("method: lowercase 'get' rejected (case-sensitive verb)", !isMethodAllowed("get"));
    chk("method: empty rejected",  !isMethodAllowed(""));
    chk("method: junk rejected",   !isMethodAllowed("FOObar"));

    // ===== read vs write classification =================================
    chk("read: GET is read",      isReadMethod("GET"));
    chk("read: HEAD is read",     isReadMethod("HEAD"));
    chk("read: OPTIONS is read",  isReadMethod("OPTIONS"));
    chk("read: POST is NOT read", !isReadMethod("POST"));
    chk("read: PUT is NOT read",  !isReadMethod("PUT"));
    chk("read: DELETE is NOT read", !isReadMethod("DELETE"));

    // ===== DNS-rebinding Host allowlist =================================
    chk("host: empty allowed (browser always sends Host; design)", isHostAllowed("", P));
    chk("host: 127.0.0.1:port allowed", isHostAllowed("127.0.0.1:8731", P));
    chk("host: localhost:port allowed", isHostAllowed("localhost:8731", P));
    chk("host: [::1]:port allowed",     isHostAllowed("[::1]:8731", P));
    chk("host: bare 127.0.0.1 allowed", isHostAllowed("127.0.0.1", P));
    chk("host: bare localhost allowed", isHostAllowed("localhost", P));
    chk("host: bare [::1] allowed",     isHostAllowed("[::1]", P));
    chk("host: uppercase LOCALHOST:port allowed (case-insensitive)", isHostAllowed("LOCALHOST:8731", P));
    chk("host: mixed-case 127.0.0.1 fine", isHostAllowed("127.0.0.1:8731", P));
    // --- rebinding / look-alike rejections ---
    chk("host: evil.com:port REJECTED (rebinding)", !isHostAllowed("evil.com:8731", P));
    chk("host: bare evil.com REJECTED", !isHostAllowed("evil.com", P));
    chk("host: localhost.evil.com REJECTED (suffix)", !isHostAllowed("localhost.evil.com", P));
    chk("host: localhost:WRONGPORT REJECTED", !isHostAllowed("localhost:9999", P));
    chk("host: 127.0.0.1:port.evil.com REJECTED", !isHostAllowed("127.0.0.1:8731.evil.com", P));
    chk("host: prefix 'localhost:8731x' REJECTED", !isHostAllowed("localhost:8731x", P));
    chk("host: trailing-dot 'localhost.' REJECTED (stricter is fine)", !isHostAllowed("localhost.", P));
    chk("host: leading-space ' localhost' REJECTED (handle() trims upstream)", !isHostAllowed(" localhost", P));
    chk("host: '0.0.0.0:port' REJECTED", !isHostAllowed("0.0.0.0:8731", P));

    // ===== CSRF: reads pass without origin/token ========================
    chk("csrf: GET passes with no origin/token", isRequestAuthorized("GET", "", "", P));
    chk("csrf: HEAD passes", isRequestAuthorized("HEAD", "", "", P));
    chk("csrf: OPTIONS passes (preflight)", isRequestAuthorized("OPTIONS", "", "", P));

    // ===== CSRF: writes need same-origin Origin OR token ================
    chk("csrf: POST + same-origin 127 origin OK",
        isRequestAuthorized("POST", "http://127.0.0.1:8731", "", P));
    chk("csrf: POST + same-origin localhost origin OK",
        isRequestAuthorized("POST", "http://localhost:8731", "", P));
    chk("csrf: POST + token '1' OK", isRequestAuthorized("POST", "", "1", P));
    chk("csrf: POST + token 'true' OK", isRequestAuthorized("POST", "", "true", P));
    chk("csrf: POST + token 'TRUE' OK (case-insensitive)", isRequestAuthorized("POST", "", "TRUE", P));
    chk("csrf: PUT/PATCH/DELETE behave as writes (token OK)",
        isRequestAuthorized("PUT", "", "1", P) && isRequestAuthorized("DELETE", "", "1", P));
    // --- the bypass rejections ---
    chk("csrf: POST + NO origin + NO token REJECTED", !isRequestAuthorized("POST", "", "", P));
    chk("csrf: POST + cross-origin evil REJECTED", !isRequestAuthorized("POST", "http://evil.com", "", P));
    chk("csrf: POST + https loopback REJECTED (exact http match)",
        !isRequestAuthorized("POST", "https://127.0.0.1:8731", "", P));
    chk("csrf: POST + origin suffix look-alike REJECTED",
        !isRequestAuthorized("POST", "http://127.0.0.1:8731.evil.com", "", P));
    chk("csrf: POST + origin prefix look-alike REJECTED",
        !isRequestAuthorized("POST", "http://localhost:8731@evil.com", "", P));
    chk("csrf: POST + wrong-port origin REJECTED",
        !isRequestAuthorized("POST", "http://127.0.0.1:9999", "", P));
    chk("csrf: POST + token 'false' REJECTED", !isRequestAuthorized("POST", "", "false", P));
    chk("csrf: POST + token '0' REJECTED", !isRequestAuthorized("POST", "", "0", P));
    chk("csrf: POST + token 'yes' REJECTED", !isRequestAuthorized("POST", "", "yes", P));
    chk("csrf: DELETE + no origin/token REJECTED", !isRequestAuthorized("DELETE", "", "", P));

    // ===== port is honored in the origin/host match =====================
    chk("port: origin must match THIS port (4444)",
        isRequestAuthorized("POST", "http://127.0.0.1:4444", "", 4444)
        && !isRequestAuthorized("POST", "http://127.0.0.1:8731", "", 4444));
    chk("port: host must match THIS port (4444)",
        isHostAllowed("localhost:4444", 4444) && !isHostAllowed("localhost:8731", 4444));

    // ===== Markdown report-export escaping ==============================
    // Code span: a backtick would close the span; control chars break it.
    chk("md-code: plain text unchanged", mdCodeSpanSafe("GET /a") == "GET /a");
    chk("md-code: backtick removed (can't escape inside a span)", mdCodeSpanSafe("a`b") == "ab");
    chk("md-code: newline -> space", mdCodeSpanSafe("a\nb") == "a b");
    chk("md-code: CR + tab -> space", mdCodeSpanSafe("a\r\tb") == "a  b");
    chk("md-code: no backtick survives a code-span breakout payload",
        !mdCodeSpanSafe("`](http://evil)`").contains('`'));
    chk("md-code: DEL control stripped", mdCodeSpanSafe(QString("a") + QChar(0x7F) + "b") == "a b");

    // Plain text: metacharacters backslash-escaped, control -> space.
    chk("md-text: plain text unchanged", mdTextSafe("normal text") == "normal text");
    chk("md-text: a link payload is neutralized (brackets/parens escaped)",
        mdTextSafe("[x](http://evil)") == "\\[x\\]\\(http://evil\\)");
    chk("md-text: backtick escaped", mdTextSafe("a`b") == "a\\`b");
    chk("md-text: emphasis escaped", mdTextSafe("*bold* _i_") == "\\*bold\\* \\_i\\_");
    chk("md-text: newline -> space (can't start a new list item / heading)",
        mdTextSafe("a\n# heading") == "a \\# heading");
    chk("md-text: pipe + angle-brackets + bang escaped",
        mdTextSafe("a|b<c>d!e") == "a\\|b\\<c\\>d\\!e");
    chk("md-text: backslash itself escaped", mdTextSafe("a\\b") == "a\\\\b");

    // ===== outbound request-builder CR/LF guard =========================
    // Locks the /api/oast/blast fix: a url whose QUrl::path() decodes to raw
    // CR/LF (Qt %0d%0a decoding), or an operator param name carrying CR/LF,
    // must be rejected before it is concatenated into raw request bytes.
    chk("smuggle: clean path passes", !hasRequestSmugglingChars("/api/v1/users"));
    chk("smuggle: empty passes", !hasRequestSmugglingChars(""));
    chk("smuggle: clean query passes", !hasRequestSmugglingChars("a=1&b=2"));
    chk("smuggle: encoded-looking %0d%0a (literal text) passes -- not raw bytes",
        !hasRequestSmugglingChars("/a%0d%0ab"));
    chk("smuggle: a token-y param name passes", !hasRequestSmugglingChars("redirect_uri"));
    // --- the rejections (decoded raw control bytes) ---
    chk("smuggle: raw CR REJECTED", hasRequestSmugglingChars("/a\rX: y"));
    chk("smuggle: raw LF REJECTED", hasRequestSmugglingChars("/a\nX: y"));
    chk("smuggle: raw CRLF REJECTED", hasRequestSmugglingChars("/a\r\nHost: evil"));
    chk("smuggle: NUL REJECTED", hasRequestSmugglingChars(QString("/a") + QChar('\0') + "b"));
    chk("smuggle: CR-only at end REJECTED", hasRequestSmugglingChars("trailing\r"));
    chk("smuggle: param name with CRLF REJECTED (the OAST-1 vector)",
        hasRequestSmugglingChars("x HTTP/1.1\r\nHost: evil.example"));
    chk("smuggle: decoded path with CRLF REJECTED (the OAST-2 vector)",
        hasRequestSmugglingChars("/a\r\nX-Injected: pwn"));

    // ===== /api/search ReDoS pattern pre-screen =========================
    // Locks looksLikeCatastrophicRegex: the textbook nested-quantifier bombs
    // AND the identical-branch alternation bombs that bypassed the old
    // shape-only kBombShape (measured against Qt 6.7.3 PCRE2), while disjoint
    // alternations and ordinary patterns pass (low false-positive).
    // --- nested unbounded quantifier (the original shape) ---
    chk("redos: (a+)+ rejected",     looksLikeCatastrophicRegex("(a+)+"));
    chk("redos: (a*)* rejected",     looksLikeCatastrophicRegex("(a*)*"));
    chk("redos: (a{2,})+ rejected",  looksLikeCatastrophicRegex("(a{2,})+"));
    chk("redos: ([a-z]+)+ rejected", looksLikeCatastrophicRegex("([a-z]+)+"));
    chk("redos: (.*)* rejected",     looksLikeCatastrophicRegex("(.*)*"));
    // --- identical-branch alternation (the kBombShape bypass, measured) ---
    chk("redos: (a|a)+ rejected",       looksLikeCatastrophicRegex("(a|a)+"));
    chk("redos: (\\d|\\d)+ rejected",   looksLikeCatastrophicRegex("(\\d|\\d)+"));
    chk("redos: ([ab]|[ab])+ rejected", looksLikeCatastrophicRegex("([ab]|[ab])+"));
    chk("redos: (a|a|a)+ rejected",     looksLikeCatastrophicRegex("(a|a|a)+"));
    chk("redos: (ab|ab)* rejected",     looksLikeCatastrophicRegex("(ab|ab)*"));
    // --- benign patterns NOT flagged ---
    chk("redos: (foo|bar)+ accepted",          !looksLikeCatastrophicRegex("(foo|bar)+"));
    chk("redos: (a|b)+ accepted (disjoint)",   !looksLikeCatastrophicRegex("(a|b)+"));
    chk("redos: (https?|ftp) accepted",        !looksLikeCatastrophicRegex("(https?|ftp)"));
    chk("redos: plain literal accepted",       !looksLikeCatastrophicRegex("GET /api HTTP"));
    chk("redos: email-ish accepted",           !looksLikeCatastrophicRegex("\\w+@\\w+"));
    chk("redos: single quantified group (no outer) accepted",
        !looksLikeCatastrophicRegex("([a-z]+)"));
    chk("redos: anchored line accepted",       !looksLikeCatastrophicRegex("^Set-Cookie: .*$"));
    chk("redos: empty accepted",               !looksLikeCatastrophicRegex(""));

    // ===== /api/search scan ordering + completeness =====================
    // Locks searchRowForIteration + searchTruncated. ProxyModel APPENDS, so
    // row 0 is the OLDEST capture; the body scan MUST run newest-first
    // (iteration 0 -> row n-1) so a time-bounded scan covers recent traffic,
    // and MUST report truncated whenever it did not examine every row. The old
    // handler scanned the OLDEST 500 rows and set truncated only on the
    // wall-clock path, so a >500-capture history silently omitted all recent
    // traffic and answered a confident 0 -- and the DEEP filter then hid it.
    // --- newest-first mapping ---
    chk("search: iter 0 -> newest row (n-1)",   searchRowForIteration(1000, 0) == 999);
    chk("search: iter 1 -> second-newest",      searchRowForIteration(1000, 1) == 998);
    chk("search: last iter -> oldest row 0",    searchRowForIteration(1000, 999) == 0);
    chk("search: single-row window -> row 0",   searchRowForIteration(1, 0) == 0);
    // --- defensive clamps: an out-of-range i can never become a negative row ---
    chk("search: i>=n clamps to oldest row 0",  searchRowForIteration(10, 10) == 0);
    chk("search: negative i clamps to newest",  searchRowForIteration(10, -1) == 9);
    chk("search: empty window -> row 0 (no UB)", searchRowForIteration(0, 0) == 0);
    // --- completeness signal (the honesty invariant) ---
    chk("search: scanned all -> not truncated",     !searchTruncated(1000, 1000));
    chk("search: scanned a suffix -> truncated",     searchTruncated(500, 1000));
    chk("search: scanned none of many -> truncated", searchTruncated(0, 1000));
    chk("search: empty history -> not truncated",   !searchTruncated(0, 0));

    // ===== path-confinement safeJoin ====================================
    // Locks the static-file + project-template traversal guard (a compiled
    // probe proved it holds on Windows; this pins it). Empty return == rejected;
    // a non-empty return must stay prefixed by the trusted base dir.
    const QString D = QStringLiteral("/srv/ui");
    // --- traversal REJECTED (empty) ---
    chk("safeJoin: ../ rejected",          safeJoin(D, "../etc/passwd").isEmpty());
    chk("safeJoin: ..\\ rejected",         safeJoin(D, "..\\windows\\win.ini").isEmpty());
    chk("safeJoin: a/../b rejected",       safeJoin(D, "a/../b").isEmpty());
    chk("safeJoin: ....// rejected",       safeJoin(D, "....//x").isEmpty());
    chk("safeJoin: leading-slash + .. rejected", safeJoin(D, "/../etc").isEmpty());
    chk("safeJoin: bare .. rejected",      safeJoin(D, "..").isEmpty());
    chk("safeJoin: deep climb rejected",   safeJoin(D, "x/../../../../etc").isEmpty());
    chk("safeJoin: template-id climb rejected (F1 vector)",
        safeJoin(D, "../../secret").isEmpty());
    // --- benign ACCEPTED + confined under D ---
    chk("safeJoin: file confined",         safeJoin(D, "Nullock.html") == "/srv/ui/Nullock.html");
    chk("safeJoin: leading-/ stripped",    safeJoin(D, "/Nullock.html") == "/srv/ui/Nullock.html");
    chk("safeJoin: leading-backslash stripped", safeJoin(D, "\\app.js") == "/srv/ui/app.js");
    chk("safeJoin: double-leading-/ stripped",  safeJoin(D, "//app.js") == "/srv/ui/app.js");
    chk("safeJoin: subdir confined",       safeJoin(D, "assets/app.js") == "/srv/ui/assets/app.js");
    chk("safeJoin: template id confined",  safeJoin(D, "web-app.json") == "/srv/ui/web-app.json");
    // --- a non-empty result ALWAYS begins with the trusted base (no escape) ---
    chk("safeJoin: drive-path stays prefixed",
        safeJoin(D, "C:/Windows/win.ini").startsWith("/srv/ui/"));
    // The substring ".." reject is deliberately conservative -- it also rejects a
    // benign filename that merely CONTAINS "..". Pinned so a future "tighten to
    // only reject '..' path SEGMENTS" is a conscious, tested contract change.
    chk("safeJoin: benign 'a..b.txt' is (conservatively) rejected",
        safeJoin(D, "a..b.txt").isEmpty());

    // ===== XML attribute escaping (nmap-XML / report export) ============
    // Locks xmlAttrEscape: the 5 predefined entities + control chars (incl
    // CR/LF/tab) -> space, so attacker scan data (host/service/banner) can't
    // break attribute framing or inject markup.
    chk("xml: amp escaped",   xmlAttrEscape("a&b") == "a&amp;b");
    chk("xml: lt/gt escaped", xmlAttrEscape("<x>") == "&lt;x&gt;");
    chk("xml: quote escaped", xmlAttrEscape("\"q\"") == "&quot;q&quot;");
    chk("xml: apos escaped",  xmlAttrEscape("'a'") == "&apos;a&apos;");
    chk("xml: all five",      xmlAttrEscape("a\"&<>'b") == "a&quot;&amp;&lt;&gt;&apos;b");
    chk("xml: LF -> space",   xmlAttrEscape("a\nb") == "a b");
    chk("xml: CR -> space",   xmlAttrEscape("a\rb") == "a b");
    chk("xml: tab -> space",  xmlAttrEscape("a\tb") == "a b");
    chk("xml: control byte -> space",
        xmlAttrEscape(QString("a") + QChar(0x01) + "b") == "a b");
    chk("xml: plain text unchanged", xmlAttrEscape("nginx/1.21") == "nginx/1.21");
    chk("xml: attribute-breakout payload neutralized",
        xmlAttrEscape("\"><script>alert(1)</script>")
            == "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;");

    // ===== bearer-token API auth =========================================
    // bearerToken: parse "Bearer <token>" tolerantly.
    chk("bearer: extracts token",         bearerToken("Bearer abc123") == "abc123");
    chk("bearer: scheme case-insensitive", bearerToken("bEaReR abc123") == "abc123");
    chk("bearer: leading/trailing ws",    bearerToken("  Bearer   abc123  ") == "abc123");
    chk("bearer: empty on wrong scheme",  bearerToken("Basic abc123").isEmpty());
    chk("bearer: empty on no scheme",     bearerToken("abc123").isEmpty());
    chk("bearer: empty on scheme only",   bearerToken("Bearer").isEmpty());
    chk("bearer: empty on scheme+space",  bearerToken("Bearer ").isEmpty());
    chk("bearer: empty input",            bearerToken("").isEmpty());
    chk("bearer: no scheme/token separator ('Bearerabc') -> empty",
        bearerToken("Bearerabc").isEmpty());

    // constantTimeEquals: correct result (the timing property isn't unit-testable).
    chk("cteq: equal strings",            constantTimeEquals("s3cret-token", "s3cret-token"));
    chk("cteq: one-char diff",           !constantTimeEquals("s3cret-token", "s3cret-tokeX"));
    chk("cteq: length diff (prefix)",    !constantTimeEquals("s3cret", "s3cret-token"));
    chk("cteq: length diff (suffix)",    !constantTimeEquals("s3cret-token", "s3cret"));
    chk("cteq: both empty equal",         constantTimeEquals("", ""));
    chk("cteq: empty vs non-empty",      !constantTimeEquals("", "x"));
    chk("cteq: unicode equal",            constantTimeEquals(QString::fromUtf8("t\xC3\xB6k\xC3\xA9n"),
                                                             QString::fromUtf8("t\xC3\xB6k\xC3\xA9n")));
    // A whole-multiple repetition ("abab" vs "ab") makes the modulo byte-loop report
    // all-equal; ONLY the size-difference fold rejects it. Existing length-diff cases
    // ("s3cret"/"s3cret-token") diverge INSIDE the loop, so none pins the fold -- a
    // regression zeroing it is an auth bypass by a repeated-token guess.
    chk("cteq: whole-multiple repetition NOT equal (length fold, not just byte loop)",
        !constantTimeEquals("abab", "ab") && !constantTimeEquals("ab", "abab"));

    // isTokenAuthorized: an empty config (auth disabled) is NEVER authorized here.
    chk("tokauth: empty config -> false",       !isTokenAuthorized("Bearer anything", ""));
    chk("tokauth: empty config, no header",     !isTokenAuthorized("", ""));
    chk("tokauth: matching bearer -> true",      isTokenAuthorized("Bearer s3cret", "s3cret"));
    chk("tokauth: wrong bearer -> false",       !isTokenAuthorized("Bearer nope", "s3cret"));
    chk("tokauth: no auth header -> false",     !isTokenAuthorized("", "s3cret"));
    chk("tokauth: wrong scheme -> false",       !isTokenAuthorized("Basic s3cret", "s3cret"));
    chk("tokauth: case-insensitive scheme",      isTokenAuthorized("bearer s3cret", "s3cret"));
    // A repeated-token guess ("s3crets3cret" vs config "s3cret") passes the modulo
    // byte-loop; only the constantTimeEquals length fold rejects it -> real auth gate.
    chk("tokauth: a repeated-token guess is rejected (length fold)",
        !isTokenAuthorized("Bearer s3crets3cret", "s3cret"));

    // ===== findingsJsonToXml: XML issue report ============================
    // The report bundles PRIVATE scan data (hosts, URLs, summaries) that an
    // attacker's own traffic can shape. If any value reached the document
    // un-escaped, a summary/host carrying "</issue>" or "<" would break the
    // framing (a report-consuming XSLT/SIEM parser then mis-parses or, worse,
    // executes injected markup). These lock the escaping + the element/attr shape.
    {
        const QString empty = findingsJsonToXml(QJsonArray{}, "proj",
                                                "2026-08-11T00:00:00Z");
        chk("xml-report: XML prolog present",
            empty.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        chk("xml-report: empty corpus -> issueCount 0 + closed root",
            empty.contains("issueCount=\"0\"") && empty.contains("</nullockReport>"));

        QJsonArray arr;
        arr.append(QJsonObject{
            { "severity", "high" }, { "confidence", "firm" }, { "kind", "sqli" },
            { "host", "ex&ample.com" }, { "url", "http://x/?q=<script>" },
            { "summary", "breakout </issue><evil/>" }, { "cwe", "CWE-89" },
            { "owasp", "A03:2021-Injection" }, { "cvssScore", 9.8 },
            { "fixSummary", "parameterize the query" }, { "fixed", false },
        });
        // Second finding is sparse: no cwe/owasp/fixSummary and a 0 CVSS.
        arr.append(QJsonObject{
            { "severity", "info" }, { "kind", "banner" }, { "host", "h" },
            { "url", "u" }, { "summary", "s" }, { "cvssScore", 0.0 },
        });
        const QString x = findingsJsonToXml(arr, "My \"Proj\" & Co",
                                            "2026-08-11T00:00:00Z");

        chk("xml-report: project attribute escaped",
            x.contains("project=\"My &quot;Proj&quot; &amp; Co\""));
        chk("xml-report: issueCount reflects 2", x.contains("issueCount=\"2\""));
        chk("xml-report: severity + confidence attributes",
            x.contains("<issue severity=\"high\" confidence=\"firm\""));
        chk("xml-report: positive CVSS emitted as attribute", x.contains("cvss=\"9.8\""));
        // THE load-bearing case: a "</issue>" in the summary must be escaped so it
        // cannot close the element early and inject sibling markup.
        chk("xml-report: element-breakout payload neutralized",
            x.contains("<detail>breakout &lt;/issue&gt;&lt;evil/&gt;</detail>"));
        chk("xml-report: host ampersand escaped in element text",
            x.contains("<host>ex&amp;ample.com</host>"));
        chk("xml-report: url angle brackets escaped in element text",
            x.contains("q=&lt;script&gt;"));
        chk("xml-report: name/cwe/owasp elements rendered",
            x.contains("<name>sqli</name>") && x.contains("<cwe>CWE-89</cwe>")
            && x.contains("<owasp>A03:2021-Injection</owasp>"));
        // Framing intact: exactly one <issue>...</issue> pair per finding despite
        // the breakout payload -- if escaping failed this count would be wrong.
        chk("xml-report: exactly two issue elements (framing intact)",
            x.count("<issue ") == 2 && x.count("</issue>") == 2);

        // The sparse finding must omit absent enrichment (no empty <cwe/> litter)
        // and emit NO cvss attribute for a 0 score.
        const QString second = x.mid(x.indexOf("</issue>"));  // 2nd issue + tail
        chk("xml-report: absent cwe omitted (no empty element)", !second.contains("<cwe>"));
        chk("xml-report: absent remediation omitted", !second.contains("<remediation>"));
        chk("xml-report: zero CVSS emits no cvss attribute", !second.contains("cvss="));

        // The baseline-diff "fixed" flag surfaces as an attribute when set.
        const QString fx = findingsJsonToXml(
            QJsonArray{ QJsonObject{{ "severity", "low" }, { "kind", "k" },
                                    { "fixed", true }} }, "p", "t");
        chk("xml-report: fixed=true surfaces as attribute", fx.contains(" fixed=\"true\""));
    }

    std::fprintf(stderr, "control_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

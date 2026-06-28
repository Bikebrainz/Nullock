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

    std::fprintf(stderr, "control_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

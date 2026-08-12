// Regression corpus for session_manager's pure cookie-jar logic (no network).
// Locks the soundness fixes from the adversarial audit (7 confirmed findings):
//   - injectableOverTransport: a Secure cookie is NEVER injectable over a non-TLS
//     request (port != 443) -- the CRITICAL fix: re-injecting a Secure session
//     token over cleartext leaks it to a passive observer;
//   - pathMatches: a Path-scoped cookie (Path=/admin) is not over-injected onto an
//     unrelated request path (/public) -- RFC 6265 §5.1.4 path matching;
//   - parseSetCookie: control bytes stripped (CRLF smuggling dead), a bad name
//     cleared, attributes (Secure/HttpOnly/Path/SameSite/Expires) parsed.
//
// Run via:  ctest -R session_manager -V

#include "session_manager_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core;
using namespace Nullock::Core::SessionLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
CapturedCookie secure(bool s) { CapturedCookie c; c.secure = s; return c; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== injectableOverTransport: honor Secure over an ACTUAL TLS check =====
    // Secure cookies inject only over TLS -- a real transport flag, not the old
    // port==443 heuristic (#165). The heuristic BOTH leaked a Secure cookie over
    // cleartext on :443 AND refused it over TLS on a non-standard port (:8443);
    // a boolean tls check fixes both directions.
    chk("transport: a Secure cookie is NOT injectable over cleartext (tls=false, no leak)",
        !injectableOverTransport(secure(true), false));
    chk("transport: a Secure cookie IS injectable over TLS -- ANY port, incl. :8443 (was the bug)",
        injectableOverTransport(secure(true), true));
    chk("transport: a non-Secure cookie is injectable over cleartext (tls=false)",
        injectableOverTransport(secure(false), false));
    chk("transport: a non-Secure cookie is injectable over TLS (tls=true)",
        injectableOverTransport(secure(false), true));
    // Fail-closed: an unknown/default transport (tls=false) never injects a Secure cookie.
    chk("transport: fail-closed -- Secure + default transport (tls=false) not injected",
        !injectableOverTransport(secure(true), false));

    // ===== pathMatches: RFC 6265 §5.1.4 (stop path over-injection) ======
    chk("path: exact match", pathMatches("/admin", "/admin"));
    chk("path: a dir-prefix cookie matches a deeper path", pathMatches("/admin", "/admin/panel"));
    chk("path: a trailing-slash cookie matches under it", pathMatches("/admin/", "/admin/panel"));
    chk("path: Path=/admin does NOT match /public (over-injection fix)", !pathMatches("/admin", "/public"));
    chk("path: Path=/admin does NOT match /administrator (no false prefix)",
        !pathMatches("/admin", "/administrator"));
    chk("path: '/' matches everything", pathMatches("/", "/anything/here"));
    chk("path: an empty cookie path defaults to '/' (matches)", pathMatches("", "/x"));
    chk("path: query string on the request path is ignored",
        pathMatches("/admin", "/admin/p?q=1"));
    chk("path: an empty request path -> '/' (a non-'/' cookie path does not match)",
        !pathMatches("/admin", ""));
    // audit-11: dot-segments are resolved BEFORE matching -- "/admin/../public" is
    // really "/public", so a Path=/admin cookie must NOT ride it (over-injection).
    chk("path: Path=/admin does NOT match /admin/../public (dot-segment traversal)",
        !pathMatches("/admin", "/admin/../public"));
    chk("path: Path=/admin does NOT match /admin/../../etc",
        !pathMatches("/admin", "/admin/../../etc"));
    chk("path: a dot-segment that STAYS in scope still matches (/admin/x/../y)",
        pathMatches("/admin", "/admin/x/../y"));
    chk("path: '.' segments are ignored (/admin/./panel still matches)",
        pathMatches("/admin", "/admin/./panel"));
    // audit-11: the prefix compare is case-SENSITIVE -- a case-insensitive regression
    // would silently reopen the over-injection hole.
    chk("path: Path=/Admin does NOT match /admin/panel (case-sensitive)",
        !pathMatches("/Admin", "/admin/panel"));

    // ===== parseSetCookie: control-strip, name validation, attributes ===
    {
        const CapturedCookie c = parseSetCookie("SID=abc123; Secure; HttpOnly; Path=/app; SameSite=Lax");
        chk("parse: name", c.name == "SID");
        chk("parse: value", c.value == "abc123");
        chk("parse: Secure flag", c.secure);
        chk("parse: HttpOnly flag", c.httpOnly);
        chk("parse: Path attribute", c.path == "/app");
        chk("parse: SameSite attribute", c.sameSite == "Lax");
    }
    chk("parse: CR/LF in the value is stripped (smuggling dead)",
        !parseSetCookie("SID=ab\r\nX-Injected: 1").value.contains('\r')
        && !parseSetCookie("SID=ab\r\nX-Injected: 1").value.contains('\n'));
    chk("parse: a value containing '=' is kept whole (e.g. base64)",
        parseSetCookie("t=YWJj==").value == "YWJj==");
    chk("parse: a name with a space is rejected (cleared)",
        parseSetCookie("bad name=v").name.isEmpty());
    chk("parse: a header with no '=' yields no name (dropped by caller)",
        parseSetCookie("justflag; Secure").name.isEmpty());
    chk("parse: leading '=' (empty name) is rejected",
        parseSetCookie("=value").name.isEmpty());
    chk("parse: an attribute-only segment doesn't crash and Secure still parses",
        parseSetCookie("a=b; ; Secure").secure);
    // audit-11: only ASCII OWS (SP/HTAB) may be trimmed. QString::trimmed() is
    // Unicode-aware and also eats U+00A0/U+0085, which are legitimate BYTES of the
    // token -- silently corrupting the session we replay.
    chk("parse: a U+00A0 byte in the value is PRESERVED (not eaten as whitespace)",
        parseSetCookie(QString("SID=tok") + QChar(0x00A0) + QString("; Path=/")).value
            == QString("tok") + QChar(0x00A0));
    chk("parse: a U+0085 byte in the value is PRESERVED",
        parseSetCookie(QString("SID=tok") + QChar(0x0085)).value
            == QString("tok") + QChar(0x0085));
    chk("parse: ASCII SP/HTAB around the value are still trimmed",
        parseSetCookie("SID= \tabc123 \t; Path=/").value == "abc123");
    // audit-11: a CONTROL byte inside the name must DROP the cookie, not be stripped
    // into a different synthetic name ("a\tb=v" was becoming a valid cookie "ab").
    chk("parse: a control byte inside the name drops the cookie (no synthetic name)",
        parseSetCookie(QString("a") + QChar('\t') + QString("b=v")).name.isEmpty());
    chk("parse: a vertical-tab inside the name also drops it",
        parseSetCookie(QString("a") + QChar(0x0B) + QString("b=v")).name.isEmpty());
    chk("parse: a clean name is still accepted (guard is not over-broad)",
        parseSetCookie("SID=v").name == "SID");
    // audit-11: attribute matching is case-INSENSITIVE -- the toLower() the CRITICAL
    // Secure/HttpOnly gate depends on was never exercised.
    {
        const CapturedCookie c = parseSetCookie("SID=x; SECURE; HTTPONLY; PATH=/app; SAMESITE=Strict");
        chk("parse: uppercase SECURE flag honored", c.secure);
        chk("parse: uppercase HTTPONLY flag honored", c.httpOnly);
        chk("parse: uppercase PATH attribute honored", c.path == "/app");
        chk("parse: uppercase SAMESITE attribute honored", c.sameSite == "Strict");
    }

    // ===== stripCtrl ====================================================
    chk("stripCtrl: CR/LF/NUL removed",
        stripCtrl(QString("a") + QChar('\r') + QChar('\n') + QChar(0) + QString("b")) == "ab");
    chk("stripCtrl: a clean string is unchanged", stripCtrl("clean-value_123") == "clean-value_123");

    std::fprintf(stderr, "session_manager_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

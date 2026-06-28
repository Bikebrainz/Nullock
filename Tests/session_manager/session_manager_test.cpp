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

    // ===== injectableOverTransport: honor Secure (the CRITICAL fix) =====
    chk("transport: a Secure cookie is NOT injectable over cleartext :80 (no leak)",
        !injectableOverTransport(secure(true), 80));
    chk("transport: a Secure cookie is NOT injectable over :8080",
        !injectableOverTransport(secure(true), 8080));
    chk("transport: a Secure cookie IS injectable over the TLS port :443",
        injectableOverTransport(secure(true), 443));
    chk("transport: a non-Secure cookie is injectable over cleartext :80",
        injectableOverTransport(secure(false), 80));
    chk("transport: a non-Secure cookie is injectable over :443",
        injectableOverTransport(secure(false), 443));
    chk("transport: a Secure cookie over an unknown high TLS port fails CLOSED (not injected)",
        !injectableOverTransport(secure(true), 8443));

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

    // ===== stripCtrl ====================================================
    chk("stripCtrl: CR/LF/NUL removed",
        stripCtrl(QString("a") + QChar('\r') + QChar('\n') + QChar(0) + QString("b")) == "ab");
    chk("stripCtrl: a clean string is unchanged", stripCtrl("clean-value_123") == "clean-value_123");

    std::fprintf(stderr, "session_manager_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

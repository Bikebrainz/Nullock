// Regression corpus for session_rules' pure logic (no proxy). Locks the security
// + soundness fixes from the adversarial audit:
//   - sanitizeHeaderValue strips CR/LF (header-injection / request-smuggling);
//   - sanitizeCookieValue also strips ';' (cookie forging);
//   - jsonEscapeInner escapes a value injected into a JSON body;
//   - jsonPathGet keeps exact integer text (no scientific notation);
//   - findCookieValue reads ONLY the first segment (not Path/Domain attributes);
//   - firstCapture returns the first PARTICIPATING group;
//   - stripQuery matches a pathGlob against the path, not the query.
//
// Run via:  ctest -R session_rules -V

#include "session_rules_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::SessionRulesLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString re(const QString &pattern, const QString &subject) {
    QRegularExpression rx(pattern);
    auto m = rx.match(subject);
    return m.hasMatch() ? firstCapture(m) : QString();
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== sanitizeHeaderValue (CRLF injection / smuggling) =============
    chk("header: a clean token is unchanged", sanitizeHeaderValue("Bearer abc.def") == "Bearer abc.def");
    chk("header: CR/LF stripped (no header splitting)",
        sanitizeHeaderValue("abc\r\nX-Injected: evil") == "abcX-Injected: evil");
    chk("header: a double CRLF (smuggled body) is stripped",
        !sanitizeHeaderValue("a\r\n\r\nGET /admin HTTP/1.1").contains('\r')
        && !sanitizeHeaderValue("a\r\n\r\nGET /admin HTTP/1.1").contains('\n'));
    chk("header: a bare LF is stripped", !sanitizeHeaderValue("a\nb").contains('\n'));
    chk("header: a NUL/control char is stripped", sanitizeHeaderValue(QString("a") + QChar(0x01) + "b") == "ab");
    chk("header: a tab is preserved", sanitizeHeaderValue("a\tb") == "a\tb");

    // ===== sanitizeCookieValue (cookie forging) =========================
    chk("cookie: ';' stripped (no forged pairs)",
        sanitizeCookieValue("good; role=admin") == "good role=admin");
    chk("cookie: CR/LF also stripped", !sanitizeCookieValue("a\r\nb;c").contains('\r'));
    chk("cookie: a plain token is unchanged", sanitizeCookieValue("sess_abc123") == "sess_abc123");

    // ===== jsonEscapeInner (JSON body injection) ========================
    chk("json: a plain value is unchanged", jsonEscapeInner("abc123") == "abc123");
    chk("json: a double-quote is escaped",
        jsonEscapeInner("x\",\"admin\":true,\"y\":\"") == "x\\\",\\\"admin\\\":true,\\\"y\\\":\\\"");
    chk("json: a backslash is escaped", jsonEscapeInner("a\\b") == "a\\\\b");
    chk("json: a newline is escaped (not raw)", jsonEscapeInner("a\nb") == "a\\nb");

    // ===== jsonPathGet (numeric precision + first-segment) ==============
    chk("json-path: string leaf",
        jsonPathGet("{\"data\":{\"token\":\"sk_abc\"}}", "data.token") == "sk_abc");
    chk("json-path: a 10-digit epoch keeps exact integer text (no sci-notation)",
        jsonPathGet("{\"exp\":1719446400}", "exp") == "1719446400");
    chk("json-path: a 64-bit id keeps exact text",
        jsonPathGet("{\"id\":1234567890123}", "id") == "1234567890123");
    chk("json-path: a fractional number is formatted without loss",
        jsonPathGet("{\"v\":1.5}", "v") == "1.5");
    chk("json-path: a bool leaf", jsonPathGet("{\"ok\":true}", "ok") == "true");
    chk("json-path: an array index", jsonPathGet("{\"a\":[10,20,30]}", "a.1") == "20");
    chk("json-path: a miss -> empty", jsonPathGet("{\"a\":1}", "b").isEmpty());
    chk("json-path: indexes a ROOT array", jsonPathGet("[10,20,30]", "1") == "20");
    chk("json-path: a non-numeric array index -> empty (type guard, fail-closed)",
        jsonPathGet("{\"a\":[10]}", "a.x").isEmpty());

    // ===== findCookieValue (first segment only) =========================
    chk("cookie-extract: the cookie value is read", findCookieValue("sid=real; Path=/; HttpOnly", "sid") == "real");
    chk("cookie-extract: an ATTRIBUTE name does NOT return its value (Domain)",
        findCookieValue("sid=real; Domain=evil.example; Path=/", "Domain").isEmpty());
    chk("cookie-extract: Path attribute not returned", findCookieValue("sid=real; Path=/admin", "Path").isEmpty());
    chk("cookie-extract: a missing cookie -> empty", findCookieValue("sid=real", "other").isEmpty());
    chk("cookie-extract: '=' inside the value is preserved (split on the FIRST '=')",
        findCookieValue("sid=a=b==; Path=/", "sid") == "a=b==");

    // ===== firstCapture (first participating group) =====================
    chk("regex: an alternation where group 1 didn't participate uses group 2",
        re(R"((?:Bearer (tok_\w+))|(sess_\w+))", "sess_ABC123") == "sess_ABC123");
    chk("regex: group 1 used when it participates",
        re(R"((?:Bearer (tok_\w+))|(sess_\w+))", "Bearer tok_XYZ") == "tok_XYZ");
    chk("regex: no group -> whole match", re(R"(tok_\w+)", "tok_ABC") == "tok_ABC");

    // ===== stripQuery (pathGlob matching) ===============================
    chk("path: query stripped", stripQuery("/api/session?ts=1719500000") == "/api/session");
    chk("path: no query unchanged", stripQuery("/api/session") == "/api/session");
    chk("path: empty unchanged", stripQuery("").isEmpty());

    // ===== globToRx ======================================================
    chk("glob: '*' matches any", globToRx("*").match("anything.com").hasMatch());
    chk("glob: exact host matches", globToRx("api.example.com").match("api.example.com").hasMatch());
    chk("glob: exact host does not match a different host",
        !globToRx("api.example.com").match("evil.com").hasMatch());
    chk("glob: '/admin*' prefix", globToRx("/admin*").match("/admin/users").hasMatch());
    // \A..\z anchoring (not ^..$): an exact glob must NOT over-match a trailing-newline
    // variant -- PCRE2 $ matches before a final \n, so the scope gate would fire on
    // "api.example.com\n" (a path/host whose trailing %0a decodes to a raw newline).
    chk("glob: exact glob does NOT over-match a trailing-newline variant",
        !globToRx("api.example.com").match("api.example.com\n").hasMatch());

    // ===== substitute (single-pass, no re-expansion) ====================
    // The security-critical primitive: {{var}} tokens are replaced, unknown vars
    // stay literal, and -- crucially -- a REPLACEMENT that itself looks like a
    // token is NOT re-scanned. Response-derived data bound into a var must never
    // pull in ANOTHER var (e.g. a target echoing "{{Authorization}}" must stay
    // literal, not expand to the scanner's own auth token). Was untested.
    {
        QHash<QString, QString> vars;
        vars.insert("tok", "abc123");
        chk("subst: a known {{var}} is replaced",
            substitute("Bearer {{tok}}", vars) == "Bearer abc123");
    }
    {
        QHash<QString, QString> vars;
        vars.insert("a", "X");   // 'b' is deliberately absent
        chk("subst: an unknown {{var}} stays literal, a later known one still fires",
            substitute("{{a}}{{b}}", vars) == "X{{b}}");
    }
    {
        // The discriminating security lock: {{a}} -> "{{b}}", and even though 'b'
        // IS defined, the injected "{{b}}" must NOT be re-expanded to SECRET. A
        // naive replace()-loop (or a re-scanning rewrite) would return "SECRET".
        QHash<QString, QString> vars;
        vars.insert("a", "{{b}}");
        vars.insert("b", "SECRET");
        chk("subst: a substituted value that looks like a token is NOT re-expanded",
            substitute("{{a}}", vars) == "{{b}}");
    }
    {
        QHash<QString, QString> vars;
        vars.insert("a", "x");
        chk("subst: every occurrence of a repeated var is replaced",
            substitute("{{a}}/{{a}}", vars) == "x/x");
    }

    // ===== findHeader (case-insensitive, first match) ===================
    {
        const QList<QPair<QString, QString>> hs = {
            { "Content-Type", "text/html" }, { "X-Dup", "first" }, { "X-Dup", "second" } };
        chk("find-header: case-insensitive name match", findHeader(hs, "content-TYPE") == "text/html");
        chk("find-header: returns the FIRST value on a duplicate name", findHeader(hs, "X-Dup") == "first");
        chk("find-header: a missing header -> empty", findHeader(hs, "X-Absent").isEmpty());
    }

    std::fprintf(stderr, "session_rules_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

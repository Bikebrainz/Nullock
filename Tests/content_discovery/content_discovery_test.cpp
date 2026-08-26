// Regression corpus for content_discovery's pure classification logic (no
// network): normBase joins, and classify()/forbiddenSaturated() -- which lock the
// soft-404 soundness fixes from the adversarial audit:
//   - a redirect to a Location DIFFERENT from the soft-404 target is reported,
//     not suppressed by status alone (the dir-redirect FN);
//   - a 401/403 with a body size distinct from the soft page is reported, not
//     swallowed by a blanket-403 baseline (the auth-soft FN);
//   - a 200 under a 200-soft-404 server is reported only when its size deviates;
//   - an unreliable calibration treats BOTH observed statuses as soft;
//   - WAF saturation (a high 401/403 fraction) is detected so per-path
//     "auth-gated" noise can be collapsed.
//
// Run via:  ctest -R content_discovery -V

#include "content_discovery.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::ContentDiscovery;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
CalibProfile cal404() {                 // hard-404 baseline
    CalibProfile c; c.softStatuses = {404}; c.softLen = 120; c.jitter = 64; c.reliable = true; return c;
}
CalibProfile cal200(int len = 500) {    // 200-soft-404 baseline
    CalibProfile c; c.softStatuses = {200}; c.softLen = len; c.jitter = 64; c.reliable = true; return c;
}
CalibProfile calRedirect() {            // everything 302 -> /login
    CalibProfile c; c.softStatuses = {302}; c.softLen = 30; c.jitter = 64; c.softLocation = "/login"; c.reliable = true; return c;
}
CalibProfile cal403() {                 // everything 403 (blanket forbidden)
    CalibProfile c; c.softStatuses = {403}; c.softLen = 200; c.jitter = 64; c.reliable = true; return c;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== normBase ======================================================
    chk("normBase '/' -> empty", normBase("/").isEmpty());
    chk("normBase '' -> empty", normBase("").isEmpty());
    chk("normBase '/sub/' -> '/sub'", normBase("/sub/") == "/sub");
    chk("normBase 'sub' -> '/sub' (leading slash added)", normBase("sub") == "/sub");
    chk("normBase '/a/b/' -> '/a/b'", normBase("/a/b/") == "/a/b");
    chk("normBase '/x' join is single-slash", (normBase("/x") + "/y") == "/x/y");
    chk("normBase root join is single-slash", (normBase("/") + "/y") == "/y");

    // ===== classify: hard-404 baseline ===================================
    {
        const CalibProfile c = cal404();
        chk("404-baseline: a 200 is a real resource -> ok", classify(200, 900, "", c) == "ok");
        chk("404-baseline: the 404 itself -> not interesting", classify(404, 120, "", c).isEmpty());
        chk("404-baseline: a 301 redirect -> redirect", classify(301, 0, "/elsewhere", c) == "redirect");
        chk("404-baseline: a 303 See Other redirect -> redirect", classify(303, 0, "/elsewhere", c) == "redirect");
        chk("404-baseline: a 403 -> auth-gated", classify(403, 50, "", c) == "auth-gated");
        chk("404-baseline: a 204 -> ok", classify(204, 0, "", c) == "ok");
        chk("404-baseline: a 500 -> not interesting", classify(500, 0, "", c).isEmpty());
    }

    // ===== classify: 200-soft-404 (size deviation) =======================
    {
        const CalibProfile c = cal200(500);
        chk("200-soft: a 200 within jitter -> suppressed", classify(200, 510, "", c).isEmpty());
        chk("200-soft: a 200 equal to soft size -> suppressed", classify(200, 500, "", c).isEmpty());
        chk("200-soft: a 200 far above jitter -> ok-distinct", classify(200, 900, "", c) == "ok-distinct");
        chk("200-soft: a 200 far below jitter -> ok-distinct", classify(200, 100, "", c) == "ok-distinct");
        chk("200-soft: a 301 is still a redirect (different status)", classify(301, 0, "/x", c) == "redirect");
    }

    // ===== classify: redirect-soft-404 (the dir-redirect FN fix) =========
    {
        const CalibProfile c = calRedirect();
        chk("redirect-soft: 302 -> /login (matches soft) -> suppressed", classify(302, 30, "/login", c).isEmpty());
        chk("redirect-soft: 302 -> /login/ (trailing slash normalized) -> suppressed",
            classify(302, 30, "/login/", c).isEmpty());
        chk("redirect-soft: 302 -> /admin/ (DIFFERENT target) -> redirect (FN fix)",
            classify(302, 30, "/admin/", c) == "redirect");
        chk("redirect-soft: 301 (different status than soft 302) -> redirect",
            classify(301, 0, "/login", c) == "redirect");
        chk("redirect-soft: a 200 (status not soft) -> ok", classify(200, 800, "", c) == "ok");
    }

    // ===== classify: blanket-403 soft (the auth-soft FN fix) =============
    {
        const CalibProfile c = cal403();
        chk("403-soft: a 403 with soft-sized body -> suppressed", classify(403, 210, "", c).isEmpty());
        chk("403-soft: a 403 with a DISTINCT (much larger) body -> auth-gated (FN fix)",
            classify(403, 900, "", c) == "auth-gated");
        chk("403-soft: a 401 (status not in soft set) -> auth-gated", classify(401, 200, "", c) == "auth-gated");
        chk("403-soft: a 200 -> ok", classify(200, 400, "", c) == "ok");
    }

    // ===== classify: UNRELIABLE calibration treats both statuses soft ====
    {
        CalibProfile c; c.softStatuses = {404, 200}; c.softLen = 300; c.jitter = 64; c.reliable = false;
        chk("unreliable: a 200 within jitter of soft -> suppressed (200 is a soft status)",
            classify(200, 320, "", c).isEmpty());
        chk("unreliable: a 200 far from soft -> ok-distinct", classify(200, 900, "", c) == "ok-distinct");
        chk("unreliable: a 404 -> suppressed", classify(404, 280, "", c).isEmpty());
        chk("unreliable: a 301 -> redirect (not a soft status)", classify(301, 0, "/x", c) == "redirect");
    }

    // ===== canonicalizeBody + bodyFingerprint (reflective soft-404) ======
    // A templated 404 that echoes the requested path and a per-request id.
    auto soft404 = [](const QString &path) {
        return QStringLiteral("<html><body><h1>Not Found</h1><p>The page ") + path
             + QStringLiteral(" does not exist. Request id 8472913.</p></body></html>");
    };
    {
        chk("canonicalize: digit runs collapse to one placeholder",
            canonicalizeBody("id=12345 hits=6789", "/x") == canonicalizeBody("id=9 hits=0", "/x"));
        chk("canonicalize: the requested path is masked (two paths -> same form)",
            canonicalizeBody("not found: /admin/panel", "/admin/panel")
            == canonicalizeBody("not found: /api/v2/users", "/api/v2/users"));
        chk("canonicalize: a short leaf masks only at a WORD BOUNDARY (not inside boilerplate)",
            canonicalizeBody("Not Found. Visit our developer blog.", "/dev")
            == canonicalizeBody("Not Found. Visit our developer blog.", "/nl404aaaaaaaaaa"));
        chk("fingerprint: deterministic for the same input",
            bodyFingerprint("abc") == bodyFingerprint("abc"));
        chk("fingerprint: differs for materially different content",
            bodyFingerprint("the quick brown fox") != bodyFingerprint("the quick brown cat"));
        chk("fingerprint: two reflective soft-404s for different paths share a fingerprint",
            bodyFingerprint(canonicalizeBody(soft404("/nl404aaaa"), "/nl404aaaa"))
            == bodyFingerprint(canonicalizeBody(soft404("/nl404bbbbbb"), "/nl404bbbbbb")));
    }

    // ===== classify: body-fingerprint overrides the length band ==========
    {
        CalibProfile c = cal200(500);
        c.softBodyHash = bodyFingerprint(canonicalizeBody(soft404("/nl404aaaa"), "/nl404aaaa"));
        c.haveBodyHash = true;

        // (1) FP-flood fix: a reflective soft-404 whose echoed path makes its LENGTH
        // diverge wildly from the soft size is still recognised as the soft page by
        // its matching fingerprint -> suppressed (not a bogus hit).
        const QString refl = soft404("/administrator-backup-portal-2024");
        const quint64 hRefl = bodyFingerprint(canonicalizeBody(refl, "/administrator-backup-portal-2024"));
        chk("fingerprint: a length-divergent reflective soft-404 is SUPPRESSED by the matching hash (FP-flood fix)",
            classify(200, 99999, "", c, hRefl, true).isEmpty());

        // (2) same-length FN fix: a REAL resource whose body size happens to equal
        // the soft-404 size (within jitter) is reported because its fingerprint
        // differs -- the length band alone would have silently dropped it.
        const QString real = QStringLiteral("<html><body><h1>Admin Console</h1><form>login</form></body></html>");
        const quint64 hReal = bodyFingerprint(canonicalizeBody(real, "/admin"));
        chk("fingerprint: a real resource AT the soft length is ok-distinct (hash differs) (same-length FN fix)",
            classify(200, 500, "", c, hReal, true) == "ok-distinct");

        // (3) the fingerprint only governs the 200 path; a 301/403 is unaffected.
        chk("fingerprint: a 301 still classifies as redirect regardless of body hash",
            classify(301, 0, "/x", c, hReal, true) == "redirect");
    }
    {
        // (4) fallback: when the profile has NO reliable fingerprint (noisy 404),
        // the length band still governs even if the caller supplies a candidate hash.
        const CalibProfile noisy = cal200(500);   // haveBodyHash defaults false
        chk("fingerprint: no profile hash -> within-jitter 200 suppressed by length",
            classify(200, 510, "", noisy, 12345ULL, true).isEmpty());
        chk("fingerprint: no profile hash -> beyond-jitter 200 is ok-distinct by length",
            classify(200, 900, "", noisy, 12345ULL, true) == "ok-distinct");
        // (5) backward-compat: the 4-arg form (no candidate hash) is unchanged.
        chk("fingerprint: 4-arg classify still length-only (within jitter suppressed)",
            classify(200, 510, "", cal200(500)).isEmpty());
    }

    // ===== forbiddenSaturated (WAF pattern-blocking) =====================
    chk("saturated: 50/100 forbidden -> true", forbiddenSaturated(50, 100));
    chk("saturated: 40/100 forbidden -> true (at threshold)", forbiddenSaturated(40, 100));
    chk("saturated: 39/100 forbidden -> false (below 40%)", !forbiddenSaturated(39, 100));
    chk("saturated: 9 forbidden -> false (below the absolute floor)", !forbiddenSaturated(9, 20));
    chk("saturated: 12/20 forbidden -> true (60%)", forbiddenSaturated(12, 20));
    chk("saturated: 10/100 forbidden -> false (10%)", !forbiddenSaturated(10, 100));
    chk("saturated: zero probed -> false", !forbiddenSaturated(0, 0));

    // ===== expandWithExtensions: word + each suffix, bare word first ==========
    {
        const QStringList w = { "admin", "login" };
        chk("expand: no extensions -> unchanged",
            expandWithExtensions(w, {}) == w);
        const QStringList e1 = expandWithExtensions({ "admin" }, { ".php", ".bak" });
        chk("expand: one word, two exts -> [word, word+ext1, word+ext2] in order",
            e1 == QStringList({ "admin", "admin.php", "admin.bak" }));
        const QStringList e2 = expandWithExtensions({ "a", "b" }, { ".x" });
        chk("expand: multiple words interleaved (a, a.x, b, b.x)",
            e2 == QStringList({ "a", "a.x", "b", "b.x" }));
        // blank extension is skipped (would just re-probe the bare word)
        const QStringList e3 = expandWithExtensions({ "a" }, { "", ".y" });
        chk("expand: blank extension skipped", e3 == QStringList({ "a", "a.y" }));
        // count == N * (1 + non-blank exts)
        const QStringList e4 = expandWithExtensions({ "a", "b", "c" }, { ".1", ".2", ".3" });
        chk("expand: count == N*(1+M)", e4.size() == 3 * (1 + 3));
        // the bare word is always present
        chk("expand: bare word retained", e4.contains("a") && e4.contains("b"));
    }

    // ===== mutateFilenames: backup/temp/editor variants per word ==============
    {
        chk("mutate: disabled -> wordlist unchanged",
            mutateFilenames(QStringList{ "admin", "config" }, false)
                == (QStringList{ "admin", "config" }));
        const QStringList m = mutateFilenames(QStringList{ "admin" }, true);
        chk("mutate: bare word kept first", !m.isEmpty() && m.first() == "admin");
        chk("mutate: emits ~ / .bak / .old / .orig / .save / .tmp / .1",
            m.contains("admin~") && m.contains("admin.bak") && m.contains("admin.old")
            && m.contains("admin.orig") && m.contains("admin.save")
            && m.contains("admin.tmp") && m.contains("admin.1"));
        chk("mutate: emits vim swap .admin.swp", m.contains(".admin.swp"));
        chk("mutate: exactly 9 variants (bare + 7 suffix + swap)", m.size() == 9);
        // Directory-aware: the swap dotfile stays in the same directory as the leaf.
        const QStringList md = mutateFilenames(QStringList{ "api/config" }, true);
        chk("mutate: dir-aware swap is api/.config.swp", md.contains("api/.config.swp"));
        chk("mutate: dir word.bak is api/config.bak", md.contains("api/config.bak"));
    }

    std::fprintf(stderr, "content_discovery_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

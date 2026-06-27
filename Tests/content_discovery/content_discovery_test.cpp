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

    // ===== forbiddenSaturated (WAF pattern-blocking) =====================
    chk("saturated: 50/100 forbidden -> true", forbiddenSaturated(50, 100));
    chk("saturated: 40/100 forbidden -> true (at threshold)", forbiddenSaturated(40, 100));
    chk("saturated: 39/100 forbidden -> false (below 40%)", !forbiddenSaturated(39, 100));
    chk("saturated: 9 forbidden -> false (below the absolute floor)", !forbiddenSaturated(9, 20));
    chk("saturated: 12/20 forbidden -> true (60%)", forbiddenSaturated(12, 20));
    chk("saturated: 10/100 forbidden -> false (10%)", !forbiddenSaturated(10, 100));
    chk("saturated: zero probed -> false", !forbiddenSaturated(0, 0));

    std::fprintf(stderr, "content_discovery_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

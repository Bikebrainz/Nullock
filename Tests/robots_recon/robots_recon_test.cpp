// Regression corpus for robots_recon's pure parsing (no network): the directive
// guard, Disallow path-vs-pattern classification, namespaced/attributed <loc>
// extraction, and sitemap-index detection. These lock the soundness fixes from
// the adversarial audit:
//   - parseRobots splits concrete PATHS from match PATTERNS ("/*.php$") and drops
//     absolute-URL values (so a consumer never GETs a literal pattern);
//   - parseSitemapLocs matches <image:loc>/<loc xml:lang=...> (were dropped);
//   - isSitemapIndex distinguishes a <sitemapindex> (child sitemaps) from pages;
//   - looksLikeRobots only accepts a line-leading directive (not arbitrary HTML).
//
// Run via:  ctest -R robots_recon -V

#include "robots_recon.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::RobotsRecon;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool has(const QStringList &l, const QString &v) { return l.contains(v); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== looksLikeRobots: line-leading directive only ==================
    chk("looksLikeRobots: a real robots.txt matches",
        looksLikeRobots("User-agent: *\nDisallow: /admin/"));
    chk("looksLikeRobots: a lone Sitemap line matches", looksLikeRobots("Sitemap: https://h/s.xml"));
    chk("looksLikeRobots: HTML with an inline 'disallow:' does NOT match (^\\s* anchor)",
        !looksLikeRobots("<html><p>we disallow: bots</p></html>"));
    chk("looksLikeRobots: a list item '- sitemap:' does NOT match",
        !looksLikeRobots("- sitemap: regenerated nightly"));
    chk("looksLikeRobots: leading-whitespace directive still matches",
        looksLikeRobots("   \tDisallow: /x"));

    // ===== parseRobots: path vs pattern vs absolute-URL ==================
    {
        const QString body =
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /backup\n"
            "Disallow: /*.php$\n"        // pattern
            "Disallow: /search?*\n"      // pattern
            "Disallow: *\n"              // pattern
            "Disallow: /\n"              // whole-site -> skipped
            "Disallow: https://cdn.other.com/private\n"  // absolute URL -> dropped
            "Disallow: # empty after comment\n"          // empty -> skipped
            "Allow: /admin/public/\n"    // allow ignored
            "Sitemap: https://h/sitemap.xml\n"
            "Sitemap: https://h/sitemap.xml\n";          // dup -> deduped
        QStringList dis, pat, sm;
        bool trunc = false;
        parseRobots(body, dis, pat, sm, trunc);
        chk("parseRobots: concrete path /admin/ collected", has(dis, "/admin/"));
        chk("parseRobots: concrete path /backup collected", has(dis, "/backup"));
        chk("parseRobots: pattern /*.php$ is NOT a concrete path", !has(dis, "/*.php$"));
        chk("parseRobots: pattern /*.php$ goes to patterns bucket", has(pat, "/*.php$"));
        chk("parseRobots: '/search?*' classified as a pattern", has(pat, "/search?*") && !has(dis, "/search?*"));
        chk("parseRobots: bare '*' classified as a pattern", has(pat, "*") && !has(dis, "*"));
        chk("parseRobots: 'Disallow: /' (whole-site) is skipped entirely",
            !has(dis, "/") && !has(pat, "/"));
        chk("parseRobots: an absolute-URL Disallow value is dropped (not a same-host path)",
            !has(dis, "https://cdn.other.com/private") && !has(pat, "https://cdn.other.com/private"));
        chk("parseRobots: Allow lines are ignored", !has(dis, "/admin/public/"));
        chk("parseRobots: Sitemap ref captured + deduped", sm.size() == 1 && has(sm, "https://h/sitemap.xml"));
        chk("parseRobots: not truncated on a small list", !trunc);
    }
    // Comment stripping (RFC 9309: '#' to EOL is a comment).
    {
        QStringList dis, pat, sm; bool trunc = false;
        parseRobots("Disallow: /keep  # trailing comment\n", dis, pat, sm, trunc);
        chk("parseRobots: trailing comment stripped from value", has(dis, "/keep"));
    }

    // ===== parseSitemapLocs: namespaced / attributed <loc> ==============
    {
        const QString xml =
            "<urlset>"
            "<url><loc>https://h/page1</loc></url>"
            "<url><loc>https://h/PAGE2</loc></url>"
            "<url><loc xml:lang=\"en\">https://h/attr</loc></url>"
            "<image:image><image:loc>https://h/img.jpg</image:loc></image:image>"
            "<url><loc>https://h/page1</loc></url>"   // dup -> deduped
            "</urlset>";
        bool trunc = false;
        const QStringList locs = parseSitemapLocs(xml, trunc);
        chk("sitemap: plain <loc> extracted", has(locs, "https://h/page1"));
        chk("sitemap: case in path preserved", has(locs, "https://h/PAGE2"));
        chk("sitemap: ATTRIBUTED <loc xml:lang> extracted (was dropped)", has(locs, "https://h/attr"));
        chk("sitemap: NAMESPACED <image:loc> extracted (was dropped)", has(locs, "https://h/img.jpg"));
        chk("sitemap: duplicate <loc> deduped", locs.count("https://h/page1") == 1);
        chk("sitemap: <location> is NOT matched as <loc>",
            parseSitemapLocs("<location>https://h/x</location>", trunc).isEmpty());
        chk("sitemap: not truncated on a small list", !trunc);
    }

    // ===== isSitemapIndex: index vs urlset ==============================
    chk("isSitemapIndex: <sitemapindex> detected",
        isSitemapIndex("<sitemapindex><sitemap><loc>https://h/s1.xml</loc></sitemap></sitemapindex>"));
    chk("isSitemapIndex: namespaced <sm:sitemapindex> detected",
        isSitemapIndex("<sm:sitemapindex><sm:sitemap><sm:loc>https://h/s1.xml</sm:loc></sm:sitemap></sm:sitemapindex>"));
    chk("isSitemapIndex: a plain <urlset> is NOT an index",
        !isSitemapIndex("<urlset><url><loc>https://h/p</loc></url></urlset>"));

    std::fprintf(stderr, "robots_recon_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

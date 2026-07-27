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
            "Disallow: /go?next=https://ext.example/cb\n"// path w/ URL in query -> KEPT (recon-3)
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
        chk("parseRobots: a same-host path whose QUERY contains '://' is KEPT (recon-3)",
            has(dis, "/go?next=https://ext.example/cb")
            && !has(dis, "https://cdn.other.com/private"));  // absolute still dropped
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
    // A '$' END-ANCHOR with NO '*' is still a match PATTERN, not a fetchable path.
    // Every other pattern case carries a '*' (which short-circuits isDisallowPattern
    // via contains('*')), so the endsWith('$') arm is otherwise unexercised. A
    // regression dropping that arm would mis-bucket "/private$" as a concrete path
    // and a consumer would GET the literal "/private$" (a 404), missing the real lead.
    {
        QStringList dis, pat, sm; bool trunc = false;
        parseRobots("Disallow: /private$\n", dis, pat, sm, trunc);
        chk("parseRobots: a '$'-anchored value (no '*') is a PATTERN, not a path",
            has(pat, "/private$") && !has(dis, "/private$"));
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
    // FP fixes: the substring ":sitemapindex"/"<sitemapindex" inside a <loc> URL or
    // a comment must NOT flip a page <urlset> to an index (which dropped its pages).
    chk("isSitemapIndex: ':sitemapindex' inside a page <loc> is NOT an index (substring FP fix)",
        !isSitemapIndex("<urlset><url><loc>https://h/x?ref=:sitemapindex</loc></url></urlset>"));
    chk("isSitemapIndex: '<sitemapindex' buried in a comment is NOT an index (comment FP fix)",
        !isSitemapIndex("<!-- example root: <sitemapindex> --><urlset><url><loc>https://h/p</loc></url></urlset>"));
    chk("isSitemapIndex: a real index whose child <loc> path contains 'urlset' is STILL an index",
        isSitemapIndex("<sitemapindex><sitemap><loc>https://h/urlset-pages.xml</loc></sitemap></sitemapindex>"));

    // ===== portInScope: req port, or a canonical http<->https default hop =
    chk("portInScope: same port -> in", portInScope(443, true, 443, true));
    chk("portInScope: http:80 -> https:443 upgrade -> in (tested redirect path)",
        portInScope(443, true, 80, false));
    chk("portInScope: https:443 -> http:80 downgrade -> in", portInScope(80, false, 443, true));
    chk("portInScope: https:443 -> :9200 -> OUT (attacker port pivot)", !portInScope(9200, false, 443, true));
    chk("portInScope: https:443 -> :6379 -> OUT", !portInScope(6379, false, 443, true));
    chk("portInScope: https:443 -> :22 -> OUT", !portInScope(22, true, 443, true));
    chk("portInScope: seed pinned to :8443 -> :8443 -> in", portInScope(8443, true, 8443, true));
    chk("portInScope: seed pinned to :8443 -> :443 default -> OUT (no hop off a non-standard scoped port)",
        !portInScope(443, true, 8443, true));

    // ===== parseFetchTarget: fetchable http(s) target, else invalid =====
    {
        const FetchTarget t = parseFetchTarget("https://h.com/sitemap2.xml");
        chk("fetchTarget: https URL is valid + tls", t.valid && t.tls);
        chk("fetchTarget: host parsed", t.host == "h.com");
        chk("fetchTarget: https default port 443", t.port == 443);
        chk("fetchTarget: path parsed", t.path == "/sitemap2.xml");
        const FetchTarget h = parseFetchTarget("http://h.com:8080/a/b.xml?x=1");
        chk("fetchTarget: explicit port kept", h.valid && !h.tls && h.port == 8080);
        chk("fetchTarget: query preserved on the path", h.path == "/a/b.xml?x=1");
        const FetchTarget root = parseFetchTarget("https://h.com");
        chk("fetchTarget: empty path normalizes to '/'", root.valid && root.path == "/");
        chk("fetchTarget: a non-http(s) scheme is invalid", !parseFetchTarget("ftp://h.com/x").valid);
        chk("fetchTarget: a javascript: URL is invalid", !parseFetchTarget("javascript:alert(1)").valid);
        chk("fetchTarget: a hostless/relative value is invalid", !parseFetchTarget("/sitemap.xml").valid);
        chk("fetchTarget: empty is invalid", !parseFetchTarget("").valid);
    }

    // ===== resolveRedirect: relative+absolute, http(s)-only =============
    chk("resolveRedirect: absolute https kept",
        resolveRedirect("https://h.com/new", "https://h.com/old") == "https://h.com/new");
    chk("resolveRedirect: a root-relative Location resolves against the base",
        resolveRedirect("/sitemap_index.xml", "https://h.com/sitemap.xml") == "https://h.com/sitemap_index.xml");
    chk("resolveRedirect: a scheme upgrade (http->https) is followed",
        resolveRedirect("https://h.com/s.xml", "http://h.com/s.xml") == "https://h.com/s.xml");
    chk("resolveRedirect: a javascript: redirect is NOT followed (empty)",
        resolveRedirect("javascript:alert(1)", "https://h.com/s.xml").isEmpty());
    chk("resolveRedirect: an empty Location -> empty", resolveRedirect("", "https://h.com/s.xml").isEmpty());

    // ===== sameHost: case-insensitive no-host-jump guard ================
    chk("sameHost: identical hosts match", sameHost("h.com", "h.com"));
    chk("sameHost: case-insensitive", sameHost("H.CoM", "h.com"));
    chk("sameHost: a different host does NOT match (no host-jump)", !sameHost("evil.com", "h.com"));
    chk("sameHost: a subdomain does NOT match (exact only)", !sameHost("a.h.com", "h.com"));
    chk("sameHost: empty does not match", !sameHost("", "h.com"));

    std::fprintf(stderr, "robots_recon_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Regression corpus for the crawler's pure logic (no network): the fail-closed
// default scope, <base href> resolution, quoted+unquoted link extraction, the
// http(s)-only canonicalizer, and tag-boundary body truncation. These lock the
// scope-safety + extraction fixes from the adversarial audit:
//   - inDefaultScope keeps an unconfigured crawl inside the seed's domain tree
//     (no fail-open walk of arbitrary hosts);
//   - canonicalLink rejects mailto:/javascript:/data: and normalizes the apex;
//   - extractRawLinks finds UNQUOTED href=/admin (was missed);
//   - resolveBase honors <base href> so relatives resolve correctly;
//   - truncateBodyAtTag never splits a tag mid-attribute.
//
// Run via:  ctest -R crawler -V

#include "crawler_logic.hpp"

#include <QCoreApplication>
#include <QUrl>

#include <cstdio>

using namespace Nullock::Core::CrawlerLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
// canonicalLink with the host discarded.
QString canon(const QString &href, const QString &base) {
    QString h; return canonicalLink(href, QUrl(base), h);
}
bool listHas(const QStringList &l, const QString &v) { return l.contains(v); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== inDefaultScope: fail-closed to the seed's domain tree =========
    chk("default scope: exact seed host in scope", inDefaultScope("example.com", "example.com"));
    chk("default scope: subdomain of apex in scope", inDefaultScope("api.example.com", "example.com"));
    chk("default scope: apex in scope when seed is www", inDefaultScope("example.com", "www.example.com"));
    chk("default scope: sibling subdomain in scope when seed is www",
        inDefaultScope("api.example.com", "www.example.com"));
    chk("default scope: deep subdomain in scope", inDefaultScope("a.b.example.com", "example.com"));
    chk("default scope: case-insensitive", inDefaultScope("API.Example.COM", "example.com"));
    chk("default scope: a DIFFERENT site is OUT of scope (no fail-open)",
        !inDefaultScope("evil.com", "example.com"));
    chk("default scope: a suffix-confusion host is OUT of scope",
        !inDefaultScope("notexample.com", "example.com"));
    chk("default scope: example.com.evil.com is OUT of scope",
        !inDefaultScope("example.com.evil.com", "example.com"));
    chk("default scope: a bare TLD-ish seed does not scope the whole TLD",
        !inDefaultScope("other.com", "site.com"));
    chk("default scope: empty host is out", !inDefaultScope("", "example.com"));
    chk("default scope: empty seed is out (nothing in scope)", !inDefaultScope("example.com", ""));

    // ===== effectivePort: explicit port wins, else scheme default ========
    chk("effPort: explicit 8080 kept", effectivePort("https", 8080) == 8080);
    chk("effPort: https default 443", effectivePort("https", -1) == 443);
    chk("effPort: http default 80", effectivePort("http", -1) == 80);
    chk("effPort: case-insensitive scheme", effectivePort("HTTPS", -1) == 443);
    chk("effPort: explicit beats scheme default", effectivePort("http", 443) == 443);

    // ===== inDefaultScopeOrigin: host tree AND no cross-service port hop ==
    // Seed on a standard web port: http<->https on the in-tree host stays in scope.
    chk("origin scope: seed https:443, link https same host -> in",
        inDefaultScopeOrigin("https", "example.com", -1, "https", "example.com", -1));
    chk("origin scope: seed https:443, link HTTP same host -> in (http<->https hop)",
        inDefaultScopeOrigin("http", "example.com", -1, "https", "example.com", -1));
    chk("origin scope: seed https:443, in-tree subdomain on 443 -> in",
        inDefaultScopeOrigin("https", "api.example.com", -1, "https", "example.com", -1));
    // ...but a non-standard port on the same host is a DIFFERENT service -> creep.
    chk("origin scope: seed https:443, link host:8080 -> OUT (cross-service creep)",
        !inDefaultScopeOrigin("http", "example.com", 8080, "https", "example.com", -1));
    chk("origin scope: seed https:443, link host:8443 -> OUT",
        !inDefaultScopeOrigin("https", "example.com", 8443, "https", "example.com", -1));
    // Off-tree host is out regardless of port.
    chk("origin scope: a different site is OUT even on a standard port",
        !inDefaultScopeOrigin("https", "evil.com", -1, "https", "example.com", -1));
    // Seed pinned to a NON-standard port: stay on exactly that port.
    chk("origin scope: seed :8080, link :8080 same host -> in",
        inDefaultScopeOrigin("http", "example.com", 8080, "http", "example.com", 8080));
    chk("origin scope: seed :8080, link :443 same host -> OUT (pinned to 8080)",
        !inDefaultScopeOrigin("https", "example.com", -1, "http", "example.com", 8080));
    chk("origin scope: seed :8080, link :9090 same host -> OUT",
        !inDefaultScopeOrigin("http", "example.com", 9090, "http", "example.com", 8080));
    chk("origin scope: seed :8080, in-tree subdomain on :8080 -> in",
        inDefaultScopeOrigin("http", "api.example.com", 8080, "http", "example.com", 8080));

    // ===== canonicalLink: resolve + http(s) allow-list + normalize =======
    chk("canon: relative path resolves against base",
        canon("/admin", "https://h.com/x/y") == "https://h.com/admin");
    chk("canon: relative file resolves against the dir",
        canon("login.php", "https://h.com/app/") == "https://h.com/app/login.php");
    chk("canon: absolute http(s) URL kept",
        canon("https://h.com/p", "https://h.com/") == "https://h.com/p");
    chk("canon: protocol-relative inherits the scheme",
        canon("//cdn.com/a.js", "https://h.com/") == "https://cdn.com/a.js");
    chk("canon: fragment is stripped",
        canon("/p#section", "https://h.com/") == "https://h.com/p");
    chk("canon: apex with no path normalizes to '/'",
        canon("https://h.com", "https://h.com/") == "https://h.com/");
    chk("canon: mailto: -> rejected (empty)", canon("mailto:a@b.com", "https://h.com/").isEmpty());
    chk("canon: tel: -> rejected", canon("tel:+15551234", "https://h.com/").isEmpty());
    chk("canon: javascript: -> rejected", canon("javascript:void(0)", "https://h.com/").isEmpty());
    chk("canon: data: -> rejected", canon("data:text/html,x", "https://h.com/").isEmpty());
    chk("canon: ftp: -> rejected (http(s) only)", canon("ftp://h.com/f", "https://h.com/").isEmpty());
    chk("canon: bare fragment resolves to the page itself (deduped upstream)",
        canon("#top", "https://h.com/p") == "https://h.com/p");
    {
        QString host;
        canonicalLink("/x", QUrl("https://Sub.Example.COM/a"), host);
        chk("canon: outHost is lower-cased", host == "sub.example.com");
        QString host2;
        const QString r = canonicalLink("mailto:x@y", QUrl("https://h.com/"), host2);
        chk("canon: rejected link clears outHost", r.isEmpty() && host2.isEmpty());
    }

    // ===== extractRawLinks: quoted AND unquoted ==========================
    {
        const QString html =
            "<a href=\"/a\">x</a> <a href='/b'>y</a> <a href=/c>z</a>"
            "<img src=/img/logo.png><form action=/search>"
            "<a href = \"/spaced\">";
        const QStringList l = extractRawLinks(html);
        chk("extract: double-quoted href", listHas(l, "/a"));
        chk("extract: single-quoted href", listHas(l, "/b"));
        chk("extract: UNQUOTED href (was missed)", listHas(l, "/c"));
        chk("extract: unquoted src", listHas(l, "/img/logo.png"));
        chk("extract: unquoted form action", listHas(l, "/search"));
        chk("extract: whitespace around '=' tolerated", listHas(l, "/spaced"));
    }
    chk("extract: no links -> empty", extractRawLinks("<p>nothing here</p>").isEmpty());

    // ===== resolveBase: honor <base href> ================================
    {
        const QString page = "https://app.example.com/portal/index.html";
        const QString withBase =
            "<head><base href=\"https://cdn.example.com/v2/\"></head><a href=\"users\">";
        const QUrl b = resolveBase(withBase, QUrl(page));
        QString host;
        chk("base href: relative resolves against <base>, not the page",
            canonicalLink("users", b, host) == "https://cdn.example.com/v2/users");
        // No <base> -> falls back to the page URL.
        const QUrl b2 = resolveBase("<a href=\"users\">", QUrl(page));
        chk("base href: absent -> page URL is the base",
            canonicalLink("users", b2, host) == "https://app.example.com/portal/users");
        // A relative <base href> resolves against the page first.
        const QUrl b3 = resolveBase("<base href=\"/api/\">", QUrl(page));
        chk("base href: relative <base> resolves against the page",
            canonicalLink("v1", b3, host) == "https://app.example.com/api/v1");
    }

    // ===== truncateBodyAtTag: never split a tag ==========================
    {
        const QByteArray small = "<a href=\"/x\">";
        chk("truncate: body under the cap is returned whole",
            truncateBodyAtTag(small, 4096) == small);
        // Cut falls mid-attribute -> back up to the last complete tag '>'.
        const QByteArray body = "<a href=\"/keep\"><a href=\"/dropped-because-split";
        const QByteArray cut = truncateBodyAtTag(body, 30);   // mid the second tag
        chk("truncate: cut backs up to the last '>' (keeps complete tags)",
            cut.endsWith('>') && cut.contains("/keep") && !cut.contains("/dropped"));
        chk("truncate: no '>' before cap -> empty rather than a split tag",
            truncateBodyAtTag(QByteArray("href=\"/no-tag-here-at-all"), 8).isEmpty());
    }

    // ===== extractSrcset ================================================
    {
        const QStringList l = extractSrcset("<img srcset=\"/img/a.jpg 1x, /img/b.jpg 2x\">");
        chk("srcset: first candidate URL", listHas(l, "/img/a.jpg"));
        chk("srcset: second candidate URL (descriptor stripped)", listHas(l, "/img/b.jpg"));
        chk("srcset: no descriptor mixed in", !listHas(l, "/img/a.jpg 1x"));
        chk("srcset: none -> empty", extractSrcset("<img src=/x.png>").isEmpty());
    }

    // ===== extractMetaRefresh ===========================================
    {
        chk("meta-refresh: url extracted",
            listHas(extractMetaRefresh("<meta http-equiv=\"refresh\" content=\"0;url=/next\">"), "/next"));
        chk("meta-refresh: attribute order tolerant",
            listHas(extractMetaRefresh("<meta content='5; url=/dest' http-equiv=refresh>"), "/dest"));
        chk("meta-refresh: a non-refresh meta is ignored",
            extractMetaRefresh("<meta name=\"viewport\" content=\"width=device-width\">").isEmpty());
    }

    // ===== extractFormGets ==============================================
    {
        const QStringList l = extractFormGets(
            "<form method=get action=/search><input name=q><input name=\"lang\"></form>");
        chk("form-get: synthesizes action?param surface", listHas(l, "/search?q=&lang="));
        const QStringList l2 = extractFormGets("<form method=\"GET\"><input name=x><select name=y></select></form>");
        chk("form-get: action-less form -> relative ?param", listHas(l2, "?x=&y="));
        chk("form-get: a POST form is ignored",
            extractFormGets("<form method=post action=/save><input name=q></form>").isEmpty());
        chk("form-get: a GET form with no fields yields nothing",
            extractFormGets("<form method=get action=/x></form>").isEmpty());
    }

    std::fprintf(stderr, "crawler_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

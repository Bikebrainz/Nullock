// Regression corpus for the cache-poisoning probe's pure logic (no network):
//   - gateDecision: the FAIL-CLOSED safety decision (silent cache, failed
//     confirm, unkeyed buster all abort; only proven-keyed injects).
//   - reflectionSite: body vs replayed headers (Location/Link); Set-Cookie and
//     other per-response headers excluded (the cross-user-poisoning FP fix).
//   - cacheHitSignal / looksCacheable: Age/X-Cache hits, Cache-Control tiers,
//     and the Vary-on-injected-header downgrade (the Vary FP fix).
//   - buildRequest: CR/LF guards on method/host/basePath + carried/extra header.
//
// Run via:  ctest -R cache_poison -V

#include "cache_poison.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::CachePoison;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
Headers H(std::initializer_list<QPair<QString, QString>> l) { return Headers(l); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- gateDecision: the fail-closed safety core ----------------------
    // Proven keyed: same-buster hit AND different-buster miss -> inject.
    chk("gate: hit + different-miss -> Inject",
        gateDecision(/*bOk*/true, /*bHit*/true, /*cOk*/true, /*cHit*/false) == Gate::Inject);
    // Silent cache: no hit signal on the same-buster repeat -> abort (the
    // headline fail-open bug; absence of proof must BLOCK injection).
    chk("gate: no hit signal -> AbortNoHitSignal",
        gateDecision(true, false, false, false) == Gate::AbortNoHitSignal);
    chk("gate: b request failed -> AbortNoHitSignal",
        gateDecision(false, false, false, false) == Gate::AbortNoHitSignal);
    // Hit on b but the confirmation request failed -> can't prove keyed -> abort
    // (old code fell through to inject on c.ok==false).
    chk("gate: confirm request failed -> AbortConfirmFailed",
        gateDecision(true, true, /*cOk*/false, false) == Gate::AbortConfirmFailed);
    // Different buster also hit -> cache ignores the buster (unkeyed) -> abort.
    chk("gate: different buster also hit -> AbortUnkeyed",
        gateDecision(true, true, true, /*cHit*/true) == Gate::AbortUnkeyed);

    // ---- reflectionSite: poisonable surfaces only -----------------------
    const QString tok = QStringLiteral("npdeadbeef01");
    chk("refl: body match",
        reflectionSite(QByteArray("<p>npdeadbeef01</p>"), {}, tok) == QStringLiteral("body"));
    chk("refl: Location header counts",
        reflectionSite(QByteArray("ok"), H({{"Location", "https://npdeadbeef01.evil/"}}), tok)
            == QStringLiteral("header:Location"));
    chk("refl: Link header counts",
        reflectionSite(QByteArray("ok"), H({{"Link", "<//npdeadbeef01>; rel=preload"}}), tok)
            == QStringLiteral("header:Link"));
    // Set-Cookie reflection is NOT cross-user cache poisoning -> excluded (FP fix).
    chk("refl: Set-Cookie excluded (FP fix)",
        reflectionSite(QByteArray("ok"), H({{"Set-Cookie", "d=npdeadbeef01; Path=/"}}), tok).isEmpty());
    chk("refl: arbitrary header excluded",
        reflectionSite(QByteArray("ok"), H({{"X-Debug", "npdeadbeef01"}}), tok).isEmpty());
    chk("refl: absent",
        reflectionSite(QByteArray("nothing here"), H({{"Server", "nginx"}}), tok).isEmpty());

    // ---- cacheHitSignal -------------------------------------------------
    chk("hit: Age present", cacheHitSignal(H({{"Age", "7"}})));
    chk("hit: Age zero still counts", cacheHitSignal(H({{"Age", "0"}})));
    chk("hit: X-Cache HIT", cacheHitSignal(H({{"X-Cache", "HIT"}})));
    chk("hit: CF-Cache-Status hit", cacheHitSignal(H({{"CF-Cache-Status", "hit"}})));
    chk("hit: X-Cache MISS -> no signal", !cacheHitSignal(H({{"X-Cache", "MISS"}})));
    chk("hit: none -> no signal", !cacheHitSignal(H({{"Server", "nginx"}})));

    // ---- looksCacheable: Cache-Control tiers + Vary downgrade -----------
    chk("cacheable: public", looksCacheable(H({{"Cache-Control", "public, max-age=60"}})));
    chk("cacheable: s-maxage>0", looksCacheable(H({{"Cache-Control", "s-maxage=30"}})));
    chk("cacheable: Expires", looksCacheable(H({{"Expires", "Wed, 21 Oct 2099 07:28:00 GMT"}})));
    chk("cacheable: no-store -> false", !looksCacheable(H({{"Cache-Control", "public, no-store"}})));
    chk("cacheable: private -> false", !looksCacheable(H({{"Cache-Control", "private, max-age=60"}})));
    chk("cacheable: max-age=0 -> false", !looksCacheable(H({{"Cache-Control", "max-age=0"}})));
    chk("cacheable: nothing -> false", !looksCacheable(H({{"Server", "nginx"}})));
    // Vary on the injected header -> keyed per value -> NOT cross-user poisonable.
    chk("cacheable: Vary on injected header -> false (FP fix)",
        !looksCacheable(H({{"Cache-Control", "public, max-age=60"},
                           {"Vary", "Accept-Encoding, X-Forwarded-Host"}}),
                        QStringLiteral("X-Forwarded-Host")));
    chk("cacheable: Vary on OTHER header -> still cacheable",
        looksCacheable(H({{"Cache-Control", "public, max-age=60"}, {"Vary", "Accept-Encoding"}}),
                       QStringLiteral("X-Forwarded-Host")));
    chk("cacheable: Vary:* -> false",
        !looksCacheable(H({{"Cache-Control", "public, max-age=60"}, {"Vary", "*"}}),
                        QStringLiteral("X-Forwarded-Host")));
    // An actual cache hit overrides cacheability heuristics regardless of Vary.
    chk("cacheable: explicit hit wins", looksCacheable(H({{"X-Cache", "HIT"}, {"Vary", "*"}})));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/dl";
        const QByteArray ok = buildRequest(req, "ncb=x", QString(), QString());
        chk("build: request line", ok.startsWith("GET /dl?ncb=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        const QByteArray withHdr = buildRequest(req, "ncb=x", "X-Forwarded-Host", "evil.test");
        chk("build: extra header emitted", withHdr.contains("X-Forwarded-Host: evil.test\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header",
            !buildRequest(injHdr, "ncb=x", QString(), QString()).contains("X-Smuggled"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty",
            buildRequest(badMethod, "ncb=x", QString(), QString()).isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty",
            buildRequest(badHost, "ncb=x", QString(), QString()).isEmpty());
        Request badPath = req; badPath.basePath = "/dl\r\nX: y";
        chk("build: CRLF path -> empty",
            buildRequest(badPath, "ncb=x", QString(), QString()).isEmpty());
        chk("build: CRLF extra header dropped",
            !buildRequest(req, "ncb=x", "X-Inj\r\nEvil", "v").contains("Evil"));
    }

    // ---- withBuster -----------------------------------------------------
    chk("buster: adds ncb to empty query", withBuster(QString(), "abc").contains("ncb=abc"));
    {
        const QString q = withBuster("a=1&ncb=old", "new");
        chk("buster: replaces existing ncb", q.contains("ncb=new") && !q.contains("ncb=old"));
        chk("buster: preserves other params", q.contains("a=1"));
    }

    std::fprintf(stderr, "cache_poison_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

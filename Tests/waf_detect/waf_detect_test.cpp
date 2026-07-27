// Regression corpus for the WAF/CDN/LB detection probe's pure matcher (no
// network). The detection logic is passive (info-only) but its 45-row signature
// table, strongest-first dedup-by-name, and cookie-NAME-only extraction were
// previously unverified -- a future edit that loosens a needle, breaks the
// dedup, or regresses the cookie parse to whole-line matching would ship
// silently. This locks down:
//   - one positive per match style: header-presence (cf-ray), header-value
//     substring (Server: cloudflare), cookie-name (BIGipServer, __cf_bm);
//   - dedup-by-name keeps the FIRST (strongest) evidence (cf-ray beats Server);
//   - cookie matching is NAME-only: a needle in a cookie VALUE/attribute does
//     NOT fire (BIGipServer / datadome / NSC_ inside a value);
//   - case-insensitivity for header names, values, and cookie names;
//   - the vendor-unique additions (AWS ELB/ALB AWSALB cookie, Signal Sciences);
//   - buildGet's CR/LF guards (host / path / carried header).
//
// Run via:  ctest -R waf_detect -V

#include "waf_detect.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::WafDetect;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using HdrList = QList<QPair<QString, QString>>;
HdrList H(std::initializer_list<QPair<QString, QString>> l) { return HdrList(l); }
const Detection *find(const QList<Detection> &ds, const char *name) {
    for (const auto &d : ds) if (d.name == QString::fromLatin1(name)) return &d;
    return nullptr;
}
int count(const QList<Detection> &ds, const char *name) {
    int n = 0;
    for (const auto &d : ds) if (d.name == QString::fromLatin1(name)) ++n;
    return n;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- positives by match style ---------------------------------------
    chk("cf-ray header presence -> Cloudflare (cdn)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"cf-ray", "8abc-DFW"}})), "Cloudflare");
              return d && d->kind == "cdn"; }());
    chk("Server: cloudflare value substring -> Cloudflare",
        find(detectFromHeaders(H({{"Server", "cloudflare"}})), "Cloudflare") != nullptr);
    chk("__cf_bm cookie -> Cloudflare",
        find(detectFromHeaders(H({{"Set-Cookie", "__cf_bm=xyz; Path=/; Secure"}})), "Cloudflare") != nullptr);
    chk("x-iinfo header -> Imperva Incapsula (waf)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"x-iinfo", "1-2-3"}})), "Imperva Incapsula");
              return d && d->kind == "waf"; }());
    chk("BIGipServer cookie NAME -> F5 BIG-IP (lb)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"Set-Cookie", "BIGipServerpool_web=12345.20480.0000; path=/"}})), "F5 BIG-IP");
              return d && d->kind == "lb"; }());
    chk("Server: AkamaiGHost -> Akamai",
        find(detectFromHeaders(H({{"Server", "AkamaiGHost"}})), "Akamai") != nullptr);
    chk("x-amz-cf-id -> AWS CloudFront",
        find(detectFromHeaders(H({{"x-amz-cf-id", "abc=="}})), "AWS CloudFront") != nullptr);

    // ---- vendor-unique additions (this tick) ----------------------------
    chk("AWSALB cookie -> AWS ELB/ALB (lb)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"Set-Cookie", "AWSALB=base64data; Expires=...; Path=/"}})), "AWS ELB/ALB");
              return d && d->kind == "lb"; }());
    chk("AWSALBCORS cookie (substring) -> AWS ELB/ALB",
        find(detectFromHeaders(H({{"Set-Cookie", "AWSALBCORS=b64; SameSite=None"}})), "AWS ELB/ALB") != nullptr);
    chk("x-sigsci-requestid header -> Signal Sciences (waf)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"x-sigsci-requestid", "0123abcd"}})), "Signal Sciences");
              return d && d->kind == "waf"; }());

    // ---- dedup-by-name keeps the FIRST (strongest) evidence -------------
    chk("cf-ray + Server: cloudflare -> single Cloudflare row",
        count(detectFromHeaders(H({{"cf-ray", "8abc"}, {"Server", "cloudflare"}})), "Cloudflare") == 1);
    chk("cf-ray wins over Server (evidence shows the header, not Server)",
        [](){ const Detection *d = find(detectFromHeaders(H({{"cf-ray", "8abc"}, {"Server", "cloudflare"}})), "Cloudflare");
              return d && d->evidence.contains("cf-ray"); }());
    chk("Incapsula via header + cookie -> single row",
        count(detectFromHeaders(H({{"x-iinfo", "1"}, {"Set-Cookie", "incap_ses_1=y"}})), "Imperva Incapsula") == 1);

    // ---- cookie matching is NAME-only (no value/attribute false-match) --
    chk("BIGipServer in a cookie VALUE does NOT fire F5",
        find(detectFromHeaders(H({{"Set-Cookie", "session=BIGipServer_lookalike; path=/"}})), "F5 BIG-IP") == nullptr);
    chk("datadome in a cookie VALUE does NOT fire DataDome",
        find(detectFromHeaders(H({{"Set-Cookie", "ref=via-datadome-blog; path=/"}})), "DataDome") == nullptr);
    chk("NSC_ as a cookie VALUE does NOT fire NetScaler",
        find(detectFromHeaders(H({{"Set-Cookie", "tracker=NSC_payload; path=/"}})), "Citrix NetScaler") == nullptr);
    chk("datadome as the cookie NAME DOES fire DataDome",
        find(detectFromHeaders(H({{"Set-Cookie", "datadome=abc; path=/"}})), "DataDome") != nullptr);

    // ---- case-insensitivity --------------------------------------------
    chk("CF-RAY (uppercase header name) -> Cloudflare",
        find(detectFromHeaders(H({{"CF-RAY", "8abc"}})), "Cloudflare") != nullptr);
    chk("Server: CLOUDFLARE (uppercase value) -> Cloudflare",
        find(detectFromHeaders(H({{"server", "CLOUDFLARE"}})), "Cloudflare") != nullptr);

    // ---- negatives: nothing fronting -> no detections ------------------
    chk("plain nginx + a generic cookie -> no detections",
        detectFromHeaders(H({{"Server", "nginx"}, {"Set-Cookie", "sid=abc; path=/"}})).isEmpty());

    // ---- buildGet: CR/LF guards ----------------------------------------
    {
        Request req; req.host = "victim.tld"; req.basePath = "/";
        chk("build: request line", buildGet(req).startsWith("GET / HTTP/1.1\r\n"));
        chk("build: Host", buildGet(req).contains("Host: victim.tld\r\n"));
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host stripped (no injected header)", !buildGet(badHost).contains("\r\nX: y\r\n"));
        Request badPath = req; badPath.basePath = "/a\r\nX: y";
        chk("build: CRLF path stripped", !buildGet(badPath).contains("\r\nX: y\r\n"));
        Request badHdr = req;
        badHdr.headers.append({QStringLiteral("X-Test"), QStringLiteral("ok\r\nInjected: 1")});
        chk("build: CRLF carried header dropped", !buildGet(badHdr).contains("Injected: 1"));

        // Carried framing/encoding headers must be dropped so the ones this body-less
        // GET forces stand alone (prior tests never carried them):
        Request aeReq = req;
        aeReq.headers.append({QStringLiteral("Accept-Encoding"), QStringLiteral("gzip, deflate, br")});
        const QByteArray ae = buildGet(aeReq);
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            ae.count("Accept-Encoding:") == 1
            && ae.contains("Accept-Encoding: identity\r\n") && !ae.contains("gzip"));
        Request cnReq = req;
        cnReq.headers.append({QStringLiteral("Connection"), QStringLiteral("keep-alive")});
        const QByteArray cn = buildGet(cnReq);
        chk("build: carried Connection dropped -> exactly one, close",
            cn.count("Connection:") == 1 && cn.contains("Connection: close\r\n") && !cn.contains("keep-alive"));
        Request frReq = req;
        frReq.headers.append({QStringLiteral("Content-Length"), QStringLiteral("100")});
        frReq.headers.append({QStringLiteral("Transfer-Encoding"), QStringLiteral("chunked")});
        const QByteArray fr = buildGet(frReq);
        chk("build: carried Content-Length/Transfer-Encoding dropped (body-less GET)",
            !fr.contains("Content-Length") && !fr.contains("Transfer-Encoding"));
    }

    std::fprintf(stderr, "waf_detect_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

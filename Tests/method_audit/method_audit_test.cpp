// Regression corpus for the HTTP method-audit probe's pure logic (no network):
//   - parseAllow: an Allow header -> a deduplicated, upper-cased method list
//     (trims whitespace, drops empties, folds case and duplicates);
//   - mergeAllow: folds a second Allow value (the 405-harvest) into an already-
//     parsed list, deduped and order-preserving, so OPTIONS-only false negatives
//     are recovered;
//   - dangerousWriteMethods / dangerousWebdavMethods: the dangerous subset;
//   - traceEchoed: requires BOTH the expected verb request-line token (TRACE by
//     default, or TRACK for the IIS alias) AND our distinctive User-Agent, so a
//     page that merely says "trace"/"track" can't trip it;
//   - buildReq's CR/LF guards on method/host/basePath/query.
//
// Run via:  ctest -R method_audit -V

#include "method_audit.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::MethodAudit;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool has(const QStringList &l, const char *s) { return l.contains(QString::fromLatin1(s)); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseAllow ====================================================
    chk("parseAllow upper-cases and trims",
        [](){ const QStringList a = parseAllow("get, Post , Put");
              return has(a, "GET") && has(a, "POST") && has(a, "PUT"); }());
    chk("parseAllow dedups case-insensitively",
        parseAllow("GET, get, GET").size() == 1);
    chk("parseAllow drops empty tokens",
        [](){ const QStringList a = parseAllow("GET,, ,POST");
              return a.size() == 2 && has(a, "GET") && has(a, "POST"); }());
    chk("parseAllow empty header -> empty list", parseAllow("").isEmpty());

    // ===== mergeAllow (405-harvest fold-in) ==============================
    chk("mergeAllow into empty -> just the harvested verbs",
        [](){ const QStringList a = mergeAllow(QStringList(), "GET, PUT, DELETE");
              return a.size() == 3 && has(a, "GET") && has(a, "PUT") && has(a, "DELETE"); }());
    chk("mergeAllow dedups across the two sources (case-folded)",
        [](){ const QStringList a = mergeAllow(parseAllow("GET, POST"), "post, DELETE");
              return a.size() == 3 && has(a, "GET") && has(a, "POST") && has(a, "DELETE"); }());
    chk("mergeAllow preserves first-seen order (existing before harvested)",
        [](){ const QStringList a = mergeAllow(parseAllow("GET, HEAD"), "PUT");
              return a.at(0) == "GET" && a.at(1) == "HEAD" && a.at(2) == "PUT"; }());
    chk("mergeAllow empty harvest -> existing unchanged",
        mergeAllow(parseAllow("GET, OPTIONS"), "").size() == 2);
    chk("mergeAllow surfaces a write verb that OPTIONS never advertised",
        [](){ const QStringList a = mergeAllow(parseAllow("GET, HEAD, OPTIONS"),
                                               "GET, HEAD, POST, PUT, DELETE");
              return !dangerousWriteMethods(a).isEmpty()
                  && has(dangerousWriteMethods(a), "PUT") && has(dangerousWriteMethods(a), "DELETE"); }());

    // ===== dangerous subsets =============================================
    {
        const QStringList allowed = parseAllow("GET, HEAD, POST, PUT, DELETE, OPTIONS");
        const QStringList w = dangerousWriteMethods(allowed);
        chk("write subset = PUT, DELETE (not GET/POST/OPTIONS)",
            has(w, "PUT") && has(w, "DELETE") && !has(w, "GET") && !has(w, "POST")
            && !has(w, "OPTIONS"));
        chk("no webdav in a plain allowed set", dangerousWebdavMethods(allowed).isEmpty());
    }
    {
        const QStringList allowed = parseAllow("OPTIONS, PROPFIND, MKCOL, LOCK, GET");
        const QStringList d = dangerousWebdavMethods(allowed);
        chk("webdav subset = PROPFIND, MKCOL, LOCK",
            has(d, "PROPFIND") && has(d, "MKCOL") && has(d, "LOCK"));
        chk("no write methods in a webdav-only set",
            dangerousWriteMethods(allowed).isEmpty());
    }
    {
        // Extended DAV/DeltaV/ACL/search/binding/CalDAV verbs are now classified.
        const QStringList allowed = parseAllow("GET, SEARCH, ACL, REPORT, BIND, VERSION-CONTROL, MKCALENDAR, MKACTIVITY");
        const QStringList d = dangerousWebdavMethods(allowed);
        chk("extended webdav verbs detected (SEARCH/ACL/REPORT/BIND/...)",
            has(d, "SEARCH") && has(d, "ACL") && has(d, "REPORT") && has(d, "BIND")
            && has(d, "VERSION-CONTROL") && has(d, "MKCALENDAR") && has(d, "MKACTIVITY"));
    }
    chk("benign GET/HEAD/POST/OPTIONS -> no dangerous methods at all",
        [](){ const QStringList a = parseAllow("GET, HEAD, POST, OPTIONS");
              return dangerousWriteMethods(a).isEmpty() && dangerousWebdavMethods(a).isEmpty(); }());

    // ===== traceEchoed ===================================================
    chk("trace echo: body starts with request line + our UA -> XST confirmed",
        traceEchoed("TRACE / HTTP/1.1\r\nHost: x\r\nUser-Agent: Nullock/method-audit\r\n\r\n"));
    chk("trace echo: leading whitespace before the request line still confirms",
        traceEchoed("\r\n  TRACE /a HTTP/1.1\r\nUser-Agent: Nullock/method-audit\r\n"));
    chk("trace: a page that merely mentions 'trace' (no UA echo) -> NOT confirmed",
        !traceEchoed("<html><body>stack trace follows: TRACE this error</body></html>"));
    chk("trace: our UA present but no TRACE request line -> NOT confirmed",
        !traceEchoed("User-Agent: Nullock/method-audit only, no method line"));
    chk("trace #8 FP fix: request quoted MID-body (logging page), not a loopback -> NOT confirmed",
        !traceEchoed("<pre>Request was: TRACE / HTTP/1.1 User-Agent: Nullock/method-audit</pre>"));
    chk("trace: gateway lower-cased the echoed UA header -> still confirmed (FN fix)",
        traceEchoed("TRACE / HTTP/1.1\r\nuser-agent: Nullock/method-audit\r\n\r\n"));

    // generalized verb token: TRACK (IIS alias) and Max-Forwards:0 (echoes TRACE)
    chk("track echo: TRACK loopback with our UA -> XST confirmed (IIS alias)",
        traceEchoed("TRACK / HTTP/1.1\r\nHost: x\r\nUser-Agent: Nullock/method-audit\r\n\r\n", "TRACK"));
    chk("track echo: verb token is case-insensitive (gateway lower-cased it)",
        traceEchoed("track /a HTTP/1.1\r\nUser-Agent: Nullock/method-audit\r\n", "TRACK"));
    chk("track vs trace: a TRACE loopback must NOT satisfy a TRACK expectation",
        !traceEchoed("TRACE / HTTP/1.1\r\nUser-Agent: Nullock/method-audit\r\n\r\n", "TRACK"));
    chk("track FP: a page mentioning 'track' without our UA -> NOT confirmed",
        !traceEchoed("<html>order tracking: TRACK your shipment here</html>", "TRACK"));
    chk("max-forwards TRACE still echoes verb TRACE -> confirmed",
        traceEchoed("TRACE / HTTP/1.1\r\nMax-Forwards: 0\r\nUser-Agent: Nullock/method-audit\r\n\r\n", "TRACE"));

    // ===== buildReq: CR/LF guard parity ==================================
    {
        Request req; req.host = "victim.tld"; req.basePath = "/";
        chk("build: request line + method", buildReq(req, "OPTIONS").startsWith("OPTIONS / HTTP/1.1\r\n"));
        chk("build: Host", buildReq(req, "OPTIONS").contains("Host: victim.tld\r\n"));
        Request bh = req; bh.host = "victim.tld\r\nEvil: 1";
        chk("build: CRLF host -> no injected header", !buildReq(bh, "OPTIONS").contains("\r\nEvil: 1"));
        Request bp = req; bp.basePath = "/a\r\nEvil: 1";
        chk("build: CRLF basePath -> no injected header", !buildReq(bp, "OPTIONS").contains("\r\nEvil: 1"));
        Request bq = req; bq.query = "a=1\r\nEvil: 1";
        chk("build: CRLF query -> no injected header", !buildReq(bq, "OPTIONS").contains("\r\nEvil: 1"));
        chk("build: CRLF method -> no injected header", !buildReq(req, "OPT\r\nEvil: 1").contains("\r\nEvil: 1"));
        Request bhe = req; bhe.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("build: CRLF carried header dropped", !buildReq(bhe, "OPTIONS").contains("Evil: 1"));
    }

    std::fprintf(stderr, "method_audit_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

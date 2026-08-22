// Regression corpus for the CSWSH WebSocket probe's pure logic (no network):
//   - expectedAccept(): the RFC 6455 proof, checked against the spec's KNOWN
//     vector (key "dGhlIHNhbXBsZSBub25jZQ==" -> "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
//     -- this is what proves a 101 came from a genuine WebSocket server;
//   - headerValue(): case-insensitive name, original-case value (the base64
//     accept must survive), a value containing a colon, a missing header;
//   - statusFromHeaderBlock(): the numeric status from the first line;
//   - buildHandshake(): the required upgrade headers, Origin present/omitted,
//     carried-header strip, and a CR/LF basePath/host aborting the build.
//
// Run via:  ctest -R ws_probe -V

#include "ws_probe.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::WsProbe;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
Request mk() { Request r; r.host = "victim.tld"; r.basePath = "/chat"; return r; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== expectedAccept: the RFC 6455 known vector =====================
    chk("RFC 6455 vector: key dGhlIHNhbXBsZSBub25jZQ== -> s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        expectedAccept("dGhlIHNhbXBsZSBub25jZQ==") == QByteArray("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    chk("expectedAccept is deterministic for a key",
        expectedAccept("AQIDBAUGBwgJCgsMDQ4PEC==") == expectedAccept("AQIDBAUGBwgJCgsMDQ4PEC=="));
    chk("a different key yields a different accept",
        expectedAccept("dGhlIHNhbXBsZSBub25jZQ==") != expectedAccept("AAAAAAAAAAAAAAAAAAAAAA=="));

    // ===== headerValue ===================================================
    {
        const QByteArray block =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
            "X-Note: a:b:c";
        chk("headerValue reads the accept (original case preserved)",
            headerValue(block, "Sec-WebSocket-Accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        chk("headerValue name is case-insensitive",
            headerValue(block, "sec-websocket-accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        chk("headerValue keeps a value that itself contains colons (colon anchored to the name)",
            headerValue(block, "X-Note") == "a:b:c");
        chk("headerValue on a missing header -> empty",
            headerValue(block, "Sec-WebSocket-Extensions").isEmpty());
        // A reflected "Sec-WebSocket-Accept:" inside a PRIOR header's VALUE must be
        // skipped: headerValue anchors to a line start ("\r\n<name>:"), so the real
        // header wins over a forged reflection. (An un-anchored matcher returns FORGED.)
        const QByteArray reflected =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "X-Reflect: Sec-WebSocket-Accept: FORGED\r\n"
            "Sec-WebSocket-Accept: REAL\r\n";
        chk("headerValue anchors to a line start (ignores a reflected value)",
            headerValue(reflected, "Sec-WebSocket-Accept") == "REAL");
    }

    // ===== statusFromHeaderBlock =========================================
    chk("status 101", statusFromHeaderBlock("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket") == 101);
    chk("status 200", statusFromHeaderBlock("HTTP/1.1 200 OK") == 200);
    chk("status 403", statusFromHeaderBlock("HTTP/1.1 403 Forbidden\r\nX: y") == 403);

    // ===== buildHandshake ================================================
    {
        const QByteArray r = buildHandshake(mk(), "https://evil.example", "AQIDBAUGBwgJCgsMDQ4PEC==");
        chk("build: GET request line with basePath", r.startsWith("GET /chat HTTP/1.1\r\n"));
        chk("build: Host", r.contains("Host: victim.tld\r\n"));
        chk("build: Upgrade: websocket", r.contains("Upgrade: websocket\r\n"));
        chk("build: Connection: Upgrade", r.contains("Connection: Upgrade\r\n"));
        chk("build: Sec-WebSocket-Key carries the key", r.contains("Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEC==\r\n"));
        chk("build: Sec-WebSocket-Version: 13", r.contains("Sec-WebSocket-Version: 13\r\n"));
        chk("build: Origin present when given", r.contains("Origin: https://evil.example\r\n"));
        chk("build: ends with the blank line", r.endsWith("\r\n\r\n"));
    }
    chk("build: empty origin -> NO Origin header (the control handshake)",
        !buildHandshake(mk(), QString(), "k==").contains("Origin:"));

    // ===== buildHandshake: carried-header handling =======================
    {
        Request r = mk();
        r.headers.append({QStringLiteral("Cookie"), QStringLiteral("session=abc")});
        chk("build: a caller Cookie is carried (authed-socket test)",
            buildHandshake(r, "https://evil.example", "k==").contains("Cookie: session=abc\r\n"));
        Request r2 = mk();
        r2.headers.append({QStringLiteral("Origin"), QStringLiteral("https://override")});
        chk("build: a caller Origin header is dropped (probe controls Origin)",
            !buildHandshake(r2, "https://evil.example", "k==").contains("Origin: https://override"));
        // The symmetric caller-Host drop (buildHandshake sets its own Host) was
        // untested though the Origin drop is. A captured/authed handshake commonly
        // carries a Host; two Host lines on an upgrade are host-header-injection /
        // smuggling. Assert exactly one, the generated victim.tld.
        Request rHost = mk();
        rHost.headers.append({QStringLiteral("Host"), QStringLiteral("attacker.tld")});
        const QByteArray hh = buildHandshake(rHost, "https://evil.example", "k==");
        chk("build: a caller Host header is dropped (exactly one Host: victim.tld)",
            !hh.contains("Host: attacker.tld") && hh.count("Host: ") == 1
            && hh.contains("Host: victim.tld\r\n"));
        Request r3 = mk();
        r3.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nInjected: 1")});
        chk("build: a CR/LF carried header is dropped",
            !buildHandshake(r3, "https://evil.example", "k==").contains("Injected: 1"));
        // Bare-LF (no CR) in a carried header value/name must ALSO be dropped -- the
        // guard checks '\r' OR '\n' per char, but only the combined "\r\n" was tested.
        Request r4 = mk();
        r4.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\nInjected: 1")});
        chk("build: a bare-LF carried header VALUE is dropped",
            !buildHandshake(r4, "https://evil.example", "k==").contains("Injected: 1"));
        Request r5 = mk();
        r5.headers.append({QStringLiteral("X-T\nInjected"), QStringLiteral("1")});
        chk("build: a bare-LF carried header NAME is dropped",
            !buildHandshake(r5, "https://evil.example", "k==").contains("\nInjected"));
    }

    // ===== hasCredential (gates confirmed-CSWSH vs lead) ================
    {
        using HL = QList<QPair<QString, QString>>;
        chk("hasCredential: Cookie present", hasCredential(HL{{"Cookie", "s=1"}}));
        chk("hasCredential: Authorization present", hasCredential(HL{{"authorization", "Bearer x"}}));
        chk("hasCredential: case-insensitive name", hasCredential(HL{{"COOKIE", "s=1"}}));
        chk("hasCredential: none -> false", !hasCredential(HL{{"X-Other", "v"}, {"Accept", "*/*"}}));
        chk("hasCredential: empty -> false", !hasCredential(HL{}));
    }

    // ===== buildHandshake: CR/LF in basePath/host ABORTS =================
    {
        Request bp = mk(); bp.basePath = "/a\r\nInjected: 1";
        chk("build: CR/LF basePath -> aborts (empty)", buildHandshake(bp, "https://evil.example", "k==").isEmpty());
        // Bare-LF (no CR) must abort too -- the guard is per-character, but only the
        // combined "\r\n" form was tested for the request line.
        Request bpLf = mk(); bpLf.basePath = "/a\nInjected: 1";
        chk("build: bare-LF basePath -> aborts (empty)", buildHandshake(bpLf, "https://evil.example", "k==").isEmpty());
        Request bhLf = mk(); bhLf.host = "victim.tld\nInjected: 1";
        chk("build: bare-LF host -> aborts (empty)", buildHandshake(bhLf, "https://evil.example", "k==").isEmpty());
        Request bh = mk(); bh.host = "victim.tld\r\nInjected: 1";
        chk("build: CR/LF host -> aborts (empty)", buildHandshake(bh, "https://evil.example", "k==").isEmpty());
    }

    // ===== originVariants (the allow-list bypass sweep, FN fix) ==========
    {
        const QStringList v = originVariants("victim.tld");
        chk("originVariants: non-empty for a real host", !v.isEmpty());
        // endsWith(host) bug: a subdomain whose host ends with the target slips by.
        chk("originVariants: a subdomain ends with the target host (endsWith bypass)",
            v.contains("https://attacker-cswsh.victim.tld"));
        // endsWith without a dot anchor: a sibling label "evilvictim.tld".
        chk("originVariants: a no-dot sibling ends with the target host (missing dot anchor)",
            v.contains("https://evilvictim.tld"));
        // startsWith(host) bug: the target as the left-most label.
        chk("originVariants: target as the left-most label (startsWith bypass)",
            v.contains("https://victim.tld.attacker-cswsh.test"));
        // contains(host) bug: the target embedded in the middle.
        chk("originVariants: target embedded in the middle (contains bypass)",
            v.contains("https://evil-victim.tld-cswsh.test"));
        chk("originVariants: empty host -> empty list", originVariants("").isEmpty());
        // The endsWith variant must NOT equal the foreign sentinel -- it has to be
        // a DIFFERENT origin or the sweep adds nothing over the single attacker test.
        chk("originVariants: distinct from the foreign sentinel",
            !v.contains("https://nullock-cswsh.test"));
    }

    // ===== stripCredentials (the authed-baseline confirm, FP fix) =======
    {
        using HL = QList<QPair<QString, QString>>;
        HL h{{"Cookie", "session=abc"}, {"X-Trace", "1"}, {"Authorization", "Bearer x"}, {"Accept", "*/*"}};
        const HL s = stripCredentials(h);
        bool hasCookie = false, hasAuth = false, hasTrace = false, hasAccept = false;
        for (const auto &p : s) {
            if (p.first.compare("Cookie", Qt::CaseInsensitive) == 0) hasCookie = true;
            if (p.first.compare("Authorization", Qt::CaseInsensitive) == 0) hasAuth = true;
            if (p.first == "X-Trace") hasTrace = true;
            if (p.first == "Accept") hasAccept = true;
        }
        chk("stripCredentials: drops Cookie", !hasCookie);
        chk("stripCredentials: drops Authorization", !hasAuth);
        chk("stripCredentials: keeps non-credential headers (X-Trace)", hasTrace);
        chk("stripCredentials: keeps non-credential headers (Accept)", hasAccept);
        chk("stripCredentials: a credential-free list is unchanged in size",
            stripCredentials(HL{{"Accept", "*/*"}}).size() == 1);
        chk("stripCredentials: after strip, hasCredential() is false",
            !hasCredential(stripCredentials(h)));
        chk("stripCredentials: case-insensitive (COOKIE dropped)",
            stripCredentials(HL{{"COOKIE", "s=1"}}).isEmpty());
    }

    // ===== schemePortVariants (scheme/port-confusion bypass) ============
    {
        const QStringList v = schemePortVariants("victim.tld", /*tls=*/true, 8443);
        chk("scheme/port: a cleartext-scheme downgrade is tried (http:// on a wss target)",
            v.contains("http://victim.tld"));
        chk("scheme/port: a non-canonical port variant is tried",
            v.contains("https://victim.tld:1337"));
        chk("scheme/port: an FQDN trailing-dot host variant is tried",
            v.contains("https://victim.tld."));
        // An upper-cased host is NOT emitted: browsers lower-case the host when
        // serializing Origin, so accepting it is correct case-folding, not a bypass
        // (this would mis-grade as a confirmed hijack -- a verified false positive).
        chk("scheme/port: NO upper-cased-host variant (would be a false positive)",
            !v.contains("https://VICTIM.TLD"));
        chk("scheme/port: empty host -> empty", schemePortVariants("", true, 443).isEmpty());
        // A ws (non-tls) target is already cleartext, so no bare-host "http://<host>"
        // downgrade variant is emitted (it would duplicate the scheme itself).
        chk("scheme/port: a ws (non-tls) target on :80 emits no bare http downgrade",
            !schemePortVariants("victim.tld", false, 80).contains("http://victim.tld"));
        // A non-canonical TARGET port (e.g. wss on :8443) is itself worth trying as a
        // bare host (no explicit port) against an allow-list that pinned the port.
        chk("scheme/port: a non-standard wss port also yields a bare-host (port-stripped) variant",
            schemePortVariants("victim.tld", true, 8443).contains("https://victim.tld"));
        chk("scheme/port: a canonical wss :443 target does NOT add a redundant bare-host variant",
            schemePortVariants("victim.tld", true, 443).count("https://victim.tld") == 0);
    }

    // ===== wsConfirmsHijack: CONFIRMED-CSWSH vs LEAD verdict ============
    // The credential-stripped baseline of an already-accepted cross-origin
    // upgrade. CONFIRMED only when the baseline RESPONDED and refused; a
    // transient reconnect failure must grade a LEAD, not a hijack. This
    // decision was inline in scan()'s gradeAccepted lambda and untested.
    {
        // Genuine refusals (baseline responded, did not upgrade) -> CONFIRMED.
        chk("wsConfirmsHijack: baseline 403 (refused) -> confirmed",
            wsConfirmsHijack(/*ok*/true, 403, /*acceptValid*/false));
        chk("wsConfirmsHijack: baseline 200 non-upgrade -> confirmed",
            wsConfirmsHijack(true, 200, false));
        chk("wsConfirmsHijack: baseline 101 with INVALID accept -> confirmed (not a real upgrade)",
            wsConfirmsHijack(true, 101, false));
        // Baseline ALSO upgraded without the credential -> socket ignores the
        // session -> LEAD, not a hijack.
        chk("wsConfirmsHijack: baseline 101 + valid accept -> NOT confirmed (LEAD)",
            !wsConfirmsHijack(true, 101, true));
        // THE BUG FIX: a transient reconnect failure (no response) must NOT be
        // read as a refusal. Previously !(0==101 && ...) == true -> false hijack.
        chk("wsConfirmsHijack: transient connection failure (ok=false,status=0) -> NOT confirmed",
            !wsConfirmsHijack(false, 0, false));
        chk("wsConfirmsHijack: baseline transport fail even at a stale 403 status -> NOT confirmed",
            !wsConfirmsHijack(false, 403, false));
    }

    std::fprintf(stderr, "ws_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

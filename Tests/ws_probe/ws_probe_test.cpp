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
        Request r3 = mk();
        r3.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nInjected: 1")});
        chk("build: a CR/LF carried header is dropped",
            !buildHandshake(r3, "https://evil.example", "k==").contains("Injected: 1"));
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

    std::fprintf(stderr, "ws_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

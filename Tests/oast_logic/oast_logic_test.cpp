// Tests for OAST callback token extraction (Src/Core/APIs/Oast/oast_logic.cpp).
// Both inputs -- the Host header and the request path -- are ATTACKER-controlled
// (a target's HTTP callback hits a publicly reachable sink). The security
// contract: only an EXACT 16-lowercase-hex token is ever returned, so an
// attacker can't forge a correlation to another engagement's token.
//
// Run via:  ctest -R oast_logic -V

#include "oast_logic.hpp"

#include <QCoreApplication>
#include <QRegularExpression>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::OastLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const QString TOK = QStringLiteral("0123456789abcdef");   // canonical 16-hex token
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- subdomain form: <token>.<base-host>[:port] -----
    chk("subdomain token",             extractToken(TOK + ".oast.example.com", "/") == TOK);
    chk("subdomain token with :port",  extractToken(TOK + ".oast.example.com:8080", "/x") == TOK);
    chk("subdomain uppercase -> lc",   extractToken("0123456789ABCDEF.oast.x", "/") == TOK);
    chk("subdomain 15-hex rejected",   extractToken("0123456789abcde.oast.x", "/").isEmpty());
    chk("subdomain 17-hex rejected",   extractToken("0123456789abcdef0.oast.x", "/").isEmpty());
    chk("subdomain non-hex rejected",  extractToken("0123456789abcdeg.oast.x", "/").isEmpty());
    chk("no dot -> no subdomain token", extractToken("localhost", "/").isEmpty());
    chk("leading dot -> no token",     extractToken(".oast.x", "/").isEmpty());
    // A trailing newline after the 16 hex must be REJECTED: PCRE2's $ matches
    // before a final '\n', so ^...$ would accept "…abcdef\n" and return a 17-char,
    // LF-bearing "token" (a downstream CR/LF-injection / mis-correlation vector).
    // \A…\z rejects it. Discriminating: on the old ^…$ regex this returned the
    // newline-suffixed string, not empty.
    chk("subdomain trailing-newline rejected (exact-16 contract, \\A..\\z anchor)",
        extractToken(TOK + "\n.oast.x", "/").isEmpty());

    // ----- path form: /oast/<token>/... -----
    chk("path token",                  extractToken("evil.com", "/oast/" + TOK + "/cb") == TOK);
    chk("path token no trailing slash", extractToken("evil.com", "/oast/" + TOK) == TOK);
    chk("path 15-hex rejected",        extractToken("evil.com", "/oast/0123456789abcde/x").isEmpty());
    chk("path wrong prefix rejected",  extractToken("evil.com", "/xoast/" + TOK).isEmpty());
    chk("path empty segment rejected", extractToken("evil.com", "/oast//x").isEmpty());
    chk("path trailing-newline rejected (no LF-bearing token)",
        extractToken("evil.com", "/oast/" + TOK + "\n").isEmpty());
    chk("empty host + path -> empty",  extractToken("", "").isEmpty());

    // subdomain is checked first, so it wins even when the path also carries one.
    chk("subdomain preferred over path",
        extractToken(TOK + ".oast.x", "/oast/ffffffffffffffff/") == TOK);

    // ===== fuzz: never crash on arbitrary attacker Host/path, and NEVER return a
    // token that isn't exactly 16 lowercase-hex (a looser match would let an
    // attacker forge a correlation). Deterministic PRNG; pool biased to hex +
    // oast-relevant chars so many inputs reach the accept path. =====
    {
        uint32_t rng = 0x0a571c0du;
        auto rnd = [&rng]() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; };
        const char pool[] = "0123456789abcdefABCDEFgh.:/oast-_ \n\r";   // incl. CR/LF
        // \A..\z (not ^..$) so the checker itself doesn't share the trailing-newline
        // blind spot it is meant to catch.
        static const QRegularExpression exact16(QStringLiteral("\\A[0-9a-f]{16}\\z"));
        bool invariant = true;
        for (int it = 0; it < 8000; ++it) {
            QString host, path;
            const int hn = int(rnd() % 40), pn = int(rnd() % 40);
            for (int i = 0; i < hn; ++i) host += QChar(pool[rnd() % (sizeof(pool) - 1)]);
            for (int i = 0; i < pn; ++i) path += QChar(pool[rnd() % (sizeof(pool) - 1)]);
            const QString t = extractToken(host, path);   // must not crash
            if (!t.isEmpty() && !exact16.match(t).hasMatch()) invariant = false;
        }
        chk("fuzz: extractToken survived 8k random host/path (no crash)", true);
        chk("fuzz: any returned token is exactly 16 lowercase-hex", invariant);
    }

    std::fprintf(stderr, "oast_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

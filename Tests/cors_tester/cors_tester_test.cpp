// Regression corpus for the active CORS tester's pure logic (no network):
//   - registrableDomain: the best-effort eTLD+1 heuristic that drives the
//     attacker-owned suffix probe (the part that must NOT mis-derive a
//     multi-label TLD, and must refuse IPs / single-label hosts).
//   - originSpecs: the (origin, label) battery -- the suffix-domain and
//     trailing-dot probes the soundness audit added, and the absence of a
//     suffix probe for hosts with no registrable domain.
//   - buildRequest: CR/LF guards on every attacker-influenceable field, matching
//     the jwt_probe hardening pattern.
//
// Run via:  ctest -R cors_tester -V

#include "cors_tester.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::CorsTester;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// Is there a probe with this label, and (optionally) this exact origin?
bool hasLabel(const QList<QPair<QString, QString>> &specs, const QString &label) {
    for (const auto &s : specs) if (s.second == label) return true;
    return false;
}
QString originForLabel(const QList<QPair<QString, QString>> &specs, const QString &label) {
    for (const auto &s : specs) if (s.second == label) return s.first;
    return {};
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- registrableDomain: the eTLD+1 heuristic ----------------------
    chk("reg: api.target.com -> target.com",     registrableDomain("api.target.com") == "target.com");
    chk("reg: target.com -> target.com",         registrableDomain("target.com") == "target.com");
    chk("reg: a.b.example.com -> example.com",   registrableDomain("a.b.example.com") == "example.com");
    chk("reg: case-folded",                      registrableDomain("API.Target.COM") == "target.com");
    // Multi-label public suffix: the verifier's correction -- must NOT collapse
    // to co.uk (which would emit a useless https://attacker-co.uk probe).
    chk("reg: api.target.co.uk -> target.co.uk", registrableDomain("api.target.co.uk") == "target.co.uk");
    chk("reg: shop.example.com.au -> example.com.au",
        registrableDomain("shop.example.com.au") == "example.com.au");
    chk("reg: bare co.uk -> co.uk (no eTLD+1)",  registrableDomain("co.uk") == "co.uk");
    // No registrable domain to attack: IPs, single-label, empty.
    chk("reg: IPv4 -> empty",                    registrableDomain("127.0.0.1").isEmpty());
    chk("reg: IPv4 public -> empty",             registrableDomain("203.0.113.7").isEmpty());
    chk("reg: IPv6 -> empty",                    registrableDomain("::1").isEmpty());
    chk("reg: host:port -> empty",               registrableDomain("target.com:8443").isEmpty());
    chk("reg: localhost -> empty",               registrableDomain("localhost").isEmpty());
    chk("reg: empty -> empty",                   registrableDomain("").isEmpty());

    // ---- originSpecs: the battery the audit hardened -------------------
    {
        const auto specs = originSpecs("api.target.com", true);
        chk("specs: has arbitrary",        hasLabel(specs, "arbitrary"));
        chk("specs: has null",             hasLabel(specs, "null"));
        chk("specs: has subdomain-suffix", hasLabel(specs, "subdomain-suffix"));
        chk("specs: has scheme-swap",      hasLabel(specs, "scheme-swap"));
        // The endsWith bypass probe: attacker-OWNED domain ending in the
        // registrable domain, hyphen-joined so it is NOT a subdomain.
        chk("specs: suffix-domain present", hasLabel(specs, "suffix-domain"));
        chk("specs: suffix-domain origin",
            originForLabel(specs, "suffix-domain") == "https://attacker-target.com");
        // ...and it must end with "target.com" but NOT ".target.com" (so it
        // trips a bare endsWith but a correct dot-anchored check rejects it).
        {
            const QString o = originForLabel(specs, "suffix-domain");
            chk("specs: suffix endsWith bare reg",  o.endsWith("target.com"));
            chk("specs: suffix !endsWith .reg",     !o.endsWith(".target.com"));
        }
        // The trailing-dot (FQDN root) probe.
        chk("specs: trailing-dot present", hasLabel(specs, "trailing-dot"));
        chk("specs: trailing-dot origin",
            originForLabel(specs, "trailing-dot") == "https://attacker.example.");
        // scheme-swap flips https->http for a TLS target.
        chk("specs: scheme-swap is http",
            originForLabel(specs, "scheme-swap") == "http://api.target.com");
    }
    {
        // Multi-label TLD: the suffix probe must target the real eTLD+1.
        const auto specs = originSpecs("api.target.co.uk", true);
        chk("specs(co.uk): suffix origin",
            originForLabel(specs, "suffix-domain") == "https://attacker-target.co.uk");
    }
    {
        // An IP target has no registrable domain -> NO suffix-domain probe (it
        // would only be noise), but the rest of the battery still fires.
        const auto specs = originSpecs("127.0.0.1", false);
        chk("specs(IP): no suffix-domain", !hasLabel(specs, "suffix-domain"));
        chk("specs(IP): still has arbitrary", hasLabel(specs, "arbitrary"));
        chk("specs(IP): scheme-swap is https",
            originForLabel(specs, "scheme-swap") == "https://127.0.0.1");
    }

    // ---- classifyCorsProbe: the verdict logic (was untested) -----------
    // The core mapping from a probe outcome to a finding {severity, kind} lived
    // inside the network test() with no coverage. Args: label, reflected,
    // credentials, wildcard.
    {
        auto cls = [](const char *label, bool r, bool c, bool w) {
            return classifyCorsProbe(QString::fromLatin1(label), r, c, w);
        };
        // reflected + credentials from an attacker origin = the critical case.
        chk("verdict: arbitrary reflected+creds -> critical cors-reflected-credentialed",
            cls("arbitrary", true, true, false).kind == "cors-reflected-credentialed"
            && cls("arbitrary", true, true, false).severity == "critical");
        // reflected without credentials -> high arbitrary-origin.
        chk("verdict: arbitrary reflected no-creds -> high cors-arbitrary-origin",
            cls("arbitrary", true, false, false).kind == "cors-arbitrary-origin"
            && cls("arbitrary", true, false, false).severity == "high");
        // null origin reflected -> medium null-origin (lower than arbitrary).
        chk("verdict: null reflected -> medium cors-null-origin",
            cls("null", true, false, false).kind == "cors-null-origin"
            && cls("null", true, false, false).severity == "medium");
        // scheme-swap reflected is only a network-position issue -> low.
        chk("verdict: scheme-swap reflected -> low cors-scheme-downgrade",
            cls("scheme-swap", true, true, false).kind == "cors-scheme-downgrade"
            && cls("scheme-swap", true, true, false).severity == "low");
        // trailing-dot normalization: medium with creds, low without.
        chk("verdict: trailing-dot reflected+creds -> medium cors-origin-normalization",
            cls("trailing-dot", true, true, false).kind == "cors-origin-normalization"
            && cls("trailing-dot", true, true, false).severity == "medium");
        chk("verdict: trailing-dot reflected no-creds -> low",
            cls("trailing-dot", true, false, false).severity == "low");
        // wildcard + credentials (not reflected) -> medium wildcard-credentials.
        chk("verdict: wildcard+creds not-reflected -> medium cors-wildcard-credentials",
            cls("arbitrary", false, true, true).kind == "cors-wildcard-credentials"
            && cls("arbitrary", false, true, true).severity == "medium");
        // NEGATIVES: not reflected + no dangerous wildcard combo -> no finding.
        chk("verdict: not reflected, no wildcard -> clean (empty)",
            cls("arbitrary", false, false, false).kind.isEmpty()
            && cls("arbitrary", false, false, false).severity.isEmpty());
        chk("verdict: scheme-swap not reflected -> clean",
            cls("scheme-swap", false, true, false).kind.isEmpty());
        // wildcard alone (no credentials) is not this detector's finding.
        chk("verdict: wildcard without creds -> clean here",
            cls("arbitrary", false, false, true).kind.isEmpty());
        // Precedence: reflected+creds outranks a co-present wildcard.
        chk("verdict: reflected+creds beats wildcard -> critical",
            cls("arbitrary", true, true, true).kind == "cors-reflected-credentialed");
    }

    // ---- buildRequest: CR/LF guards (jwt_probe parity) ----------------
    {
        Request req;
        req.host = "victim.tld";
        req.method = "GET";
        req.basePath = "/api/data";

        // Clean build contains the origin + Host and a terminating blank line.
        const QByteArray ok = buildRequest(req, "https://attacker.example");
        chk("build: emits request line", ok.startsWith("GET /api/data HTTP/1.1\r\n"));
        chk("build: emits Origin",       ok.contains("Origin: https://attacker.example\r\n"));
        chk("build: emits Host",         ok.contains("Host: victim.tld\r\n"));

        // A header carrying CR/LF is DROPPED, not written (no smuggled header).
        Request inj = req;
        inj.headers.append(qMakePair(QString("X-Foo"), QString("bar\r\nX-Smuggled: 1")));
        const QByteArray h = buildRequest(inj, "https://attacker.example");
        chk("build: drops CRLF header value", !h.contains("X-Smuggled"));
        chk("build: still well-formed",       h.endsWith("\r\n\r\n"));

        // A header NAME with CR/LF is likewise dropped.
        Request injName = req;
        injName.headers.append(qMakePair(QString("X-Bad\r\nEvil"), QString("1")));
        const QByteArray hn = buildRequest(injName, "https://attacker.example");
        chk("build: drops CRLF header name", !hn.contains("Evil"));

        // A tainted CORE field (method / host / path / origin) ABORTS the build.
        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "https://attacker.example").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty",   buildRequest(badHost, "https://attacker.example").isEmpty());
        Request badPath = req; badPath.basePath = "/a\r\nX: y";
        chk("build: CRLF path -> empty",   buildRequest(badPath, "https://attacker.example").isEmpty());
        chk("build: CRLF origin -> empty", buildRequest(req, "https://e\r\nX: y").isEmpty());
    }

    // ---- reflection derivation (was inline in the excluded test()) -----
    // How `reflected` / `wildcard` / `credentials` -- the inputs to the tested
    // classifyCorsProbe -- are actually derived from the response headers.
    {
        // corsNormalizeOrigin: case-fold + strip trailing slash, keep trailing dot.
        chk("normOrigin: lowercases", corsNormalizeOrigin("HTTPS://ATTACKER.EXAMPLE") == "https://attacker.example");
        chk("normOrigin: strips a trailing slash", corsNormalizeOrigin("https://attacker.example/") == "https://attacker.example");
        chk("normOrigin: trims surrounding space", corsNormalizeOrigin("  https://attacker.example  ") == "https://attacker.example");
        chk("normOrigin: KEEPS a trailing dot (distinct from the un-dotted form)",
            corsNormalizeOrigin("https://attacker.example.") == "https://attacker.example.");

        const QString origin = "https://attacker.example";
        // Straight reflection.
        chk("reflected: exact echo -> true", corsOriginReflected({origin}, origin));
        // Case-folded reflection still detected (no false negative).
        chk("reflected: re-cased echo -> true", corsOriginReflected({"HTTPS://ATTACKER.EXAMPLE"}, origin));
        // Trailing-slash-normalized reflection detected.
        chk("reflected: echo with trailing slash -> true", corsOriginReflected({"https://attacker.example/"}, origin));
        // Multi-value ACAO: a proxy-added second value must not hide the malicious one.
        chk("reflected: found among multiple ACAO values -> true",
            corsOriginReflected({"https://good.example", origin}, origin));
        // No reflection.
        chk("reflected: a different allowed origin -> false",
            !corsOriginReflected({"https://good.example"}, origin));
        chk("reflected: wildcard alone is not a reflection of our origin",
            !corsOriginReflected({"*"}, origin));
        // Trailing-dot bypass: a dotted sent origin reflected verbatim IS a hit,
        // but must NOT match the un-dotted form (that's the whole point of keeping the dot).
        chk("reflected: dotted origin echoed verbatim -> true",
            corsOriginReflected({"https://attacker.example."}, "https://attacker.example."));
        chk("reflected: un-dotted ACAO does NOT match a dotted sent origin",
            !corsOriginReflected({"https://attacker.example"}, "https://attacker.example."));

        chk("wildcard: '*' present -> true", corsHasWildcard({"https://good.example", "*"}));
        chk("wildcard: none -> false", !corsHasWildcard({"https://good.example"}));

        chk("credentials: 'true' -> true", corsCredentialsAllowed("true"));
        chk("credentials: 'TRUE' (case-insensitive) -> true", corsCredentialsAllowed("TRUE"));
        chk("credentials: ' true ' (trimmed) -> true", corsCredentialsAllowed(" true "));
        chk("credentials: '1' is NOT true", !corsCredentialsAllowed("1"));
        chk("credentials: empty -> false", !corsCredentialsAllowed(QString()));
    }

    std::fprintf(stderr, "cors_tester_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

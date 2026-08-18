// Unit corpus for the pure advanced scope-control logic. A scope bug is the
// worst-case failure in a pentest tool (an out-of-scope host attacked, or an
// in-scope host silently skipped), so this locks the whole adversarial-review
// matrix: OFF-parity with the legacy glob decision, compose-not-replace,
// deny-precedence across layers, port-range anchoring, host-only fail-closed,
// the all-empty-exclude blackout guard, and the ReDoS/validation caps.
//
// Run via:  ctest -R scope_logic -V

#include "scope_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Proxy::ScopeLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
AdvancedScopeRule mk(bool inc, const QString &host, int pf = 0, int pt = 0,
                     const QString &file = QString(), int proto = ProtoAny, bool en = true) {
    AdvancedScopeRule r;
    r.enabled = en; r.include = inc; r.protocol = proto;
    r.hostRegex = host; r.portFrom = pf; r.portTo = pt; r.fileRegex = file;
    return r;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== configured / has-include / has-exclude =======================
    chk("configured: empty -> false", !configured(compile({})));
    chk("configured: all-disabled -> false",
        !configured(compile({ mk(true, "a\\.com", 0, 0, {}, ProtoAny, /*en*/false) })));
    chk("configured: one enabled include -> true",
        configured(compile({ mk(true, "a\\.com") })));
    chk("configured: one enabled exclude -> true",
        configured(compile({ mk(false, "a\\.com") })));
    chk("has-include false for exclude-only",
        !hasEnabledInclude(compile({ mk(false, "a\\.com") })));

    // ===== OFF-parity: no advanced rules => legacy glob decision =========
    // urlInScope must reduce to (!globOut && globIn) when nothing is configured.
    {
        const auto none = compile({});
        chk("off-parity: globOut=1 -> out", !urlInScope(none, true, true, true, "x", 443, "/"));
        chk("off-parity: globOut=0 globIn=1 -> in", urlInScope(none, false, true, true, "x", 443, "/"));
        chk("off-parity: globOut=0 globIn=0 -> out", !urlInScope(none, false, false, true, "x", 443, "/"));
    }

    // ===== compose-not-replace: exclude-only does NOT flip to allow-all ==
    {
        // one enabled EXCLUDE for evil.com, no includes.
        const auto rules = compile({ mk(false, "evil\\.com") });
        // a host the glob layer did NOT include (globIn=false) stays OUT -- the
        // exclude-only advanced list must not widen scope to allow-all.
        chk("compose: exclude-only + glob-not-in -> still OUT",
            !urlInScope(rules, false, /*globIn*/false, true, "random.com", 443, "/"));
        // the glob-in host is still allowed (glob inclusion governs)...
        chk("compose: exclude-only + glob-in -> IN",
            urlInScope(rules, false, true, true, "good.com", 443, "/"));
        // ...unless it matches the advanced exclude.
        chk("compose: exclude matches -> OUT even if glob-in",
            !urlInScope(rules, false, true, true, "evil.com", 443, "/"));
    }

    // ===== advanced inclusion regime (>=1 enabled include) ==============
    {
        const auto rules = compile({ mk(true, "app\\.example\\.com") });
        chk("include-regime: matching include -> IN (even if globIn=false)",
            urlInScope(rules, false, false, true, "app.example.com", 443, "/x"));
        chk("include-regime: non-matching -> OUT (even if globIn=true)",
            !urlInScope(rules, false, true, true, "other.com", 443, "/x"));
    }

    // ===== deny precedence: matches BOTH include and exclude -> OUT =======
    {
        const auto rules = compile({ mk(true, "app\\.com"), mk(false, "app\\.com", 0, 0, "/admin.*") });
        chk("deny-wins: include+exclude both match -> OUT",
            !urlInScope(rules, false, true, true, "app.com", 443, "/admin/x"));
        chk("deny-wins: include matches, exclude's file does not -> IN",
            urlInScope(rules, false, true, true, "app.com", 443, "/home"));
    }

    // ===== cross-layer: glob-out beats an advanced include ==============
    {
        const auto rules = compile({ mk(true, "app\\.com") });
        chk("cross-layer: globOut beats advanced include -> OUT",
            !urlInScope(rules, /*globOut*/true, true, true, "app.com", 443, "/"));
    }

    // ===== protocol dimension ===========================================
    {
        const auto https = compile({ mk(true, "a\\.com", 0, 0, {}, ProtoHttps) });
        chk("proto: https rule vs http request -> no match (out)",
            !urlInScope(https, false, true, /*tls*/false, "a.com", 80, "/"));
        chk("proto: https rule vs https request -> IN",
            urlInScope(https, false, true, true, "a.com", 443, "/"));
        const auto any = compile({ mk(true, "a\\.com", 0, 0, {}, ProtoAny) });
        chk("proto: any matches http", urlInScope(any, false, true, false, "a.com", 80, "/"));
        chk("proto: any matches https", urlInScope(any, false, true, true, "a.com", 443, "/"));
    }

    // ===== port range anchoring (no substring leak) =====================
    chk("port: exact 443 does NOT match 8443", !portInRange(443, 0, 8443));
    chk("port: exact 443 does NOT match 4433", !portInRange(443, 0, 4433));
    chk("port: exact 80 does NOT match 8080", !portInRange(80, 0, 8080));
    chk("port: exact 443 matches 443", portInRange(443, 0, 443));
    chk("port: any (0) matches anything", portInRange(0, 0, 12345));
    chk("port: range 8000-8100 matches 8080", portInRange(8000, 8100, 8080));
    chk("port: range 8000-8100 excludes 8443", !portInRange(8000, 8100, 8443));
    {
        const auto rules = compile({ mk(true, "a\\.com", 8443) });
        chk("port-rule: include on 8443 does NOT admit 443",
            !urlInScope(rules, false, true, true, "a.com", 443, "/"));
        chk("port-rule: include on 8443 admits 8443",
            urlInScope(rules, false, true, true, "a.com", 8443, "/"));
    }

    // ===== file/path dimension ==========================================
    {
        const auto rules = compile({ mk(true, ".*", 0, 0, "/api/.*") });
        chk("file: /api/x matches", urlInScope(rules, false, true, true, "h", 443, "/api/x"));
        chk("file: /home does not match /api/.* -> OUT",
            !urlInScope(rules, false, true, true, "h", 443, "/home"));
    }

    // ===== host-only FAIL-CLOSED ========================================
    {
        // an exclude carrying a file dimension for app.com: a host-only gate can't
        // check the path, so it must BLOCK app.com (under-permit).
        const auto rules = compile({ mk(true, "app\\.com"), mk(false, "app\\.com", 0, 0, "/admin.*") });
        chk("host-only: exclude w/ path dim for the host -> BLOCKED (fail closed)",
            !hostInScope(rules, false, true, "app.com"));
        // a host with only an include and no exclude -> allowed host-only.
        chk("host-only: include-matched host, no exclude -> IN",
            hostInScope(compile({ mk(true, "safe\\.com") }), false, true, "safe.com"));
        chk("host-only: globOut still wins", !hostInScope(rules, true, true, "app.com"));
    }

    // ===== all-empty EXCLUDE dropped (no total blackout) ================
    {
        AdvancedScopeRule blank; blank.include = false;   // every dim empty
        const auto rules = compile({ blank });
        chk("blackout-guard: blank exclude is dropped (not configured)", !configured(rules));
        chk("blackout-guard: blank exclude does NOT drop everything",
            urlInScope(rules, false, true, true, "anything.com", 443, "/"));
    }
    {
        AdvancedScopeRule blankInc; blankInc.include = true;   // blank include = allow-any
        const auto rules = compile({ blankInc });
        chk("blank include kept (match-any allow)",
            urlInScope(rules, false, false, true, "anything.com", 443, "/"));
    }

    // ===== ReDoS / validation caps ======================================
    {
        AdvancedScopeRule big; big.hostRegex = QString(kMaxPatternBytes + 10, QChar('a'));
        chk("cap: oversized host regex rule is dropped", compile({ big }).isEmpty());
        AdvancedScopeRule bad; bad.hostRegex = "([unterminated";
        chk("cap: invalid regex rule is dropped", compile({ bad }).isEmpty());
        AdvancedScopeRule ok; ok.hostRegex = "good\\.com";
        chk("cap: a valid rule survives", compile({ ok }).size() == 1);
    }
    {
        QList<AdvancedScopeRule> many;
        for (int i = 0; i < kMaxRules + 50; ++i) many.append(mk(true, "h\\.com"));
        chk("cap: rule count capped at kMaxRules", compile(many).size() == kMaxRules);
    }

    // ===== JSON round-trip ==============================================
    {
        QList<AdvancedScopeRule> in = { mk(false, "x\\.com", 8000, 8100, "/a.*", ProtoHttps) };
        const auto rt = rulesFromJson(rulesToJson(in));
        chk("json: round-trips a rule", rt.size() == 1 && rt[0].include == false
            && rt[0].hostRegex == "x\\.com" && rt[0].portFrom == 8000 && rt[0].portTo == 8100
            && rt[0].fileRegex == "/a.*" && rt[0].protocol == ProtoHttps);
    }

    std::fprintf(stderr, "scope_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

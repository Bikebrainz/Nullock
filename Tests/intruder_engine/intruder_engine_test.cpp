// Regression corpus for the multi-mode Intruder engine (pure logic):
// the four attack types' combination generation + positional marker
// substitution. No network -- the firing lives in the control server.
//
// Run via:  ctest -R intruder_engine -V

#include "intruder_engine.hpp"

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>

using namespace Nullock::Core::IntruderEngine;

namespace {
int pass = 0, fail = 0;
QStringList failures;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; failures << label; }
}
// Render a 2-marker template with a combo, for value assertions.
QString render2(const QStringList &combo) {
    return applyPayloads(QStringLiteral("a=\xC2\xA7""d1\xC2\xA7&b=\xC2\xA7""d2\xC2\xA7"), combo);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QString tmpl2 = QStringLiteral("a=\xC2\xA7""d1\xC2\xA7&b=\xC2\xA7""d2\xC2\xA7");

    // ---- countMarkers / parseAttackType -------------------------------
    chk("countMarkers: 2", countMarkers(tmpl2) == 2);
    chk("countMarkers: 0", countMarkers(QStringLiteral("nothing here")) == 0);
    chk("parse cluster-bomb", parseAttackType("cluster-bomb") == AttackType::ClusterBomb);
    chk("parse Pitchfork", parseAttackType("Pitchfork") == AttackType::Pitchfork);
    chk("parse 'battering ram'", parseAttackType("battering ram") == AttackType::BatteringRam);
    chk("parse default->sniper", parseAttackType("whatever") == AttackType::Sniper);

    // ---- Battering Ram: same payload in every position ----------------
    {
        const auto c = generateCombinations(AttackType::BatteringRam, 2, { { "x", "y" } });
        chk("battering: 2 requests", c.size() == 2);
        chk("battering: req0 = x in both", render2(c.value(0)) == "a=x&b=x");
        chk("battering: req1 = y in both", render2(c.value(1)) == "a=y&b=y");
    }

    // ---- Sniper: one position at a time, others default ---------------
    {
        const auto c = generateCombinations(AttackType::Sniper, 2, { { "x", "y" } });
        chk("sniper: 4 requests (2 positions x 2 payloads)", c.size() == 4);
        chk("sniper: pos0=x, pos1=default", render2(c.value(0)) == "a=x&b=d2");
        chk("sniper: pos0=y, pos1=default", render2(c.value(1)) == "a=y&b=d2");
        chk("sniper: pos0=default, pos1=x", render2(c.value(2)) == "a=d1&b=x");
        chk("sniper: pos0=default, pos1=y", render2(c.value(3)) == "a=d1&b=y");
    }

    // ---- Pitchfork: zip the per-position sets -------------------------
    {
        const auto c = generateCombinations(AttackType::Pitchfork, 2, { { "u", "v" }, { "1", "2" } });
        chk("pitchfork: 2 requests (zip)", c.size() == 2);
        chk("pitchfork: req0 = (u,1)", render2(c.value(0)) == "a=u&b=1");
        chk("pitchfork: req1 = (v,2)", render2(c.value(1)) == "a=v&b=2");
    }

    // ---- Cluster Bomb: cartesian product ------------------------------
    {
        const auto c = generateCombinations(AttackType::ClusterBomb, 2, { { "u", "v" }, { "1", "2" } });
        chk("cluster: 4 requests (2x2)", c.size() == 4);
        chk("cluster: req0 = (u,1)", render2(c.value(0)) == "a=u&b=1");
        chk("cluster: req1 = (u,2)", render2(c.value(1)) == "a=u&b=2");
        chk("cluster: req2 = (v,1)", render2(c.value(2)) == "a=v&b=1");
        chk("cluster: req3 = (v,2)", render2(c.value(3)) == "a=v&b=2");
    }

    // ---- maxResults cap bounds cluster-bomb explosion -----------------
    {
        const QStringList big = QStringList(50, "p");   // 50 x 50 = 2500 -> capped
        const auto c = generateCombinations(AttackType::ClusterBomb, 2, { big, big }, 100);
        chk("cluster: capped to maxResults", c.size() == 100);
    }

    // ---- applyPayloads: explicit values + null->default ---------------
    chk("apply: both explicit", applyPayloads(tmpl2, { "P", "Q" }) == "a=P&b=Q");
    chk("apply: null keeps default", applyPayloads(tmpl2, { QString(), "Q" }) == "a=d1&b=Q");
    chk("apply: empty string is NOT default", applyPayloads(tmpl2, { QStringLiteral(""), "Q" }) == "a=&b=Q");

    std::fprintf(stderr,
        "\n========================================\n"
        "Intruder engine regression: %d passed, %d failed\n"
        "========================================\n",
        pass, fail);
    if (fail > 0) {
        std::fprintf(stderr, "Failures:\n");
        for (const QString &f : failures)
            std::fprintf(stderr, "  - %s\n", f.toLocal8Bit().constData());
    }
    return fail == 0 ? 0 : 1;
}

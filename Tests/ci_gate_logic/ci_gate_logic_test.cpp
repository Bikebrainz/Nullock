// Tests for the CI security gate (Src/Core/Networking/ci_gate_logic.cpp). The
// gate decides whether a pipeline PASSES or FAILS given the findings and a
// fail-on threshold, and returns a process exit code. Invariants:
//   * severity ranking is correct and blank/unknown -> info (rank 0);
//   * an unknown/empty threshold defaults to "high" (never "never fail");
//   * "none"/"off" never trips even with critical findings;
//   * offending count = findings AT OR ABOVE the threshold; exit code follows.
//
// Run via:  ctest -R ci_gate_logic -V

#include "ci_gate_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::CiGate;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- severityRank / canonicalSeverity -----
    chk("rank critical > high", severityRank("critical") > severityRank("high"));
    chk("rank high > medium",   severityRank("high") > severityRank("medium"));
    chk("rank medium > low",    severityRank("medium") > severityRank("low"));
    chk("rank low > info",      severityRank("low") > severityRank("info"));
    chk("rank case-insensitive", severityRank("HIGH") == severityRank("high"));
    chk("rank blank -> info(0)", severityRank("") == 0);
    chk("rank unknown -> info(0)", severityRank("bogus") == 0);
    chk("canon blank -> info",   canonicalSeverity("") == QStringLiteral("info"));
    chk("canon trims+lowers",    canonicalSeverity("  High ") == QStringLiteral("high"));

    // ----- thresholdRank / thresholdName -----
    chk("threshold high -> 3",       thresholdRank("high") == 3);
    chk("threshold critical -> 4",   thresholdRank("critical") == 4);
    chk("threshold none -> never",   thresholdRank("none") == kNeverFail);
    chk("threshold off -> never",    thresholdRank("off") == kNeverFail);
    chk("threshold unknown -> high", thresholdRank("banana") == 3);
    chk("threshold empty -> high",   thresholdRank("") == 3);
    chk("name none stays none",      thresholdName("none") == QStringLiteral("none"));
    chk("name unknown -> high",      thresholdName("xyz") == QStringLiteral("high"));
    chk("name preserves medium",     thresholdName("MEDIUM") == QStringLiteral("medium"));
    // fail-on=info is the always-offend boundary (rank 0): the ONE threshold that
    // fails on every finding. Previously "info" was only ever a finding severity,
    // never a threshold -- a regression dropping ci_gate_logic.cpp:33 would let
    // thresholdRank("info") fall through to the default 3 and silently stop gating.
    chk("threshold info -> 0 (always-offend boundary)", thresholdRank("info") == 0);
    chk("name info stays info",      thresholdName("info") == QStringLiteral("info"));

    // ----- evaluate -----
    {
        const QList<QString> f{ "high", "low", "info", "medium" };
        const GateResult r = evaluate(f, "high");
        chk("eval fail-on high: fails",       !r.pass && r.exitCode == kExitFail);
        chk("eval fail-on high: offending=1", r.offendingCount == 1);
        chk("eval total counts all",          r.total == 4);
        chk("eval breakdown high=1",          r.bySeverity.value("high") == 1);
        chk("eval breakdown medium=1",        r.bySeverity.value("medium") == 1);
        chk("eval breakdown critical=0 seeded", r.bySeverity.value("critical") == 0);
    }
    {
        const QList<QString> f{ "high", "medium", "critical" };
        const GateResult r = evaluate(f, "high");
        chk("eval fail-on high: crit+high offend=2", r.offendingCount == 2 && !r.pass);
    }
    {
        const QList<QString> f{ "high", "medium", "low" };
        const GateResult r = evaluate(f, "critical");
        chk("eval fail-on critical: passes (no crit)", r.pass && r.exitCode == kExitPass);
        chk("eval fail-on critical: offending=0",      r.offendingCount == 0);
    }
    {
        const QList<QString> f{ "critical", "critical" };
        const GateResult r = evaluate(f, "none");
        chk("eval fail-on none: never fails even w/ crit", r.pass && r.offendingCount == 0);
        chk("eval fail-on none: threshold name 'none'",    r.threshold == QStringLiteral("none"));
    }
    {
        const GateResult r = evaluate({}, "high");
        chk("eval empty findings: passes", r.pass && r.total == 0 && r.offendingCount == 0);
    }
    {
        // blank-severity finding coalesces to info -> can't trip a high gate.
        const QList<QString> f{ "", "  ", "info" };
        const GateResult r = evaluate(f, "high");
        chk("eval blank severities -> info, gate passes", r.pass && r.bySeverity.value("info") == 3);
    }
    {
        // fail-on=info (rank 0): EVERY finding offends, down to a lone info. This
        // threshold path was never evaluated. A regression making thresholdRank
        // ("info") fall through to the default 3 would flip these to pass/exit-0.
        const GateResult r = evaluate({ "info" }, "info");
        chk("eval fail-on info: a lone info finding FAILS the gate",
            !r.pass && r.exitCode == kExitFail && r.offendingCount == 1
            && r.threshold == QStringLiteral("info") && r.thresholdRank == 0);
        const GateResult r2 = evaluate({ "low", "medium" }, "info");
        chk("eval fail-on info: low+medium both offend", r2.offendingCount == 2 && !r2.pass);
    }
    {
        // default threshold (unknown) behaves as high.
        const QList<QString> f{ "high" };
        chk("eval unknown threshold behaves as high",
            !evaluate(f, "wat").pass && evaluate(f, "wat").threshold == QStringLiteral("high"));
    }

    std::fprintf(stderr, "ci_gate_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

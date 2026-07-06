// Tests for Intruder concurrency/throttle config math
// (Src/Core/Networking/intruder_pool_logic.cpp). The load-bearing invariants
// are the CLAMPS: concurrency is always in [1, kMaxConcurrency] (never 0 -> no
// wedged dispatcher, never unbounded -> no thread/socket exhaustion), throttle
// is always in [0, kMaxThrottleMs] (never negative, never a run-parking giant),
// and rps->delay never divides by zero.
//
// Run via:  ctest -R intruder_pool_logic -V

#include "intruder_pool_logic.hpp"

#include <QCoreApplication>

#include <cstdio>
#include <limits>

using namespace Nullock::Core::IntruderPool;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- clampConcurrency: [1, kMaxConcurrency] -----
    chk("concurrency 0 -> 1",              clampConcurrency(0) == 1);
    chk("concurrency negative -> 1",       clampConcurrency(-9) == 1);
    chk("concurrency 1 -> 1",              clampConcurrency(1) == 1);
    chk("concurrency 10 -> 10",            clampConcurrency(10) == 10);
    chk("concurrency max -> max",          clampConcurrency(kMaxConcurrency) == kMaxConcurrency);
    chk("concurrency over max -> max",     clampConcurrency(kMaxConcurrency + 1) == kMaxConcurrency);
    chk("concurrency huge -> max",         clampConcurrency(1000000) == kMaxConcurrency);
    chk("concurrency int-min -> 1",        clampConcurrency(std::numeric_limits<int>::min()) == 1);
    chk("concurrency int-max -> max",      clampConcurrency(std::numeric_limits<int>::max()) == kMaxConcurrency);

    // ----- clampThrottleMs: [0, kMaxThrottleMs] -----
    chk("throttle negative -> 0",          clampThrottleMs(-1) == 0);
    chk("throttle 0 -> 0",                 clampThrottleMs(0) == 0);
    chk("throttle 500 -> 500",             clampThrottleMs(500) == 500);
    chk("throttle at ceiling",             clampThrottleMs(kMaxThrottleMs) == kMaxThrottleMs);
    chk("throttle over ceiling -> ceiling",clampThrottleMs(kMaxThrottleMs + 1) == kMaxThrottleMs);
    chk("throttle int-min -> 0",           clampThrottleMs(std::numeric_limits<int>::min()) == 0);
    chk("throttle int-max -> ceiling",     clampThrottleMs(std::numeric_limits<int>::max()) == kMaxThrottleMs);

    // ----- rpsToDelayMs: no divide-by-zero, sane spacing -----
    chk("rps 0 -> 0",                      rpsToDelayMs(0) == 0);
    chk("rps negative -> 0",               rpsToDelayMs(-5) == 0);
    chk("rps 1 -> 1000ms",                 rpsToDelayMs(1) == 1000);
    chk("rps 4 -> 250ms",                  rpsToDelayMs(4) == 250);
    chk("rps 10 -> 100ms",                 rpsToDelayMs(10) == 100);
    chk("rps 1000 -> 1ms",                 rpsToDelayMs(1000) == 1);
    chk("rps huge -> 0 (floors)",          rpsToDelayMs(std::numeric_limits<int>::max()) == 0);
    // The delay is always a valid throttle input (never needs a second clamp).
    chk("rps->delay is already clamped",   clampThrottleMs(rpsToDelayMs(3)) == rpsToDelayMs(3));

    // Sanity: defaults are inside their own bounds.
    chk("default concurrency in range",
        kDefaultConcurrency >= 1 && kDefaultConcurrency <= kMaxConcurrency);

    std::fprintf(stderr, "intruder_pool_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

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

    // ----- clampRetries: [0, kMaxRetries] -----
    chk("retries negative -> 0",           clampRetries(-1) == 0);
    chk("retries 0 -> 0",                  clampRetries(0) == 0);
    chk("retries 3 -> 3",                  clampRetries(3) == 3);
    chk("retries at ceiling",              clampRetries(kMaxRetries) == kMaxRetries);
    chk("retries over ceiling -> ceiling", clampRetries(kMaxRetries + 1) == kMaxRetries);
    chk("retries int-min -> 0",            clampRetries(std::numeric_limits<int>::min()) == 0);
    chk("retries int-max -> ceiling",      clampRetries(std::numeric_limits<int>::max()) == kMaxRetries);
    chk("default retries in range",
        kDefaultRetries >= 0 && kDefaultRetries <= kMaxRetries);

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

    // ===== audit-13: sleepSliceMs -- the interruptible-wait primitive ======
    // QThread::msleep cannot be cancelled, so the dispatcher's throttle (up to
    // kMaxThrottleMs = 60s) and each request's 429 Retry-After back-off (up to
    // 59s) ignored stop() outright. ~Intruder sets the stop flag and then WAITS on
    // the worker, so application shutdown hung for the same duration. Callers now
    // loop on this, re-checking their flag between slices.
    chk("slice: a long wait is cut to one slice", sleepSliceMs(60000) == kSleepSliceMs);
    chk("slice: the tail is the remainder, not a full slice", sleepSliceMs(20, 50) == 20);
    chk("slice: exactly one slice left", sleepSliceMs(50, 50) == 50);
    chk("slice: nothing left -> 0", sleepSliceMs(0) == 0);
    // NEVER negative: msleep takes an unsigned long, so a negative would become an
    // astronomically long wait -- the exact hang this primitive exists to prevent.
    chk("slice: negative remaining -> 0, never negative", sleepSliceMs(-1) == 0);
    chk("slice: deeply negative -> 0", sleepSliceMs(-60000) == 0);
    chk("slice: never exceeds what remains", sleepSliceMs(7, 50) <= 7);
    chk("slice: never exceeds the slice size", sleepSliceMs(60000, 50) <= 50);
    // Degenerate slice sizes fail CLOSED (0 = stop looping), never "wait forever".
    chk("slice: zero slice size -> 0",     sleepSliceMs(1000, 0) == 0);
    chk("slice: negative slice size -> 0", sleepSliceMs(1000, -5) == 0);
    // The whole point: a maximal throttle is bounded by slices, not one 60s block.
    // Walk it forward -- the loop must terminate and the total must be exact.
    {
        int remaining = kMaxThrottleMs, total = 0, slices = 0;
        while (remaining > 0 && slices < 100000) {
            const int s = sleepSliceMs(remaining);
            if (s <= 0) break;
            total += s; remaining -= s; ++slices;
        }
        chk("slice: a 60s throttle terminates", remaining == 0 && slices < 100000);
        chk("slice: the slices sum to EXACTLY the requested wait", total == kMaxThrottleMs);
        chk("slice: and it takes many slices (so a stop lands in <= one slice)",
            slices == kMaxThrottleMs / kSleepSliceMs);
        chk("slice: the granularity is small enough to feel responsive",
            kSleepSliceMs <= 100);
    }

    std::fprintf(stderr, "intruder_pool_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

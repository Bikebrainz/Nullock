#include "intruder_pool_logic.hpp"

namespace Nullock::Core::IntruderPool {

int clampConcurrency(int n) {
    if (n < 1) return 1;
    if (n > kMaxConcurrency) return kMaxConcurrency;
    return n;
}

int clampThrottleMs(int ms) {
    if (ms < 0) return 0;
    if (ms > kMaxThrottleMs) return kMaxThrottleMs;
    return ms;
}

int clampRetries(int n) {
    if (n < 0) return 0;
    if (n > kMaxRetries) return kMaxRetries;
    return n;
}

int sleepSliceMs(int remainingMs, int sliceMs) {
    if (remainingMs <= 0 || sliceMs <= 0) return 0;
    return remainingMs < sliceMs ? remainingMs : sliceMs;
}

int rpsToDelayMs(int rps) {
    if (rps <= 0) return 0;
    return 1000 / rps;
}

} // namespace Nullock::Core::IntruderPool

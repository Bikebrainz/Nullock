#pragma once

// Intruder concurrency / throttle configuration math (Burp-parity: a resource
// pool with a bounded number of concurrent requests plus an optional rate
// limit). PURE: ints in, ints out, no I/O -- links against Qt6::Core alone (in
// fact needs nothing but the standard library, but we keep it in the Core
// namespace next to the other _logic TUs).
//
// The point of pulling this out is that the clamps are the load-bearing safety:
// a caller-supplied concurrency or throttle must never let the engine spawn an
// unbounded number of threads, stall forever on a giant delay, or divide by
// zero converting a requests-per-second target into a per-dispatch delay.

namespace Nullock::Core::IntruderPool {

// Default in-flight request count when the operator hasn't chosen one. Matches
// Burp's default resource-pool size so behaviour is familiar.
constexpr int kDefaultConcurrency = 10;
// Hard ceiling on concurrent requests -- above this we're just DoSing the
// target and exhausting local sockets, not testing faster.
constexpr int kMaxConcurrency = 64;
// Ceiling on the inter-dispatch delay (60s). A throttle larger than this is
// almost certainly a mistake and would park the whole run.
constexpr int kMaxThrottleMs = 60000;

// Clamp a requested concurrency into [1, kMaxConcurrency]. Zero/negative -> 1
// (fully serial), never 0 (which would wedge a semaphore-bounded dispatcher).
int clampConcurrency(int n);

// Clamp an inter-dispatch throttle into [0, kMaxThrottleMs]. Negative -> 0.
int clampThrottleMs(int ms);

// Convert a requests-per-second target into a per-dispatch delay in ms.
//   rps <= 0      -> 0   (no throttle)
//   otherwise     -> 1000 / rps  (integer; very high rps floors to 0)
// The result is already within [0, 1000] so it needs no separate clamp.
int rpsToDelayMs(int rps);

} // namespace Nullock::Core::IntruderPool

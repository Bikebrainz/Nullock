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

// --- interruptible waiting -----------------------------------------------
// QThread::msleep CANNOT be cancelled. The dispatcher slept the full throttle
// (up to kMaxThrottleMs = 60s) between dispatches, and each in-flight request
// slept a 429 Retry-After back-off (up to 59s), with neither looking at the stop
// flag. So stop() took up to a minute to land -- and because ~Intruder sets the
// flag and then waits on the worker, APPLICATION SHUTDOWN hung for just as long.
// The dispatch loop's own comment promises a stop "lands promptly"; slicing the
// wait is what makes that true.
//
// Callers loop on this, re-checking their stop flag between slices, so no single
// blocking call outlasts a stop by more than one slice.
constexpr int kSleepSliceMs = 50;
// Length of the next slice: min(remainingMs, sliceMs). Returns 0 when there is
// nothing left to wait for, and NEVER a negative or a value exceeding what
// remains -- a negative would be cast to a huge unsigned by msleep().
int sleepSliceMs(int remainingMs, int sliceMs = kSleepSliceMs);

} // namespace Nullock::Core::IntruderPool

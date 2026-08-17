#pragma once

// Pure logic for Sequencer live-capture (see sequencer_capture.hpp for the
// QObject engine that drives the actual HttpClient loop). Split out so all the
// decision logic is unit-testable against Qt6::Core alone -- no sockets, no
// proxy types, no threads.
//
// Live-capture fires the SAME request N times and pulls one token out of each
// response, building the corpus the Sequencer's randomness analysis then scores.
// The token-extraction vocabulary is deliberately identical to ChainRunner's
// (header / cookie / json-path / regex / status) so a token you can already
// thread through a chain is one you can also harvest for randomness analysis.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::SequencerCaptureLogic {

// Where in a response the token lives. Values match ChainRunner::Extract::From so
// the wire contract ("header"/"cookie"/"json"/"regex"/"status") is shared.
enum ExtractFrom {
    FromHeader = 0,
    FromCookie = 1,
    FromJson   = 2,
    FromRegex  = 3,
    FromStatus = 4,
};

// Parse the wire string ("header"/"cookie"/"json"/"regex"/"status", any case)
// into an ExtractFrom. Unknown / empty -> FromHeader (the safe default, matching
// ChainRunner's own fallback).
ExtractFrom parseExtractFrom(const QString &s);

// Pull ONE token out of a response, mirroring ChainRunner::extractOne exactly but
// taking the decomposed pieces (so it is pure + testable without a Proxy type):
//   Header : first header value by case-insensitive name
//   Cookie : the named cookie's value from the first Set-Cookie that has it
//   Json   : dot-path into the JSON body
//   Regex  : first capture group (or whole match) over the body (capped at 1 MiB)
//   Status : the numeric status code as text
// The caller MUST pass the DECODED body (bodyForInspection()), not the raw wire
// body: a gzip/deflate response would otherwise silently yield empty tokens for
// json/regex. Unlike the session/chain path this does NOT sanitize the value: a
// Sequencer token is an analysis sample fed to the entropy tests and is never
// re-sent on the wire, so stripping bytes would corrupt the very randomness we
// measure.
QString extractToken(int from, const QString &key, int statusCode,
                     const QList<QPair<QString, QString>> &headers,
                     const QByteArray &body);

// Clamp a requested shot count into [0, maxCap]. A live-capture loop auto-issues
// this many requests, so an unbounded / negative / absurd count is a
// self-inflicted DoS on the target -- the engine always routes the requested
// count through here first. Negative -> 0, > cap -> cap, cap < 0 -> 0.
int clampCaptureCount(int requested, int maxCap);

// Clamp the per-shot pacing delay into [0, 60000] ms. Firing rapid identical
// auth-shaped requests can trip rate-limits / account lockout on the very
// session being sampled, so pacing is a real control; but an unbounded sleep
// would also let a capture hang for hours. Negative -> 0, > 60000 -> 60000.
int clampThrottleMs(int requestedMs);

// How one capture shot ended -- drives both the failure report and the
// circuit-breaker. Only ShotToken appends to the corpus.
enum ShotClass {
    ShotToken          = 0,   // a non-empty token was extracted
    ShotEmptyExtract   = 1,   // response arrived (ok-ish status) but no token matched
    ShotHttpError      = 2,   // response arrived with a non-2xx/3xx status and no token
    ShotTransportError = 3,   // the request never completed (timeout / reset / connect fail)
};

// Classify a shot. A non-empty token counts as captured on ANY status (a 302
// carrying a fresh Set-Cookie is a legitimate token source), so the status only
// discriminates the two empty-token failure modes. statusOk == [200,400).
ShotClass classifyShot(bool ok, int statusCode, bool tokenEmpty);

// True only for ShotToken -- the sole class that appends to the corpus.
bool shotYieldsToken(ShotClass c);

// Parse a Retry-After response header (delta-seconds form only) into a bounded,
// interruptible backoff in ms: clamped to [0, capMs]. Non-numeric (e.g. an
// HTTP-date), empty, or negative -> 0. Lets a 429 pace the capture without
// letting a hostile "Retry-After: 999999" stall it.
int retryAfterMs(const QString &retryAfterHeader, int capMs);

// Circuit breaker: abort the whole capture once `consecutiveFailures` reaches
// `threshold` (a run of straight 5xx / transport errors means the target is down
// or a WAF tripped -- don't burn all N shots). threshold <= 0 disables it.
bool circuitTripped(int consecutiveFailures, int threshold);

// The gate BEFORE randomness analysis is trusted. A corpus of identical tokens
// scores "maximally predictable", which an operator misreads as "the RNG is
// guessable" -- when really the extractor grabbed a constant (a static CSRF, a
// cached cookie). Distinguish that case explicitly.
enum CorpusVerdict {
    CorpusOk       = 0,   // >= 2 tokens, >= 2 distinct -> run the analysis
    CorpusNoData   = 1,   // nothing captured
    CorpusTooFew   = 2,   // 1 token -- analysis needs >= 2
    CorpusConstant = 3,   // >= 2 tokens but all identical -> NOT a rotating token
};
CorpusVerdict corpusGuard(int total, int distinct);
QString corpusVerdictMessage(CorpusVerdict v, int total, int distinct);

// An AUTOMATED harvester must refuse an EMPTY scope: ProxyServer::isInScope
// returns true when the in-scope list is empty (fine for passively logging
// browser traffic, dangerous for a loop that generates traffic -- it would mean
// "fire at anything"). Only run when the scope list is non-empty AND the host
// matches it.
bool scopeAllows(bool inScopeEmpty, bool hostInScope);

} // namespace Nullock::Core::SequencerCaptureLogic

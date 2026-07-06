#pragma once

// Intruder result grep (Burp-parity gap: "Grep - Match" / "Grep - Extract").
// After each fuzzed request lands, its response is scanned so an operator can
// flag interesting rows at a glance:
//   * grepMatch  -> a bool: did the response contain ANY of N match strings?
//   * grepExtract -> a QString pulled out of the response, either the first
//                    capture group of a regex, or the text between a start/end
//                    delimiter pair.
//
// PURE: QString in, bool/QString out, no I/O -- links against Qt6::Core alone.
//
// SAFETY (learned the hard way from the ReDoS / undecompressed-body lessons):
//   * The Intruder result callback runs on the GUI thread; a catastrophic regex
//     over a huge attacker-controlled body there would freeze the UI. We bound
//     BOTH axes: the scanned prefix is capped at kMaxScan, and every user regex
//     is validity-checked (an invalid pattern degrades to a literal search for
//     match, and to "no extraction" for extract -- never a throw, never a hang).
//     QRegularExpression additionally caps a single catastrophic match via
//     PCRE2's match_limit, so worst-case is bounded input x bounded match.
//   * Callers should feed the DECODED response (HttpResponse::bodyForInspection),
//     not raw compressed bytes, so a gzip body is actually searchable.

#include <QString>
#include <QStringList>

namespace Nullock::Core::IntruderGrep {

// How many characters of the response we ever scan. A multi-megabyte body must
// not stall the (GUI-thread) result callback -- we only look at the first
// kMaxScan chars. 256 KiB is far more than enough to spot a token or marker.
constexpr int kMaxScan = 256 * 1024;

// Spec for grep-extract. `regex` wins if non-empty (first capture group, or the
// whole match when the pattern has no capture group). Otherwise the delimiter
// pair is used: the text AFTER the first `start` and BEFORE the next `end`.
// An all-empty spec extracts nothing.
struct ExtractSpec {
    QString regex;   // regex mode: first capture group (or whole match)
    QString start;   // delimiter mode: begin after the first occurrence of this
    QString end;     // delimiter mode: stop before the next occurrence of this
};

// True if ANY needle is found in `text` (scanning bounded to kMaxScan chars).
// Each needle is tried as a REGEX first; an invalid pattern falls back to a
// literal substring search, so a plain string and a regex both "just work" and
// a malformed pattern can never crash or hang. Empty needle list, or a list of
// only-empty needles, returns false.
bool grepMatch(const QString &text, const QStringList &needles);

// Extract a value from `text` per `spec` (see ExtractSpec). Scanning is bounded
// to kMaxScan chars. Returns an empty string on no match, invalid regex, or a
// missing delimiter -- never throws.
QString grepExtract(const QString &text, const ExtractSpec &spec);

} // namespace Nullock::Core::IntruderGrep

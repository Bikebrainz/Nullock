#pragma once

// Intruder payload-processing rules (Burp-parity gap). A generated payload can
// be run through an ordered chain of transforms before it is substituted into a
// request -- e.g. url-encode then prefix "id=", or sha256 a brute value. Burp
// charges for this in Pro; ours is pure and reuses the Transcode workbench as the
// single source of truth for the encode/hash ops.
//
// PURE: QString in, QString out, no I/O -- links against Qt6::Core alone.

#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::IntruderRules {

// One processing step: an op plus an optional argument (prefix/suffix text, or
// the match-replace pair). Kept as strings so the control API can round-trip it
// straight from JSON.
struct Rule {
    QString op;
    QString arg;
};

// Apply a single rule to `value`. Encode/hash ops (base64-encode,
// base64url-encode, url-encode, hex-encode, html-encode, md5, sha1, sha256,
// sha512) delegate to Transcode::apply so there is ONE implementation. Local ops:
//   prefix        -> arg + value
//   suffix        -> value + arg
//   uppercase / lowercase / reverse
//   match-replace -> arg is "find\x1freplace" (US-delimited); replaces all
//                    literal occurrences of find with replace.
//   substring / reverse-substring -> arg is "offset" or "offset,length"; extracts
//                    a code-point-safe slice. substring counts the offset from the
//                    START (0-indexed); reverse-substring counts the end offset
//                    (and length) backwards from the END. Out-of-range -> unchanged.
//   url-encode-chars -> arg is a SET of characters; percent-encodes only those
//                    (byte-by-byte, code-point-safe), leaving the rest verbatim.
//                    This is Burp's global "URL-encode these characters" safety
//                    net; the Intruder appends it to every payload's chain when
//                    a global char-set is configured.
// An unknown op, or an encode/hash op that fails, leaves the value UNCHANGED (a
// payload run must never silently vanish).
QString applyRule(const QString &value, const Rule &rule);

// Apply an ordered chain, threading each rule's output into the next.
QString applyRules(const QString &value, const QList<Rule> &rules);

// The processing ops this engine understands (for UI discovery). Union of the
// local ops and the Transcode encode/hash ops that make sense as a payload
// transform (decode ops are intentionally excluded -- a payload is authored, not
// received).
QStringList operations();

} // namespace Nullock::Core::IntruderRules

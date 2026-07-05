#pragma once

// Transcode: the encode/decode/hash workbench behind the DECODER tab -- Nullock's
// answer to Burp's Decoder, but with smart recursive auto-decoding, hash
// identification, and full JWT decoding on top of the usual transforms.
//
// PURE: QString in, QString out, no I/O / clock / randomness, so it links against
// Qt6::Core alone and is fully unit-testable. Everything an operator does here is
// a deterministic function of (operation, input).

#include <QString>
#include <QStringList>

namespace Nullock::Core::Transcode {

struct Result {
    QString output;
    bool    ok = false;
    QString error;
};

// All direct operation ids in stable display order (for the UI + validation).
QStringList operations();

// Apply one direct operation to `input`. Unknown op -> ok=false. Decode ops that
// fail on malformed input -> ok=false with a human error; encode/hash ops always
// succeed. Ops: base64/base64url/url/html/hex encode+decode, unicode-escape +
// unescape, rot13, jwt-decode, and the md5/sha1/sha256/sha512 hashes.
Result apply(const QString &op, const QString &input);

// Auto-detect the most likely encoding of `input` and decode it, repeating until
// nothing further decodes (bounded). Each applied step is appended to *chain.
// If nothing decodes, ok=false and output == input.
Result smartDecode(const QString &input, QStringList *chain);

// Guess which hash algorithm(s) `input` could be, by length + charset (e.g.
// 32 hex -> MD5 / NTLM, 64 hex -> SHA-256, "$2b$" -> bcrypt). Empty if it does
// not look like any known hash.
QStringList identifyHash(const QString &input);

} // namespace Nullock::Core::Transcode

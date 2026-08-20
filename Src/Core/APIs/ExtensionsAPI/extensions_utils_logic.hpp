#pragma once

// Pure codec/hash primitives exposed to JavaScript extensions as nullock.utils.*
// (Burp's api.utilities() equivalent). No QObject, no engine, no I/O -- just
// QByteArray/QString/QCryptographicHash -- so this compiles against Qt6::Core
// alone and is unit-tested directly. Extensions had to re-implement base64 / hex
// / hashing by hand in ES5; these give them correct, one-call primitives.
//
// Everything is STRING-oriented: text in, text out. A string is treated as its
// UTF-8 bytes for the byte-level operations (base64/hex/hash), which is the shape
// a JS extension can actually hold (JS has no native byte type -- that gap is the
// documented remainder for a future ByteArray helper).

#include <QString>

namespace Nullock::Core::ExtUtils {

// Base64 (standard alphabet, padded). base64Decode is best-effort: invalid input
// yields whatever QByteArray::fromBase64 salvages, decoded as UTF-8.
QString base64Encode(const QString &s);
QString base64Decode(const QString &s);

// application/x-www-form-urlencoded style percent-encoding of the UTF-8 bytes.
// urlEncode encodes everything that isn't an RFC 3986 unreserved char.
QString urlEncode(const QString &s);
QString urlDecode(const QString &s);

// Lowercase hex of the UTF-8 bytes / its inverse (hexDecode ignores case and
// tolerates surrounding whitespace; odd/invalid nibbles yield what fromHex keeps).
QString hexEncode(const QString &s);
QString hexDecode(const QString &s);

// HTML-entity encode/decode of the five significant characters (& < > " ')
// plus numeric (&#NN; / &#xHH;) and the common named entities on decode. Encoding
// is the conservative set that makes a value safe to drop into HTML text/attribute.
QString htmlEncode(const QString &s);
QString htmlDecode(const QString &s);

// Lowercase hex digest of the UTF-8 bytes.
QString sha256Hex(const QString &s);
QString sha1Hex(const QString &s);
QString md5Hex(const QString &s);

} // namespace Nullock::Core::ExtUtils

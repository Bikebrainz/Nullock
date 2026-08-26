// Regression corpus for the Transcode workbench (pure encode/decode/hash logic).
// Locks round-trips, decode-failure handling, known hash vectors, JWT decoding,
// smart recursive auto-decode (incl. the hex-vs-base64 disambiguation), and hash
// identification.
//
// Run via:  ctest -R transcode -V

#include "transcode.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::Transcode;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString ap(const char *op, const QString &in) { return apply(op, in).output; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== operation registry ==========================================
    chk("operations: 26 listed", operations().size() == 26);

    // ===== base64 round-trip + failure =================================
    chk("base64 encode", ap("base64-encode", "Hello, World!") == "SGVsbG8sIFdvcmxkIQ==");
    chk("base64 decode", ap("base64-decode", "SGVsbG8sIFdvcmxkIQ==") == "Hello, World!");
    chk("base64 round-trip", ap("base64-decode", ap("base64-encode", "round \xE2\x9c\x93 trip")) == "round \xE2\x9c\x93 trip");
    chk("base64 decode invalid -> not ok", !apply("base64-decode", "not!!base64!!").ok);
    chk("base64url encode (no padding)", ap("base64url-encode", "Hello, World!") == "SGVsbG8sIFdvcmxkIQ");
    chk("base64url decode (no padding)", ap("base64url-decode", "SGVsbG8sIFdvcmxkIQ") == "Hello, World!");

    // ===== url / html / hex ============================================
    chk("url encode", ap("url-encode", "a b&c=d") == "a%20b%26c%3Dd");
    chk("url decode", ap("url-decode", "a%20b%26c%3Dd") == "a b&c=d");
    chk("html encode", ap("html-encode", "<a href=\"x\">&'") == "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    chk("html decode named", ap("html-decode", "&lt;b&gt;&amp;&quot;") == "<b>&\"");
    chk("html decode numeric dec", ap("html-decode", "&#65;&#66;") == "AB");
    chk("html decode numeric hex", ap("html-decode", "&#x41;&#x42;") == "AB");
    chk("html decode no double-decode of &amp;lt;", ap("html-decode", "&amp;lt;") == "&lt;");
    // ASTRAL (supplementary plane): a numeric entity > U+FFFF decodes via
    // QString::fromUcs4 to a surrogate PAIR (transcode.cpp:76). Every case above is
    // <= U+FFFF (line-75 branch); a truncating regression (char16_t(cp)) would emit
    // the wrong BMP char (128512 & 0xFFFF == U+8600).
    chk("html decode astral entity &#128512; -> U+1F600 (surrogate pair)",
        ap("html-decode", "&#128512;") == QString::fromUcs4(U"\U0001F600"));
    chk("html decode astral hex &#x1F600; -> U+1F600",
        ap("html-decode", "&#x1F600;") == QString::fromUcs4(U"\U0001F600"));
    // Upper-bound FAIL-CLOSED: a code point past U+10FFFF is NOT decoded -- the
    // entity stays literal (transcode.cpp:74 guard); the max valid U+10FFFF decodes.
    chk("html decode rejects > U+10FFFF (stays literal)",
        ap("html-decode", "&#1114112;") == "&#1114112;");
    chk("html decode accepts the max valid U+10FFFF",
        ap("html-decode", "&#1114111;") == QString::fromUcs4(U"\U0010FFFF"));
    // audit-4: a numeric entity must not be re-combined into a named one by a
    // second decode pass ("&#38;lt;" is '&' then literal "lt;", NOT "<").
    chk("html decode no numeric->named recombine (dec)", ap("html-decode", "&#38;lt;") == "&lt;");
    chk("html decode no numeric->named recombine (hex)", ap("html-decode", "&#x26;gt;") == "&gt;");
    chk("hex encode", ap("hex-encode", "ABC") == "414243");
    chk("hex decode", ap("hex-decode", "414243") == "ABC");
    chk("hex decode spaced", ap("hex-decode", "41 42 43") == "ABC");
    chk("hex decode odd length -> not ok", !apply("hex-decode", "abc").ok);
    chk("hex decode non-hex -> not ok", !apply("hex-decode", "zzzz").ok);

    // ===== unicode + rot13 =============================================
    chk("unicode escape non-ascii", ap("unicode-escape", "A\xE2\x9c\x93") == "A\\u2713");
    chk("unicode unescape", ap("unicode-unescape", "A\\u2713") == "A\xE2\x9c\x93");
    chk("rot13 round-trip", ap("rot13", ap("rot13", "Attack at Dawn!")) == "Attack at Dawn!");
    chk("rot13 known", ap("rot13", "Hello") == "Uryyb");

    // ===== hashes (known vectors for empty + 'abc') ====================
    chk("md5('')",    ap("md5", "")    == "d41d8cd98f00b204e9800998ecf8427e");
    chk("sha1('abc')",   ap("sha1", "abc")   == "a9993e364706816aba3e25717850c26c9cd0d89d");
    chk("sha256('abc')", ap("sha256", "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    chk("sha512('') len 128", ap("sha512", "").size() == 128);
    // Added hashes (#320).
    chk("md4('')",       ap("md4", "")       == "31d6cfe0d16ae931b73c59d7e0c089c0");
    chk("sha224('abc')", ap("sha224", "abc") == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    chk("sha384('abc')", ap("sha384", "abc") == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    chk("sha3-256('abc')", ap("sha3-256", "abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    // Octal codec (#355).
    chk("octal encode 'Hi'",   ap("octal-encode", "Hi") == "110 151");
    chk("octal round-trip",    ap("octal-decode", ap("octal-encode", "Hello \xE2\x9c\x93")) == "Hello \xE2\x9c\x93");
    chk("octal decode invalid -> not ok", !apply("octal-decode", "999").ok);
    // Binary codec (#356).
    chk("binary encode 'Hi'",  ap("binary-encode", "Hi") == "01001000 01101001");
    chk("binary round-trip",   ap("binary-decode", ap("binary-encode", "Bin \xE2\x9c\x93")) == "Bin \xE2\x9c\x93");
    chk("binary decode odd length -> not ok", !apply("binary-decode", "0101").ok);
    chk("binary decode bad digit -> not ok", !apply("binary-decode", "01010102").ok);

    // ===== jwt decode ==================================================
    {
        // {"alg":"none","typ":"JWT"} . {"sub":"admin"} .
        const QString jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";
        const Result r = apply("jwt-decode", jwt);
        chk("jwt decode ok", r.ok);
        chk("jwt shows header + payload", r.output.contains("HEADER") && r.output.contains("PAYLOAD"));
        chk("jwt surfaces alg=none warning", r.output.contains("alg=none"));
        chk("jwt decodes the sub claim", r.output.contains("admin"));
        chk("jwt not-a-jwt -> not ok", !apply("jwt-decode", "just-text").ok);
    }

    // ===== unknown op ==================================================
    chk("unknown op -> not ok", !apply("frobnicate", "x").ok);

    // ===== smart decode ================================================
    {
        QStringList chain;
        // base64 of url-encoded of "a b" -> "a%20b" -> base64 "YSUyMGI="
        const Result r = smartDecode("YSUyMGI=", &chain);
        chk("smart: base64 then url decoded", r.ok && r.output == "a b");
        chk("smart: chain records both steps", chain.size() == 2
            && chain.at(0) == "base64-decode" && chain.at(1) == "url-decode");
    }
    {
        QStringList chain;
        // pure hex must be hex-decoded, NOT mis-detected as base64
        const Result r = smartDecode("48656c6c6f", &chain);   // "Hello"
        chk("smart: pure hex -> hex-decode (not base64)", r.ok && r.output == "Hello"
            && chain.size() == 1 && chain.at(0) == "hex-decode");
    }
    {
        QStringList chain;
        const Result r = smartDecode("just plain text", &chain);
        chk("smart: plain text -> nothing detected", !r.ok && chain.isEmpty());
    }
    {
        QStringList chain;
        const QString jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.";
        const Result r = smartDecode(jwt, &chain);
        chk("smart: JWT detected + decoded", r.ok && r.output.contains("HEADER"));
    }

    // ===== hash identification =========================================
    chk("identify md5 (32 hex)", identifyHash("d41d8cd98f00b204e9800998ecf8427e").contains("MD5"));
    chk("identify sha1 (40 hex)", identifyHash(QString(40, 'a')).contains("SHA-1"));
    chk("identify sha256 (64 hex)", identifyHash(QString(64, 'a')).contains("SHA-256"));
    chk("identify sha512 (128 hex)", identifyHash(QString(128, 'a')).contains("SHA-512"));
    chk("identify bcrypt", identifyHash("$2b$12$abcdefghijklmnopqrstuv").contains("bcrypt"));
    chk("identify non-hash -> empty", identifyHash("hello world").isEmpty());

    // ===== binary-safe decode: raw octets preserved, not folded to U+FFFD ===
    // The `output` QString view folds non-UTF-8 bytes to the replacement char;
    // outputBytes holds the EXACT octets a Hex view / binary round-trip needs.
    {
        QByteArray b00ff; b00ff.append(char(0x00)); b00ff.append(char(0xFF));
        chk("hex-decode outputBytes preserves 0x00 0xFF (no U+FFFD loss)",
            apply("hex-decode", "00ff").outputBytes == b00ff);
        chk("binary-decode outputBytes preserves 0x00 0xFF",
            apply("binary-decode", "0000000011111111").outputBytes == b00ff);
        QByteArray b8081; b8081.append(char(0x80)); b8081.append(char(0x81));
        const QString b64 = QString::fromLatin1(b8081.toBase64());
        chk("base64-decode outputBytes preserves invalid-UTF-8 0x80 0x81",
            apply("base64-decode", b64).outputBytes == b8081);
        chk("octal-decode outputBytes preserves bytes",
            apply("octal-decode", "000 377").outputBytes == b00ff);
        // ASCII decode: exact bytes + a matching text view.
        chk("hex-decode ASCII: outputBytes == \"Hi\"",
            apply("hex-decode", "4869").outputBytes == QByteArray("Hi"));
        // Additive-field contract: a text-only op leaves outputBytes empty.
        chk("text op (url-encode) has empty outputBytes",
            apply("url-encode", "a b").outputBytes.isEmpty());
    }

    std::fprintf(stderr, "transcode_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

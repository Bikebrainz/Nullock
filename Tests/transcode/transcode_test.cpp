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
    chk("operations: 18 listed", operations().size() == 18);

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

    std::fprintf(stderr, "transcode_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

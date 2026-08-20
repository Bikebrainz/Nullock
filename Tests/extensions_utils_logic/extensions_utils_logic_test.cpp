// Unit tests for the pure extension-utility codecs (nullock.utils.*).
// Qt6::Core only -- extensions_utils_logic.cpp is compiled directly into this
// binary (see CMakeLists.txt), so the test self-validates its compilation.

#include "extensions_utils_logic.hpp"

#include <QCoreApplication>
#include <cstdio>

using namespace Nullock::Core::ExtUtils;

static int pass = 0, fail = 0;
static void chk(const char *label, bool ok) {
    if (ok) { ++pass; }
    else    { ++fail; std::fprintf(stderr, "  FAIL  %s\n", label); }
}
static void eq(const char *label, const QString &got, const QString &want) {
    const bool ok = got == want;
    if (!ok) std::fprintf(stderr, "  FAIL  %s: got \"%s\" want \"%s\"\n",
                          label, got.toUtf8().constData(), want.toUtf8().constData());
    ok ? ++pass : ++fail;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== base64 =====================================================
    eq("base64Encode hello",  base64Encode("hello"), "aGVsbG8=");
    eq("base64Decode hello",  base64Decode("aGVsbG8="), "hello");
    chk("base64 round-trips UTF-8", base64Decode(base64Encode(QString::fromUtf8("caf\xC3\xA9"))) == QString::fromUtf8("caf\xC3\xA9"));
    eq("base64Encode empty",  base64Encode(""), "");

    // ===== url ========================================================
    eq("urlEncode space+meta", urlEncode("a b&c=d"), "a%20b%26c%3Dd");
    eq("urlDecode",            urlDecode("a%20b%26c%3Dd"), "a b&c=d");
    chk("url round-trips",     urlDecode(urlEncode("x y/z?q=1&r=2")) == "x y/z?q=1&r=2");

    // ===== hex ========================================================
    eq("hexEncode AB",  hexEncode("AB"), "4142");
    eq("hexEncode lowercase output", hexEncode(QString(QChar(0x00FF))), "c3bf"); // U+00FF -> UTF-8 c3 bf
    eq("hexDecode",     hexDecode("4142"), "AB");
    chk("hex round-trips", hexDecode(hexEncode("Nullock")) == "Nullock");

    // ===== html =======================================================
    eq("htmlEncode all 5", htmlEncode("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    eq("htmlDecode named",  htmlDecode("&lt;a&gt;&amp;&quot;&#39;"), "<a>&\"'");
    eq("htmlDecode numeric dec", htmlDecode("&#65;&#66;"), "AB");
    eq("htmlDecode numeric hex", htmlDecode("&#x41;&#X42;"), "AB");
    eq("htmlDecode nbsp",   htmlDecode("a&nbsp;b"), QString("a") + QChar(0x00A0) + "b");
    eq("htmlDecode bare & is literal", htmlDecode("a & b"), "a & b");
    eq("htmlDecode unknown entity kept", htmlDecode("&bogus;"), "&bogus;");
    chk("html round-trips", htmlDecode(htmlEncode("<b>\"it's\" & <c>")) == "<b>\"it's\" & <c>");

    // ===== hashes (known vectors for "abc") ===========================
    eq("sha256 abc", sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    eq("sha1 abc",   sha1Hex("abc"),   "a9993e364706816aba3e25717850c26c9cd0d89d");
    eq("md5 abc",    md5Hex("abc"),    "900150983cd24fb0d6963f7d28e17f72");
    // hashes must differ from each other for the same input (guards a wrong-algo swap)
    chk("sha256 != sha1", sha256Hex("abc") != sha1Hex("abc"));

    std::fprintf(stderr, "extensions_utils_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

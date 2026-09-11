#include "networking_logic.hpp"
#include <QCoreApplication>
#include <cstdio>
using namespace Nullock::Core::NetworkingLogic;
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QByteArray body;
    for (int i = 0; i < 256; ++i) body += char(i);
    body += QByteArray(70000, 'x');
    const QByteArray original = "POST / HTTP/1.1\r\nHost: fixture.test\r\n\r\n" + body;
    bool latin1 = false;
    const QString text = decodeRequestText(original, latin1);
    if (!latin1 || encodeRequestText(text, latin1) != original) return 1;
    const QByteArray utf8 = "POST / HTTP/1.1\r\nHost: fixture.test\r\n\r\nline1\nline2\r\n" + QString::fromUtf8("日本語").toUtf8();
    const auto unicode = decodeRequestText(utf8, latin1);
    if (latin1 || encodeRequestText(unicode, latin1) != utf8) return 2;
    if (!encodeRequestText(unicode, true).isEmpty()) return 4;
    if (encodeRequestText("POST / HTTP/1.1\nHost: fixture.test\n\nbody\nline") !=
        "POST / HTTP/1.1\r\nHost: fixture.test\r\n\r\nbody\nline") return 3;
    std::puts("PASS: all 256 byte values, large body, UTF-8, header-only newline normalization");
    return 0;
}

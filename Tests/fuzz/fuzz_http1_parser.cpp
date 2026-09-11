// libFuzzer harness for the HTTP/1.x header parser + framing-safety
// check. Feeds random byte sequences as a header block and exercises
// parseHeaders + isFramingSafe.

#include "proxy_logic.hpp"

#include <QByteArray>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 64 * 1024) size = 64 * 1024;
    QByteArray buf(reinterpret_cast<const char *>(data),
                   static_cast<qsizetype>(size));
    const auto headers = Nullock::Proxy::HttpLogic::parseHeaders(buf);
    (void)Nullock::Proxy::HttpLogic::isFramingSafe(headers, true);
    (void)Nullock::Proxy::HttpLogic::isFramingSafe(headers, false);
    return 0;
}

#ifdef NULLOCK_FUZZ_STANDALONE
#include <cstdio>
int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file...>\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; ++i) {
        std::FILE *f = std::fopen(argv[i], "rb");
        if (!f) { std::perror(argv[i]); return 2; }
        std::vector<uint8_t> buf;
        uint8_t chunk[4096];
        size_t n;
        while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0)
            buf.insert(buf.end(), chunk, chunk + n);
        std::fclose(f);
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    return 0;
}
#endif

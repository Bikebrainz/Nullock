// libFuzzer harness for WsFrameParser. Feeds raw bytes into the parser
// in random chunk sizes, watches for crashes / asserts / OOM.
//
// Build (with clang-cl):
//   cmake -B build-fuzz -G Ninja -DCMAKE_C_COMPILER=clang-cl \
//                                 -DCMAKE_CXX_COMPILER=clang-cl \
//                                 -DNULLOCK_FUZZ=ON
//   cmake --build build-fuzz --target fuzz_ws_parser
//   ./build-fuzz/tests/fuzz/fuzz_ws_parser -max_total_time=120 corpus/
//
// Without libFuzzer we still build a standalone driver -- pass a file
// path as argv[1] and it'll run the corpus byte-by-byte.

#include "websocket.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Random chunk size from the first byte: 1..255. This exercises
    // the parser's partial-frame state across feed() calls -- the most
    // common source of bugs in incremental parsers.
    if (size == 0) return 0;
    const size_t chunkSize = static_cast<size_t>(data[0]) + 1;
    Nullock::Proxy::WsFrameParser p;
    size_t off = 1;
    while (off < size) {
        const size_t take = std::min(chunkSize, size - off);
        QByteArray bytes(reinterpret_cast<const char *>(data + off),
                         static_cast<qsizetype>(take));
        (void)p.feed(bytes);
        off += take;
    }
    return 0;
}

#ifdef NULLOCK_FUZZ_STANDALONE
#include <cstdio>
int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: %s <file-or-corpus-dir>\n"
                     "feeds each file's contents into the WS frame parser\n",
                     argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; ++i) {
        std::FILE *f = std::fopen(argv[i], "rb");
        if (!f) continue;
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

// libFuzzer harness for ProjectStore::importHarBytes. Walks malformed
// JSON shapes that the importer might see from a hostile HAR file.

#include "project_store.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QTemporaryDir>

#include <cstdint>
#include <cstddef>
#include <vector>

namespace {
struct FuzzCtx {
    QCoreApplication *app = nullptr;
    Nullock::Core::ProjectStore *store = nullptr;
    QTemporaryDir tmpDir;
    void init() {
        if (app) return;
        // libFuzzer hands us argc/argv via separate API; pass dummies.
        static int argc = 1;
        static char arg0[] = "fuzz";
        static char *argv[] = { arg0, nullptr };
        app = new QCoreApplication(argc, argv);
        store = new Nullock::Core::ProjectStore;
        store->open(tmpDir.path());
    }
};
FuzzCtx g_ctx;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    g_ctx.init();
    QByteArray bytes(reinterpret_cast<const char *>(data),
                     static_cast<qsizetype>(size));
    // Refuse oversize inputs (mirrors the 256MB cap importHar enforces
    // for paths -- importHarBytes itself has no cap so we apply one here
    // to keep fuzz iterations fast).
    if (bytes.size() > 8 * 1024 * 1024) bytes.truncate(8 * 1024 * 1024);
    (void)g_ctx.store->importHarBytes(bytes);
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

// Regression corpus for the pure server-side h2 translation (Phase 3): pulling
// request fields out of a browser stream's h2 headers, and building h2 response
// headers from an h1-shaped response.
//
// Run via:  ctest -R h2_server_logic -V

#include "h2_server_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Proxy::H2ServerLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool hasHdr(const QList<QPair<QString, QString>> &hs, const QString &n) {
    for (const auto &kv : hs) if (kv.first == n) return true;
    return false;
}
int nvIdx(const QList<HeaderNV> &nv, const QByteArray &n) {
    for (int i = 0; i < nv.size(); ++i) if (nv[i].name == n) return i;
    return -1;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseRequestHeaders =========================================
    {
        QList<QPair<QString, QString>> h = {
            { ":method", "POST" }, { ":scheme", "https" },
            { ":authority", "example.com" }, { ":path", "/api?q=1" },
            { "content-type", "application/json" }, { "user-agent", "curl" },
            { ":unknownpseudo", "x" },   // must be dropped, not leaked
        };
        const H2ReqFields f = parseRequestHeaders(h);
        chk("parse: method", f.method == "POST");
        chk("parse: scheme", f.scheme == "https");
        chk("parse: authority", f.authority == "example.com");
        chk("parse: path", f.path == "/api?q=1");
        chk("parse: valid (method + path present)", f.valid);
        chk("parse: regular headers kept", hasHdr(f.headers, "content-type")
                                            && hasHdr(f.headers, "user-agent"));
        chk("parse: pseudo-headers not leaked into regular",
            !hasHdr(f.headers, ":method") && !hasHdr(f.headers, ":unknownpseudo"));
        chk("parse: exactly the 2 regular headers", f.headers.size() == 2);
    }
    {
        // missing :path -> invalid
        const H2ReqFields f = parseRequestHeaders({ { ":method", "GET" } });
        chk("parse: missing :path -> invalid", !f.valid);
    }
    {
        // missing :method -> invalid
        const H2ReqFields f = parseRequestHeaders({ { ":path", "/" } });
        chk("parse: missing :method -> invalid", !f.valid);
    }

    // ===== responseHeaders =============================================
    {
        QList<QPair<QString, QString>> h = {
            { "Content-Type", "text/html" }, { "Connection", "keep-alive" },
            { "Transfer-Encoding", "chunked" }, { "Set-Cookie", "a=b" },
            { "Keep-Alive", "5" }, { "Content-Length", "908" }, { "", "empty" },
        };
        const QList<HeaderNV> nv = responseHeaders(200, h);
        chk("resp: :status is first", nv.value(0).name == ":status" && nv.value(0).value == "200");
        chk("resp: content-type kept + lowercased", nvIdx(nv, "content-type") > 0);
        chk("resp: set-cookie kept + lowercased", nvIdx(nv, "set-cookie") > 0);
        chk("resp: connection stripped", nvIdx(nv, "connection") < 0);
        chk("resp: transfer-encoding stripped", nvIdx(nv, "transfer-encoding") < 0);
        chk("resp: keep-alive stripped", nvIdx(nv, "keep-alive") < 0);
        // We re-frame the body, so content-length must be dropped (else a length
        // mismatch trips the h2 client -> STREAM_ERROR, e.g. on a favicon).
        chk("resp: content-length stripped", nvIdx(nv, "content-length") < 0);
        chk("resp: empty-name skipped -> :status + 2 kept", nv.size() == 3);
    }
    {
        const QList<HeaderNV> nv = responseHeaders(404, {});
        chk("resp: 404 status", nv.value(0).value == "404");
        chk("resp: only :status when no headers", nv.size() == 1);
    }

    std::fprintf(stderr, "h2_server_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

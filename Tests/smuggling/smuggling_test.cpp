// Regression corpus for the HTTP request-smuggling probe's pure builders (no
// network). The probe is timing-based, but its EXACT bytes are load-bearing: a
// wrong Content-Length or chunk encoding silently turns the probe inert (a
// permanent false negative that no timing logic can recover). This locks:
//   - clteProbe: CL=6 + Transfer-Encoding: chunked + body "1\r\nA\r\nX" (the
//     first 6 bytes "1\r\nA\r\n" are a complete chunk the CL front-end forwards;
//     the trailing "X" strands a TE back-end);
//   - teclProbe: CL=6 + chunked + body "0\r\n\r\nX" (a TE front-end ends at the
//     5-byte "0\r\n\r\n" terminator, a CL=6 back-end blocks for the 6th byte);
//   - ambiguousControl: CL=5 + chunked + body "0\r\n\r\n" (both parsers agree --
//     the tarpit control must NOT strand either);
//   - baselineRequest: a well-formed POST with a matching Content-Length;
//   - every probe carries Connection: close (the safety choice);
//   - a CR/LF in basePath/host ABORTS the build (returns {}).
//
// Run via:  ctest -R smuggling -V

#include "smuggling.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::Smuggling;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
Request mk() {
    Request r; r.host = "victim.tld"; r.basePath = "/"; return r;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== CL.TE probe bytes =============================================
    {
        const QByteArray p = clteProbe(mk());
        chk("clte: POST request line", p.startsWith("POST / HTTP/1.1\r\n"));
        chk("clte: Host header", p.contains("Host: victim.tld\r\n"));
        chk("clte: Content-Length is 6", p.contains("Content-Length: 6\r\n"));
        chk("clte: Transfer-Encoding: chunked", p.contains("Transfer-Encoding: chunked\r\n"));
        chk("clte: Connection: close (safety)", p.contains("Connection: close\r\n"));
        chk("clte: body is exactly '1\\r\\nA\\r\\nX' (first 6 bytes a complete chunk, trailing X stranded)",
            p.endsWith("\r\n\r\n1\r\nA\r\nX"));
    }

    // ===== TE.CL probe bytes =============================================
    {
        const QByteArray p = teclProbe(mk());
        chk("tecl: Content-Length is 6", p.contains("Content-Length: 6\r\n"));
        chk("tecl: Transfer-Encoding: chunked", p.contains("Transfer-Encoding: chunked\r\n"));
        chk("tecl: Connection: close (safety)", p.contains("Connection: close\r\n"));
        chk("tecl: body is exactly '0\\r\\n\\r\\nX' (TE ends at the 5-byte terminator, CL=6 blocks for the 6th)",
            p.endsWith("\r\n\r\n0\r\n\r\nX"));
    }

    // ===== ambiguous control bytes (must strand neither parser) ==========
    {
        const QByteArray p = ambiguousControl(mk());
        chk("control: Content-Length is 5 (matches the 5-byte terminator)", p.contains("Content-Length: 5\r\n"));
        chk("control: Transfer-Encoding: chunked", p.contains("Transfer-Encoding: chunked\r\n"));
        chk("control: Connection: close (safety)", p.contains("Connection: close\r\n"));
        chk("control: body is exactly '0\\r\\n\\r\\n' (complete, no trailing junk)",
            p.endsWith("\r\n\r\n0\r\n\r\n"));
    }

    // ===== baseline is a well-formed POST ===============================
    {
        const QByteArray p = baselineRequest(mk());
        chk("baseline: POST", p.startsWith("POST / HTTP/1.1\r\n"));
        chk("baseline: Content-Length matches body 'x=1' (3)", p.contains("Content-Length: 3\r\n"));
        chk("baseline: NO Transfer-Encoding (well-formed)", !p.contains("Transfer-Encoding"));
        chk("baseline: Connection: close (safety)", p.contains("Connection: close\r\n"));
        chk("baseline: body is 'x=1'", p.endsWith("\r\n\r\nx=1"));
    }

    // ===== carried-header CR/LF is dropped ==============================
    {
        Request r = mk();
        r.headers.append({QStringLiteral("X-T"), QStringLiteral("ok\r\nEvil: 1")});
        chk("carried header with CR/LF in value is dropped", !clteProbe(r).contains("Evil: 1"));
        // Content-Length / Transfer-Encoding from the caller are also stripped so
        // they can't fight the probe's own framing headers.
        Request r2 = mk();
        r2.headers.append({QStringLiteral("Content-Length"), QStringLiteral("999")});
        chk("caller Content-Length is dropped (probe sets its own)",
            !clteProbe(r2).contains("Content-Length: 999"));
    }

    // ===== CR/LF in basePath/host ABORTS the build ======================
    {
        Request bp = mk(); bp.basePath = "/a\r\nEvil: 1";
        chk("CRLF basePath -> clte build aborts (empty)", clteProbe(bp).isEmpty());
        chk("CRLF basePath -> tecl build aborts (empty)", teclProbe(bp).isEmpty());
        chk("CRLF basePath -> baseline build aborts (empty)", baselineRequest(bp).isEmpty());
        Request bh = mk(); bh.host = "victim.tld\r\nEvil: 1";
        chk("CRLF host -> clte build aborts (empty)", clteProbe(bh).isEmpty());
        chk("CRLF host -> control build aborts (empty)", ambiguousControl(bh).isEmpty());
    }

    std::fprintf(stderr, "smuggling_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

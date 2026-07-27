// Regression corpus for chain_runner's pure request/response-mutation helpers (no
// network). Locks the soundness fixes from the adversarial audit (15 confirmed
// findings, 4 distinct issues):
//   - sanitizeExtractedValue strips CR/LF/C0 from a TARGET-derived value before it
//     is substituted into the next on-the-wire request -- killing the header-
//     injection / request-splitting / Content-Length-desync smuggling primitive
//     (a JSON string or regex capture can legally carry \r\n);
//   - normalizeContentLength reconciles Transfer-Encoding (chunked drops CL),
//     collapses duplicate Content-Length headers, and no longer lets a bare-LF
//     request bypass normalization (all CL.TE / TE.CL / dup-CL smuggling vectors);
//   - jsonPathGet preserves exact integer text (a 64-bit id/token is not mangled
//     to scientific notation by QString::number(double));
//   - substituteStr does not re-scan an inserted value (no placeholder injection).
//
// Run via:  ctest -R chain_runner -V

#include "chain_runner.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::ChainRunner;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
int countOccur(const QByteArray &hay, const char *needle) {
    int n = 0, i = 0;
    const QByteArray nd(needle);
    while ((i = hay.indexOf(nd, i)) >= 0) { ++n; i += nd.size(); }
    return n;
}
QHash<QString, QString> vars(std::initializer_list<QPair<QString, QString>> xs) {
    QHash<QString, QString> h; for (const auto &p : xs) h.insert(p.first, p.second); return h;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== sanitizeExtractedValue: kill the CRLF injection sink =========
    chk("sanitize: CR/LF stripped (header-injection killed)",
        sanitizeExtractedValue("abc\r\nX-Admin: 1") == "abcX-Admin: 1");
    chk("sanitize: a \\r\\n\\r\\n cannot survive to split the request",
        !sanitizeExtractedValue("x\r\n\r\nGET /smuggled HTTP/1.1").contains('\r')
        && !sanitizeExtractedValue("x\r\n\r\nGET /smuggled HTTP/1.1").contains('\n'));
    chk("sanitize: a clean token is unchanged", sanitizeExtractedValue("tok_123ABC") == "tok_123ABC");
    chk("sanitize: NUL and other C0 controls dropped",
        sanitizeExtractedValue(QString("a") + QChar(0) + QString("b") + QChar(0x07) + QString("c")) == "abc");
    chk("sanitize: a tab is kept (legal header whitespace)",
        sanitizeExtractedValue("a\tb") == "a\tb");

    // ===== jsonPathGet: exact integers + paths ==========================
    chk("json: a 64-bit id is exact, NOT scientific notation",
        jsonPathGet("{\"id\":123456789012345}", "id") == "123456789012345");
    chk("json: a small int is exact", jsonPathGet("{\"n\":42}", "n") == "42");
    chk("json: a non-integer double round-trips", jsonPathGet("{\"v\":3.5}", "v") == "3.5");
    chk("json: nested object path", jsonPathGet("{\"a\":{\"b\":7}}", "a.b") == "7");
    chk("json: array index path", jsonPathGet("{\"xs\":[{\"t\":\"ok\"}]}", "xs.0.t") == "ok");
    chk("json: leading $. prefix accepted", jsonPathGet("{\"a\":1}", "$.a") == "1");
    chk("json: a bool renders true/false", jsonPathGet("{\"b\":true}", "b") == "true");
    chk("json: a missing path -> empty", jsonPathGet("{\"a\":1}", "z").isEmpty());
    chk("json: invalid JSON -> empty", jsonPathGet("not json", "a").isEmpty());
    chk("json: an out-of-range array index -> empty", jsonPathGet("{\"xs\":[1]}", "xs.5").isEmpty());

    // ===== substituteStr: {{var}} expansion, no re-scan =================
    chk("subst: a known var is expanded", substituteStr("Hi {{name}}", vars({{"name", "Bob"}})) == "Hi Bob");
    chk("subst: adjacent vars", substituteStr("{{a}}{{b}}", vars({{"a", "1"}, {"b", "2"}})) == "12");
    chk("subst: an unknown var is left untouched",
        substituteStr("x{{nope}}y", vars({{"a", "1"}})) == "x{{nope}}y");
    chk("subst: an inserted value is NOT re-scanned (no placeholder injection)",
        substituteStr("{{a}}", vars({{"a", "{{b}}"}, {"b", "X"}})) == "{{b}}");

    // ===== substituteBytes: BYTE-safe expansion (binary body preserved) ==
    // The request TEMPLATE is raw bytes -- a QString UTF-8 round trip would
    // replace a lone 0x80 (a binary body) with U+FFFD (EF BF BD) and corrupt the
    // request put on the wire. substituteBytes must preserve every non-token byte.
    {
        const QByteArray out = substituteBytes(QByteArray("A\x80" "{{tok}}B"), vars({{"tok", "Z"}}));
        chk("subBytes: a lone 0x80 binary byte survives verbatim (no corruption)",
            out == QByteArray("A\x80" "ZB"));
        chk("subBytes: no U+FFFD replacement char is introduced", !out.contains("\xEF\xBF\xBD"));
    }
    chk("subBytes: an unknown var is left untouched",
        substituteBytes(QByteArray("x{{nope}}y"), vars({{"a", "1"}})) == QByteArray("x{{nope}}y"));
    chk("subBytes: an inserted value is NOT re-scanned",
        substituteBytes(QByteArray("{{a}}"), vars({{"a", "{{b}}"}, {"b", "X"}})) == QByteArray("{{b}}"));
    chk("subBytes: a Unicode value is spliced as its UTF-8 bytes",
        substituteBytes(QByteArray("[{{v}}]"), vars({{"v", QString::fromUtf8("\xC3\xA9")}}))
            == QByteArray("[\xC3\xA9]"));
    chk("subBytes: the CRLF head/body boundary in the template is preserved",
        substituteBytes(QByteArray("POST / HTTP/1.1\r\n\r\n{{b}}"), vars({{"b", "hi"}}))
            == QByteArray("POST / HTTP/1.1\r\n\r\nhi"));

    // ===== normalizeContentLength: framing soundness ====================
    {
        const QByteArray r = normalizeContentLength("POST /x HTTP/1.1\r\nHost: h\r\n\r\nhello");
        chk("clen: a body with no CL gets one", r.contains("Content-Length: 5\r\n"));
        chk("clen: exactly one CL header", countOccur(r, "Content-Length:") == 1);
    }
    chk("clen: an existing CL is rewritten to the real body length",
        normalizeContentLength("POST /x HTTP/1.1\r\nContent-Length: 99\r\n\r\nhello").contains("Content-Length: 5\r\n"));
    {
        // TE.CL smuggling: chunked is authoritative -> Content-Length is DROPPED.
        const QByteArray r = normalizeContentLength(
            "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nx");
        chk("clen: Transfer-Encoding:chunked present -> NO Content-Length emitted (TE.CL fix)",
            !r.contains("Content-Length"));
        chk("clen: Transfer-Encoding is preserved", r.contains("Transfer-Encoding: chunked\r\n"));
    }
    {
        // Duplicate Content-Length headers collapse to exactly one (smuggling fix).
        const QByteArray r = normalizeContentLength(
            "POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 99\r\n\r\nhello");
        chk("clen: duplicate Content-Length headers collapse to ONE (dup-CL fix)",
            countOccur(r, "Content-Length:") == 1);
        chk("clen: the surviving CL is the real body length", r.contains("Content-Length: 5\r\n"));
    }
    {
        // Bare-LF framing no longer bypasses normalization (desync fix).
        const QByteArray r = normalizeContentLength("POST /x HTTP/1.1\nHost: h\n\nhello");
        chk("clen: a bare-LF request is normalized (not passed through) -> gets a CL",
            r.contains("Content-Length: 5\r\n"));
        chk("clen: the normalized output uses CRLF", r.contains("Host: h\r\n"));
    }
    // MIXED / CR-only blank lines must ALSO be found (terminator-agnostic scan).
    // A boundary that only matched "\r\n\r\n" or "\n\n" would miss these and let
    // the request bypass CL reconciliation entirely (a smuggling desync source).
    chk("clen: '\\n\\r\\n' mixed-terminator boundary is normalized (gets a CL)",
        normalizeContentLength(QByteArray("POST /x HTTP/1.1\r\nHost: h\n\r\nbody")).contains("Content-Length: 4\r\n"));
    chk("clen: '\\r\\n\\n' mixed-terminator boundary is normalized (gets a CL)",
        normalizeContentLength(QByteArray("POST /x HTTP/1.1\r\nHost: h\r\n\nbody")).contains("Content-Length: 4\r\n"));
    chk("clen: CR-only '\\r\\r' boundary is found (not passed through)",
        normalizeContentLength(QByteArray("POST /x HTTP/1.1\rHost: h\r\rbody")).contains("Content-Length: 4\r\n"));
    chk("clen: a bodyless request gets no Content-Length added",
        !normalizeContentLength("GET /x HTTP/1.1\r\nHost: h\r\n\r\n").contains("Content-Length"));
    // audit-3: a bare-CR-separated header block must be parsed line-by-line
    // (head.split('\n') folded the whole head into ONE line), or TE-chunked
    // detection and duplicate-Content-Length collapse are bypassed -> desync.
    {
        const QByteArray r = normalizeContentLength(
            "POST /x HTTP/1.1\rTransfer-Encoding: chunked\rContent-Length: 6\r\rbody");
        chk("clen: bare-CR head, TE:chunked -> Content-Length dropped (CL.TE fix)",
            !r.contains("Content-Length"));
        chk("clen: bare-CR head, Transfer-Encoding preserved",
            r.contains("Transfer-Encoding: chunked\r\n"));
    }
    {
        const QByteArray r = normalizeContentLength(
            "POST /x HTTP/1.1\rContent-Length: 5\rContent-Length: 99\r\rhello");
        chk("clen: bare-CR head, duplicate Content-Length collapses to one (dup-CL fix)",
            countOccur(r, "Content-Length:") == 1);
        chk("clen: bare-CR head, surviving CL is the real body length",
            r.contains("Content-Length: 5\r\n"));
    }

    // ===== findHeader / findCookieValue =================================
    {
        const QList<QPair<QString, QString>> h{ {"Content-Type", "json"}, {"X-Token", "abc"} };
        chk("findHeader: case-insensitive", findHeader(h, "x-token") == "abc");
        chk("findHeader: missing -> empty", findHeader(h, "nope").isEmpty());
    }
    chk("findCookie: named value", findCookieValue("a=1; sid=xyz; b=2", "sid") == "xyz");
    chk("findCookie: case-insensitive name", findCookieValue("SID=xyz", "sid") == "xyz");
    chk("findCookie: a value containing '=' is kept", findCookieValue("t=a=b=c", "t") == "a=b=c");
    chk("findCookie: missing -> empty", findCookieValue("a=1", "z").isEmpty());

    // ===== fuzz: sanitizeExtractedValue is the CRLF-injection sink -- a
    // TARGET-controlled value flows through it and is substituted into the NEXT
    // on-the-wire request. Locked invariant, on ANY input: the output never
    // carries a char below 0x20 except tab (in particular no CR/LF, which would
    // split the request / inject a header), and it never crashes. =====
    {
        uint32_t rng = 0x00c0ffeeu;
        auto rnd = [&rng]() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; };
        bool invariant = true;
        for (int it = 0; it < 8000; ++it) {
            QString v;
            const int n = int(rnd() % 60);
            for (int i = 0; i < n; ++i) {
                const uint r = rnd();
                // 1-in-4 forces a pure C0 control char; the rest span 0x00..0x7F
                // (still includes CR/LF/controls). Heavily exercises the strip.
                v += (r & 3) ? QChar(ushort(r % 0x80)) : QChar(ushort(r % 0x20));
            }
            const QString out = sanitizeExtractedValue(v);   // must not crash
            for (const QChar c : out)
                if (c.unicode() < 0x20 && c != QChar('\t')) { invariant = false; break; }
        }
        chk("fuzz: sanitizeExtractedValue survived 8k random values (no crash)", true);
        chk("fuzz: output never carries a C0 control char except tab (no CR/LF)", invariant);
    }

    std::fprintf(stderr, "chain_runner_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Unit corpus for the pure Sequencer live-capture logic. These lock every
// decision the capture engine makes so a regression can't silently break it:
//   - token extraction (MUST match ChainRunner's extractOne; MUST read decoded body)
//   - count / throttle clamps (the auto-fire DoS + pacing guards)
//   - shot classification (what appends to the corpus, what the report counts)
//   - Retry-After backoff parse + circuit breaker
//   - corpus verdict guard (constant token != predictable RNG)
//   - scope predicate (empty scope must REFUSE, not fire-at-anything)
//
// Run via:  ctest -R sequencer_capture -V

#include "sequencer_capture_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::SequencerCaptureLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
using Hdrs = QList<QPair<QString, QString>>;
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== parseExtractFrom (wire string -> enum) =======================
    chk("parse: header",  parseExtractFrom("header") == FromHeader);
    chk("parse: cookie",  parseExtractFrom("cookie") == FromCookie);
    chk("parse: json",    parseExtractFrom("json")   == FromJson);
    chk("parse: regex",   parseExtractFrom("regex")  == FromRegex);
    chk("parse: status",  parseExtractFrom("status") == FromStatus);
    chk("parse: delimiter", parseExtractFrom("delimiter") == FromDelimiter);
    chk("parse: delim alias", parseExtractFrom("delim") == FromDelimiter);
    chk("parse: case-insensitive", parseExtractFrom("COOKIE") == FromCookie);
    chk("parse: whitespace trimmed", parseExtractFrom("  json ") == FromJson);
    chk("parse: unknown -> header (default)", parseExtractFrom("nonsense") == FromHeader);
    chk("parse: empty -> header (default)", parseExtractFrom("") == FromHeader);

    // ===== extractToken: Header =========================================
    {
        const Hdrs h = { { "Content-Type", "text/html" }, { "X-Token", "abc123" } };
        chk("header: value by name", extractToken(FromHeader, "X-Token", 200, h, {}) == "abc123");
        chk("header: case-insensitive name", extractToken(FromHeader, "x-token", 200, h, {}) == "abc123");
        chk("header: a miss -> empty", extractToken(FromHeader, "X-Absent", 200, h, {}).isEmpty());
    }

    // ===== extractToken: Cookie (two-level) =============================
    {
        const Hdrs h = { { "Set-Cookie", "sid=REALTOKEN; Path=/; HttpOnly" },
                         { "Set-Cookie", "other=zzz" } };
        chk("cookie: value of named cookie", extractToken(FromCookie, "sid", 200, h, {}) == "REALTOKEN");
        chk("cookie: an ATTRIBUTE name is not a value (Path)",
            extractToken(FromCookie, "Path", 200, h, {}).isEmpty());
        chk("cookie: a second Set-Cookie's cookie is found",
            extractToken(FromCookie, "other", 200, h, {}) == "zzz");
        chk("cookie: a missing cookie -> empty", extractToken(FromCookie, "nope", 200, h, {}).isEmpty());
    }
    {
        const Hdrs h = { { "Set-Cookie", "a=1" }, { "Set-Cookie", "sid=DEEP; Secure" } };
        chk("cookie: found in a later Set-Cookie header",
            extractToken(FromCookie, "sid", 200, h, {}) == "DEEP");
    }

    // ===== extractToken: Json (over DECODED body) =======================
    chk("json: dot-path leaf",
        extractToken(FromJson, "data.token", 200, {}, "{\"data\":{\"token\":\"sk_xyz\"}}") == "sk_xyz");
    chk("json: a miss -> empty",
        extractToken(FromJson, "data.absent", 200, {}, "{\"data\":{}}").isEmpty());
    // The engine passes bodyForInspection() (decoded); prove extraction reads the
    // plain body it is handed (a gzip blob would never parse as JSON -> empty),
    // i.e. the contract is "hand me decoded bytes".
    chk("json: raw gzip-magic bytes do NOT parse (engine must pass decoded body)",
        extractToken(FromJson, "data.token", 200, {},
                     QByteArray::fromHex("1f8b08")).isEmpty());

    // ===== extractToken: Regex ==========================================
    chk("regex: first capture group",
        extractToken(FromRegex, "token=([A-Za-z0-9]+)", 200, {}, "x token=CAP99 y") == "CAP99");
    chk("regex: whole match when no group",
        extractToken(FromRegex, "[A-Z]{4}", 200, {}, "zz ABCD zz") == "ABCD");
    chk("regex: no match -> empty",
        extractToken(FromRegex, "NOPE([0-9]+)", 200, {}, "nothing here").isEmpty());
    chk("regex: invalid pattern -> empty (fail-closed, no crash)",
        extractToken(FromRegex, "([unterminated", 200, {}, "([unterminated").isEmpty());

    // ===== extractToken: Status / bad enum ==============================
    chk("status: numeric code as text", extractToken(FromStatus, "", 403, {}, {}) == "403");
    chk("extract: an out-of-range 'from' -> empty (no crash)",
        extractToken(99, "x", 200, {}, "body").isEmpty());

    // ===== cookieNameFromSetCookie (name-only extraction) ===============
    chk("cookie-name: simple pair", cookieNameFromSetCookie("sid=REALTOKEN") == "sid");
    chk("cookie-name: attributes after the first ';' ignored",
        cookieNameFromSetCookie("sid=REALTOKEN; Path=/; HttpOnly") == "sid");
    chk("cookie-name: whitespace around the name trimmed",
        cookieNameFromSetCookie("  sid  =REALTOKEN") == "sid");
    chk("cookie-name: an attribute-only value later in the string is not the name",
        cookieNameFromSetCookie("csrftoken=abc; Domain=example.com") == "csrftoken");
    chk("cookie-name: no '=' at all -> empty", cookieNameFromSetCookie("garbage").isEmpty());
    chk("cookie-name: '=' as the very first char (empty name) -> empty",
        cookieNameFromSetCookie("=novalue").isEmpty());
    chk("cookie-name: empty input -> empty", cookieNameFromSetCookie("").isEmpty());

    // ===== clampCaptureCount (DoS guard) ================================
    chk("clamp-count: within cap unchanged", clampCaptureCount(50, 500) == 50);
    chk("clamp-count: exactly at cap unchanged", clampCaptureCount(500, 500) == 500);
    chk("clamp-count: over cap -> cap", clampCaptureCount(1000000, 500) == 500);
    chk("clamp-count: negative -> 0", clampCaptureCount(-5, 500) == 0);
    chk("clamp-count: zero -> 0", clampCaptureCount(0, 500) == 0);
    chk("clamp-count: negative cap -> 0 (fail-closed)", clampCaptureCount(10, -1) == 0);

    // ===== clampThrottleMs (pacing bound) ==============================
    chk("clamp-throttle: within bound unchanged", clampThrottleMs(250) == 250);
    chk("clamp-throttle: zero stays zero", clampThrottleMs(0) == 0);
    chk("clamp-throttle: negative -> 0", clampThrottleMs(-100) == 0);
    chk("clamp-throttle: over 60000 -> 60000", clampThrottleMs(999999) == 60000);
    chk("clamp-throttle: exactly 60000 kept", clampThrottleMs(60000) == 60000);

    // ===== classifyShot + shotYieldsToken ==============================
    chk("classify: ok + token on 200 -> Token", classifyShot(true, 200, false) == ShotToken);
    chk("classify: ok + token on 302 -> Token (cookie-from-redirect)",
        classifyShot(true, 302, false) == ShotToken);
    chk("classify: ok + token on 500 -> Token (token still valid)",
        classifyShot(true, 500, false) == ShotToken);
    chk("classify: ok + empty on 200 -> EmptyExtract", classifyShot(true, 200, true) == ShotEmptyExtract);
    chk("classify: ok + empty on 500 -> HttpError", classifyShot(true, 500, true) == ShotHttpError);
    chk("classify: ok + empty on 404 -> HttpError", classifyShot(true, 404, true) == ShotHttpError);
    chk("classify: not ok -> TransportError (even with a status)", classifyShot(false, 200, true) == ShotTransportError);
    chk("yields-token: only ShotToken appends", shotYieldsToken(ShotToken)
        && !shotYieldsToken(ShotEmptyExtract) && !shotYieldsToken(ShotHttpError)
        && !shotYieldsToken(ShotTransportError));

    // ===== retryAfterMs (429 backoff parse) ============================
    chk("retry-after: seconds -> ms", retryAfterMs("5", 60000) == 5000);
    chk("retry-after: capped", retryAfterMs("999999", 60000) == 60000);
    chk("retry-after: whitespace tolerated", retryAfterMs("  3 ", 60000) == 3000);
    chk("retry-after: http-date / garbage -> 0", retryAfterMs("Wed, 21 Oct 2026 07:28:00 GMT", 60000) == 0);
    chk("retry-after: empty -> 0", retryAfterMs("", 60000) == 0);
    chk("retry-after: negative -> 0", retryAfterMs("-4", 60000) == 0);

    // ===== circuitTripped ==============================================
    chk("breaker: below threshold -> not tripped", !circuitTripped(9, 10));
    chk("breaker: at threshold -> tripped", circuitTripped(10, 10));
    chk("breaker: above threshold -> tripped", circuitTripped(11, 10));
    chk("breaker: threshold 0 disables", !circuitTripped(1000, 0));
    chk("breaker: negative threshold disables", !circuitTripped(1000, -1));

    // ===== corpusGuard + message =======================================
    chk("corpus: 0 tokens -> NoData", corpusGuard(0, 0) == CorpusNoData);
    chk("corpus: 1 token -> TooFew", corpusGuard(1, 1) == CorpusTooFew);
    chk("corpus: all identical -> Constant", corpusGuard(50, 1) == CorpusConstant);
    chk("corpus: varied -> Ok", corpusGuard(50, 47) == CorpusOk);
    chk("corpus: 2 distinct of 2 -> Ok", corpusGuard(2, 2) == CorpusOk);
    chk("corpus: NoData has a message", !corpusVerdictMessage(CorpusNoData, 0, 0).isEmpty());
    chk("corpus: Constant message names the counts",
        corpusVerdictMessage(CorpusConstant, 50, 1).contains("50") &&
        corpusVerdictMessage(CorpusConstant, 50, 1).contains("constant"));
    chk("corpus: Ok has no message", corpusVerdictMessage(CorpusOk, 50, 47).isEmpty());

    // ===== scopeAllows (empty scope must REFUSE) =======================
    chk("scope: empty list refuses even a 'matching' host", !scopeAllows(true, true));
    chk("scope: non-empty + host in scope -> allow", scopeAllows(false, true));
    chk("scope: non-empty + host NOT in scope -> refuse", !scopeAllows(false, false));
    chk("scope: empty + not-in-scope -> refuse", !scopeAllows(true, false));

    // ===== extractToken: Delimiter (key = "<start>\x1f<end>") ============
    {
        auto k = [](const QString &start, const QString &end) {
            return start + QChar(0x1f) + end;
        };
        const QByteArray body = QByteArray("prefix<<TOKEN=abc123>>suffix");
        chk("delim: between << and >>",
            extractToken(FromDelimiter, k("<<TOKEN=", ">>"), 200, {}, body) == "abc123");
        chk("delim: empty start -> from beginning",
            extractToken(FromDelimiter, k("", "<<"), 200, {}, body) == "prefix");
        chk("delim: empty end -> to end",
            extractToken(FromDelimiter, k(">>", ""), 200, {}, body) == "suffix");
        chk("delim: absent start -> empty",
            extractToken(FromDelimiter, k("NOPE", ">>"), 200, {}, body).isEmpty());
        chk("delim: absent end -> empty",
            extractToken(FromDelimiter, k("<<TOKEN=", "###"), 200, {}, body).isEmpty());
        chk("delim: malformed key (no separator) -> empty",
            extractToken(FromDelimiter, "no-separator-here", 200, {}, body).isEmpty());
        // end is searched AFTER start, so a start-substring appearing in the tail
        // doesn't confuse the second boundary.
        chk("delim: end sought after start",
            extractToken(FromDelimiter, k("a", "a"), 200, {}, QByteArray("XaYaZ")) == "Y");
    }

    std::fprintf(stderr, "sequencer_capture_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

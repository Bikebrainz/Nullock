// Tests for Intruder result grep (Src/Core/Networking/intruder_grep.cpp) --
// the "Grep - Match" / "Grep - Extract" result columns.
//
// Load-bearing invariants:
//   * a match/extract NEVER crashes or hangs, even on a malformed regex or a
//     multi-megabyte response (scanning is bounded to kMaxScan chars);
//   * an invalid regex degrades safely (literal search for match, nothing for
//     extract) instead of throwing;
//   * both regex and delimiter extraction pull the right substring.
//
// Run via:  ctest -R intruder_grep -V

#include "intruder_grep.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>

#include <cstdio>

using namespace Nullock::Core::IntruderGrep;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QString body = QStringLiteral(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "{\"status\":\"ok\",\"token\":\"tok_A1B2C3\",\"role\":\"admin\"}");

    // ----- grepMatch: literal -----
    chk("match literal hit",            grepMatch(body, { "admin" }));
    chk("match literal miss",          !grepMatch(body, { "root" }));
    chk("match any-of hits on second",  grepMatch(body, { "nope", "token" }));
    chk("match empty needle list",     !grepMatch(body, {}));
    chk("match only-empty needle",     !grepMatch(body, { QString() }));

    // ----- grepMatch: regex -----
    chk("match regex digits",           grepMatch(body, { "tok_[A-Z0-9]+" }));
    chk("match regex miss",            !grepMatch(body, { "tok_[0-9]{9,}" }));
    // An invalid regex must not throw; it degrades to a literal search. The
    // literal "[unclosed" is not in the body -> no (safe) match.
    chk("match invalid regex -> literal, safe miss", !grepMatch(body, { "[unclosed" }));
    // ...and the same invalid pattern DOES match when present literally.
    chk("match invalid regex -> literal hit",
        grepMatch(QStringLiteral("has a [unclosed bracket"), { "[unclosed" }));

    // ----- grepExtract: regex capture group -----
    chk("extract regex capture group",
        grepExtract(body, { QStringLiteral("\"token\":\"([^\"]+)\""), {}, {} })
            == QStringLiteral("tok_A1B2C3"));
    // No capture group -> whole match.
    chk("extract regex whole match",
        grepExtract(body, { QStringLiteral("tok_[A-Z0-9]+"), {}, {} })
            == QStringLiteral("tok_A1B2C3"));
    chk("extract regex no match -> empty",
        grepExtract(body, { QStringLiteral("nope([0-9]+)"), {}, {} }).isEmpty());
    chk("extract invalid regex -> empty",
        grepExtract(body, { QStringLiteral("([unclosed"), {}, {} }).isEmpty());

    // ----- grepExtract: delimiter pair -----
    chk("extract between delimiters",
        grepExtract(body, { {}, QStringLiteral("\"token\":\""), QStringLiteral("\"") })
            == QStringLiteral("tok_A1B2C3"));
    chk("extract empty start -> from beginning",
        grepExtract(QStringLiteral("ABCDEF"), { {}, {}, QStringLiteral("CD") })
            == QStringLiteral("AB"));
    chk("extract empty end -> to end",
        grepExtract(QStringLiteral("ABCDEF"), { {}, QStringLiteral("CD"), {} })
            == QStringLiteral("EF"));
    chk("extract missing start -> empty",
        grepExtract(body, { {}, QStringLiteral("<<nope>>"), QStringLiteral("\"") }).isEmpty());
    chk("extract missing end -> empty",
        grepExtract(body, { {}, QStringLiteral("\"token\":\""), QStringLiteral("<<nope>>") }).isEmpty());
    chk("extract all-empty spec -> empty",
        grepExtract(body, { {}, {}, {} }).isEmpty());

    // ----- bounds: empty + huge input -----
    chk("match empty text -> false", !grepMatch(QString(), { "x" }));
    chk("extract empty text -> empty", grepExtract(QString(), { QStringLiteral("x"), {}, {} }).isEmpty());

    // A token PAST the kMaxScan window must NOT be found, and the call must be
    // fast (bounded scan). Build ~2x the cap of filler, then append the token.
    {
        QString huge(kMaxScan * 2, QLatin1Char('.'));
        huge += QStringLiteral("NEEDLE_PAST_CAP");
        QElapsedTimer t; t.start();
        const bool matched = grepMatch(huge, { "NEEDLE_PAST_CAP" });
        const QString ex = grepExtract(huge, { QStringLiteral("NEEDLE_(PAST)_CAP"), {}, {} });
        const qint64 ms = t.elapsed();
        chk("huge input: token past cap NOT matched", !matched);
        chk("huge input: token past cap NOT extracted", ex.isEmpty());
        chk("huge input: bounded scan is fast (<250ms)", ms < 250);
    }
    // ...but a token WITHIN the cap IS found even in a huge string.
    {
        QString huge = QStringLiteral("EARLY_TOKEN_xyz");
        huge += QString(kMaxScan * 2, QLatin1Char('.'));
        chk("huge input: token within cap matched", grepMatch(huge, { "EARLY_TOKEN" }));
        chk("huge input: token within cap extracted",
            grepExtract(huge, { QStringLiteral("EARLY_(TOKEN)"), {}, {} }) == QStringLiteral("TOKEN"));
    }

    // ----- payloadReflected: LITERAL reflection (never regex) -----
    chk("reflected: payload echoed in body",  payloadReflected(body, "tok_A1B2C3"));
    chk("reflected: payload not echoed",      !payloadReflected(body, "not-present"));
    chk("reflected: empty payload -> false",  !payloadReflected(body, QString()));
    // The critical difference from grepMatch: a payload is DATA, not a regex.
    // "a.b" must be reflected ONLY by the literal "a.b", never by "axb".
    chk("reflected: literal dot NOT matched by axb",
        !payloadReflected(QStringLiteral("value=axb;"), "a.b"));
    chk("reflected: literal dot matched by a.b",
        payloadReflected(QStringLiteral("value=a.b;"), "a.b"));
    // A regex-metachar payload (a real fuzz string) is matched literally, not
    // interpreted -- grepMatch would treat "(?:" as an invalid/again-literal case,
    // but reflection is unconditionally literal.
    chk("reflected: regex-metachar payload matched literally",
        payloadReflected(QStringLiteral("err near '(?:' token"), "(?:"));
    // Case sensitivity is a caller option (default sensitive).
    chk("reflected: case-sensitive default misses different case",
        !payloadReflected(QStringLiteral("Value=ADMIN"), "admin"));
    chk("reflected: case-insensitive opt-in hits",
        payloadReflected(QStringLiteral("Value=ADMIN"), "admin", /*caseSensitive=*/false));
    // Bounded like the rest: a reflection past kMaxScan is not scanned.
    {
        QString huge = QString(kMaxScan * 2, QLatin1Char('.'));
        huge += QStringLiteral("LATE_PAYLOAD");
        chk("reflected: payload past the scan cap is NOT flagged",
            !payloadReflected(huge, "LATE_PAYLOAD"));
    }

    std::fprintf(stderr, "intruder_grep_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

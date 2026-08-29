// Tests for Intruder save/resume serialization
// (Src/Core/Networking/intruder_persist_logic.cpp). Invariants:
//   * a SavedRun (config + result rows) round-trips through JSON unchanged;
//   * a NULL combo entry ("leave this marker at default") survives the trip as
//     null (not "" ) so resend() still reproduces the exact request;
//   * malformed / empty / garbage JSON parses to a safe default SavedRun, never
//     a crash;
//   * the format carries a version tag.
//
// Run via:  ctest -R intruder_persist_logic -V

#include "intruder_persist_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::IntruderPersist;
using Nullock::Core::IntruderRules::Rule;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

bool sameConfig(const RunConfig &a, const RunConfig &b) {
    if (a.host != b.host || a.port != b.port || a.tls != b.tls) return false;
    if (a.requestTemplate != b.requestTemplate || a.attackType != b.attackType) return false;
    if (a.payloadSets != b.payloadSets) return false;
    if (a.grepMatch != b.grepMatch) return false;
    if (a.grepExtract.regex != b.grepExtract.regex) return false;
    if (a.grepExtract.start != b.grepExtract.start) return false;
    if (a.grepExtract.end   != b.grepExtract.end)   return false;
    if (a.concurrency != b.concurrency || a.throttleMs != b.throttleMs) return false;
    if (a.retries != b.retries) return false;
    // Request-shaping fields (their omission was the persistence bug).
    if (a.globalEncodeChars != b.globalEncodeChars) return false;
    if (a.recursiveGrep != b.recursiveGrep) return false;
    if (a.recursiveGrepSeed != b.recursiveGrepSeed) return false;
    if (a.recursiveGrepCount != b.recursiveGrepCount) return false;
    if (a.followPolicy != b.followPolicy || a.followCookies != b.followCookies) return false;
    if (a.rules.size() != b.rules.size()) return false;
    for (int i = 0; i < a.rules.size(); ++i)
        if (a.rules[i].op != b.rules[i].op || a.rules[i].arg != b.rules[i].arg) return false;
    return true;
}

bool sameRow(const ResultRow &a, const ResultRow &b) {
    if (a.id != b.id || a.payloadValues != b.payloadValues) return false;
    // combo compared element-by-element so a null and an empty string differ.
    if (a.combo.size() != b.combo.size()) return false;
    for (int i = 0; i < a.combo.size(); ++i) {
        if (a.combo[i].isNull() != b.combo[i].isNull()) return false;
        if (a.combo[i] != b.combo[i]) return false;
    }
    return a.statusCode == b.statusCode && a.responseSize == b.responseSize
        && a.elapsedMs == b.elapsedMs && a.errorMessage == b.errorMessage
        && a.complete == b.complete && a.matched == b.matched
        && a.extracted == b.extracted;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // Build a fully-populated run.
    SavedRun run;
    run.config.host = QStringLiteral("api.example.com");
    run.config.port = 8443;
    run.config.tls = true;
    run.config.requestTemplate = QStringLiteral("GET /?q=\xC2\xA7""FUZZ\xC2\xA7 HTTP/1.1\r\nHost: x\r\n\r\n");
    run.config.attackType = 3; // cluster bomb
    run.config.payloadSets = QStringList{ QStringLiteral("a\nb\nc"), QStringLiteral("1\n2") };
    run.config.rules = QList<Rule>{ { QStringLiteral("prefix"), QStringLiteral("id=") },
                                    { QStringLiteral("base64-encode"), QString() } };
    run.config.grepMatch = QStringList{ QStringLiteral("admin"), QStringLiteral("tok_[0-9]+") };
    run.config.grepExtract.regex = QStringLiteral("\"token\":\"([^\"]+)\"");
    run.config.grepExtract.start = QStringLiteral("<<");
    run.config.grepExtract.end   = QStringLiteral(">>");
    run.config.concurrency = 12;
    run.config.throttleMs = 250;
    run.config.retries = 3;
    // Request-shaping fields, set to NON-default values so their round-trip is exercised.
    run.config.globalEncodeChars = QStringLiteral("&=#");
    run.config.recursiveGrep = true;
    run.config.recursiveGrepSeed = QStringLiteral("seed-token-0");
    run.config.recursiveGrepCount = 25;
    run.config.followPolicy = 3;      // FollowAlways (non-default)
    run.config.followCookies = false; // non-default

    ResultRow r1;
    r1.id = 1;
    r1.payloadValues = QStringList{ QStringLiteral("a"), QStringLiteral("1") };
    r1.combo = QStringList{ QStringLiteral("a"), QStringLiteral("1") };
    r1.statusCode = 200; r1.responseSize = 56; r1.elapsedMs = 17;
    r1.complete = true; r1.matched = true; r1.extracted = QStringLiteral("tok_9");
    run.rows.append(r1);

    // Row 2 has a NULL combo entry (Sniper leaves a marker at its default).
    ResultRow r2;
    r2.id = 2;
    r2.payloadValues = QStringList{ QStringLiteral("(default)"), QStringLiteral("2") };
    r2.combo = QStringList{ QString(), QStringLiteral("2") };   // combo[0] is null
    r2.statusCode = 404; r2.responseSize = 12; r2.elapsedMs = 9;
    r2.complete = true; r2.matched = false; r2.extracted = QString();
    run.rows.append(r2);

    // ----- round-trip via QJsonObject -----
    {
        const SavedRun back = fromJson(toJson(run));
        chk("json round-trip: version",  back.version == run.version);
        chk("json round-trip: config",   sameConfig(back.config, run.config));
        chk("json round-trip: row count",back.rows.size() == run.rows.size());
        chk("json round-trip: row 0",    back.rows.size() == 2 && sameRow(back.rows[0], r1));
        chk("json round-trip: row 1",    back.rows.size() == 2 && sameRow(back.rows[1], r2));
        chk("json round-trip: null combo preserved as null",
            back.rows.size() == 2 && back.rows[1].combo.size() == 2 && back.rows[1].combo[0].isNull());
    }

    // ----- round-trip via bytes -----
    {
        const SavedRun back = fromBytes(toBytes(run));
        chk("bytes round-trip: config", sameConfig(back.config, run.config));
        chk("bytes round-trip: rows",   back.rows.size() == 2 && sameRow(back.rows[0], r1) && sameRow(back.rows[1], r2));
    }

    // ----- version tag present in output -----
    chk("output carries version tag",  toJson(run).value("version").toInt() == kFormatVersion);
    chk("output carries kind tag",     toJson(run).value("kind").toString() == QStringLiteral("nullock.intruder.run"));

    // ----- default-safe on empty / garbage -----
    {
        const SavedRun empty = fromJson(QJsonObject{});
        chk("empty object -> no rows",       empty.rows.isEmpty());
        chk("empty object -> default port",  empty.config.port == 443);
        chk("empty object -> default tls",   empty.config.tls == true);
        chk("empty object -> default retries", empty.config.retries == 0);
        chk("empty object -> version",       empty.version == kFormatVersion);
    }
    {
        const SavedRun garbage = fromBytes(QByteArray("this is not json {{{"));
        chk("garbage bytes -> empty run",    garbage.rows.isEmpty() && garbage.config.host.isEmpty());
    }
    {
        const SavedRun notObj = fromBytes(QByteArray("[1,2,3]"));
        chk("json array (not object) -> empty run", notObj.rows.isEmpty());
    }
    {
        // wrong field types must not throw.
        const SavedRun weird = fromBytes(QByteArray("{\"config\":{\"port\":\"nope\"},\"rows\":\"x\"}"));
        chk("wrong types -> safe defaults", weird.rows.isEmpty() && weird.config.port == 443);
    }

    // ----- empty run round-trips -----
    {
        SavedRun e;
        const SavedRun back = fromBytes(toBytes(e));
        chk("empty run round-trip", back.rows.isEmpty() && back.version == kFormatVersion);
    }

    // ----- planResume: the "Resume" decision -----
    {
        // No rows -> nothing to resume.
        const ResumePlan none = planResume(false, {});
        chk("resume: no rows -> not resumable", !none.canResume && none.toFireCount == 0);

        // A partially-fired attack: rows 0 and 2 complete, 1 and 3 pending.
        const ResumePlan part = planResume(false, {true, false, true, false});
        chk("resume: partial -> resumable", part.canResume);
        chk("resume: partial -> skip the completed rows",
            part.skipRows == QList<int>({0, 2}));
        chk("resume: partial -> re-fire the pending rows", part.toFireCount == 2);

        // Nothing fired yet -> resumable, fire every row (skip none).
        const ResumePlan fresh = planResume(false, {false, false, false});
        chk("resume: none complete -> resumable, skip none",
            fresh.canResume && fresh.skipRows.isEmpty() && fresh.toFireCount == 3);

        // Every row complete -> nothing left to resume.
        const ResumePlan done = planResume(false, {true, true, true});
        chk("resume: all complete -> not resumable",
            !done.canResume && done.toFireCount == 0 && done.skipRows.isEmpty());

        // Recursive-grep runs are unresumable regardless of completion state.
        const ResumePlan rec = planResume(true, {true, false, false});
        chk("resume: recursive-grep -> not resumable (even with pending rows)",
            !rec.canResume && !rec.reason.isEmpty());
    }

    std::fprintf(stderr, "intruder_persist_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

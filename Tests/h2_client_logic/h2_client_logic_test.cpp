// Regression corpus for the pure HTTP/2 client logic that backs the multi-stream
// rework: the request-header build (pseudo-header order + hop-by-hop stripping),
// the exhaustion caps (concurrent-stream + per-stream body), the status->reason
// map, and the pump-loop decision (whose interleave ordering prevents a second
// stream deadlocking behind a blocking read).
//
// Run via:  ctest -R h2_client_logic -V

#include "h2_client_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Proxy::H2ClientLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
int idxOf(const QList<HeaderNV> &nv, const QByteArray &name) {
    for (int i = 0; i < nv.size(); ++i) if (nv[i].name == name) return i;
    return -1;
}
bool has(const QList<HeaderNV> &nv, const QByteArray &name) { return idxOf(nv, name) >= 0; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== buildRequestHeaders ==========================================
    {
        QList<QPair<QString, QString>> hdrs = {
            { "User-Agent", "x" }, { "Host", "evil" }, { "Connection", "keep-alive" },
            { "Content-Type", "application/json" }, { "TE", "trailers" },
            { "Proxy-Connection", "x" }, { "Transfer-Encoding", "chunked" },
            { "Upgrade", "h2c" }, { "Keep-Alive", "5" }, { "", "empty-name" },
        };
        const auto nv = buildRequestHeaders("POST", "example.com", "/api?q=1", hdrs);

        chk("pseudo: :method first",    nv.value(0).name == ":method"    && nv.value(0).value == "POST");
        chk("pseudo: :scheme second",   nv.value(1).name == ":scheme"    && nv.value(1).value == "https");
        chk("pseudo: :authority third", nv.value(2).name == ":authority" && nv.value(2).value == "example.com");
        chk("pseudo: :path fourth",     nv.value(3).name == ":path"      && nv.value(3).value == "/api?q=1");

        chk("hop-by-hop: host dropped",              !has(nv, "host"));
        chk("hop-by-hop: connection dropped",        !has(nv, "connection"));
        chk("hop-by-hop: te dropped",                !has(nv, "te"));
        chk("hop-by-hop: proxy-connection dropped",  !has(nv, "proxy-connection"));
        chk("hop-by-hop: transfer-encoding dropped", !has(nv, "transfer-encoding"));
        chk("hop-by-hop: upgrade dropped",           !has(nv, "upgrade"));
        chk("hop-by-hop: keep-alive dropped",        !has(nv, "keep-alive"));
        chk("kept: user-agent lowercased",           has(nv, "user-agent"));
        chk("kept: content-type lowercased",         has(nv, "content-type"));
        chk("empty header name skipped",             nv.size() == 6);   // 4 pseudo + 2 kept
        // pseudo-headers must precede regular headers
        chk("all pseudo-headers precede regular", idxOf(nv, "user-agent") >= 4);
    }
    {
        const auto nv = buildRequestHeaders("", "h.example", "", {});
        chk("empty method -> GET", nv.value(0).value == "GET");
        chk("empty path -> /",     nv.value(3).value == "/");
        chk("scheme is always https", nv.value(1).value == "https");
    }

    // ===== isHopByHopHeader =============================================
    chk("hop: 'te' is hop-by-hop", isHopByHopHeader("te"));
    chk("hop: 'content-type' is not", !isHopByHopHeader("content-type"));

    // ===== reasonFor ====================================================
    chk("reason 200", QByteArray(reasonFor(200)) == "OK");
    chk("reason 404", QByteArray(reasonFor(404)) == "Not Found");
    chk("reason 503", QByteArray(reasonFor(503)) == "Service Unavailable");
    chk("reason 299 -> generic 2xx", QByteArray(reasonFor(299)) == "OK");
    chk("reason 418 -> generic 4xx", QByteArray(reasonFor(418)) == "Client Error");
    chk("reason 599 -> generic 5xx", QByteArray(reasonFor(599)) == "Server Error");
    chk("reason 100 -> Unknown",     QByteArray(reasonFor(100)) == "Unknown");

    // ===== exhaustion caps ==============================================
    chk("submit: below cap allowed",  !shouldRejectSubmit(15, 64));
    chk("submit: at cap rejected",     shouldRejectSubmit(64, 64));
    chk("submit: over cap rejected",   shouldRejectSubmit(65, 64));
    chk("submit: 63 of 64 allowed",   !shouldRejectSubmit(63, 64));
    chk("body: under budget ok",      !bodyOverBudget(100, 1000));
    chk("body: exactly at budget ok", !bodyOverBudget(1000, 1000));
    chk("body: over budget flagged",   bodyOverBudget(1001, 1000));

    // ===== nextPumpAction ==============================================
    chk("pump: 0 open -> Done",           nextPumpAction(0, false, false) == PumpAction::Done);
    chk("pump: open + no write -> Read",  nextPumpAction(3, false, false) == PumpAction::ReadOnly);
    chk("pump: open + wrote -> WriteThenRead", nextPumpAction(3, true, false) == PumpAction::WriteThenRead);
    chk("pump: fatal beats open+write",   nextPumpAction(3, true, true)  == PumpAction::Fatal);
    chk("pump: fatal beats done",         nextPumpAction(0, false, true) == PumpAction::Fatal);
    // done-beats-write: when the LAST stream closes in the same iteration that
    // flushed trailing outbound bytes (SETTINGS/WINDOW_UPDATE ACK, final RST),
    // openStreams<=0 AND wrotePending=true both hold -- the done-gate must win, or
    // the pump loops into a blocking read with zero open streams and hangs until
    // the read-timeout. This precedence was untested (0,true,false was never fed).
    chk("pump: 0 open + wrote -> Done (done beats write, no post-close read hang)",
        nextPumpAction(0, true, false) == PumpAction::Done);
    // invariant: never Done while a stream is still open (and not fatal)
    {
        bool ok = true;
        for (int open = 1; open <= 5; ++open)
            for (int w = 0; w < 2; ++w)
                if (nextPumpAction(open, w, false) == PumpAction::Done) ok = false;
        chk("pump invariant: never Done while streams open", ok);
    }

    // ===== assembleOutcome ==============================================
    using AO = AssembleOutcome;
    // (done, status, hadError, fatal)
    chk("assemble: clean finish -> Success",       assembleOutcome(true, 200, false, false) == AO::Success);
    chk("assemble: not-done + fatal -> Fatal",     assembleOutcome(false, 200, false, true) == AO::Fatal);
    // A cleanly-completed stream survives a later connection fatal (the Phase-1
    // completedOk-survives-fatal fix): Success, NOT Fatal.
    chk("assemble: completed stream survives a later fatal",
        assembleOutcome(true, 200, false, true)  == AO::Success);
    chk("assemble: per-stream error -> StreamError", assembleOutcome(false, 200, true, false) == AO::StreamError);
    chk("assemble: no status at all -> NoStatus",  assembleOutcome(false, 0, false, false)  == AO::NoStatus);
    // The regression the refactor introduced + this pins: :status received but
    // END_STREAM never arrived (truncated body) must still be served (Success),
    // NOT failed.
    chk("assemble: status-but-not-done (truncated) -> Success",
        assembleOutcome(false, 200, false, false) == AO::Success);
    chk("assemble: truncated with error still fails", assembleOutcome(false, 200, true, false) == AO::StreamError);

    std::fprintf(stderr, "h2_client_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// Regression corpus for the H2EventLog bounding logic.
//
// The HTTP/2 telemetry sink records proxied (untrusted) traffic. Its event ring
// was already capped, but the per-stream summary map grew without bound -- every
// stream a connection ever opened stayed resident, contradicting the header's own
// "attacker bytes can't pin RAM" promise. capStreamSummaries() now bounds it; this
// locks the eviction policy (closed-first, then oldest) and the field clamp.
//
// Run via:  ctest -R h2_logic -V

#include "h2_logic.hpp"

#include <QCoreApplication>
#include <QMap>
#include <QString>

#include <cstdio>

using namespace Nullock::Proxy;
using namespace Nullock::Proxy::H2Logic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

H2StreamSummary mk(qint64 openedAtMs, bool closed) {
    H2StreamSummary s;
    s.openedAtMs = openedAtMs;
    s.closed     = closed;
    return s;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== under / at cap: no eviction ==================================
    {
        QMap<QString, H2StreamSummary> m;
        m["a"] = mk(100, false);
        m["b"] = mk(200, false);
        chk("cap: at cap (2,max2) evicts nothing", capStreamSummaries(m, 2) == 0 && m.size() == 2);
        chk("cap: under cap (2,max5) evicts nothing", capStreamSummaries(m, 5) == 0 && m.size() == 2);
    }

    // ===== over cap: evict down to cap, return count ====================
    {
        QMap<QString, H2StreamSummary> m;
        m["a"] = mk(100, false);
        m["b"] = mk(200, false);
        m["c"] = mk(300, false);
        const int n = capStreamSummaries(m, 2);
        chk("cap: 3->max2 evicts 1", n == 1 && m.size() == 2);
        chk("cap: oldest-open evicted (a, openedAt 100)", !m.contains("a") && m.contains("b") && m.contains("c"));
    }

    // ===== closed-first eviction ========================================
    {
        QMap<QString, H2StreamSummary> m;
        m["a"] = mk(100, false);   // open, oldest by age
        m["b"] = mk(200, true);    // CLOSED (terminal)
        m["c"] = mk(300, false);   // open, newest
        const int n = capStreamSummaries(m, 2);
        chk("cap: closed evicted FIRST even though not the oldest", n == 1 && !m.contains("b"));
        chk("cap: both open streams survive (a older, c newer)", m.contains("a") && m.contains("c"));
    }

    // ===== multiple closed: oldest-closed-first =========================
    {
        QMap<QString, H2StreamSummary> m;
        m["a"] = mk(300, true);    // closed, newer
        m["b"] = mk(100, true);    // closed, older
        m["c"] = mk(200, false);   // open
        const int n = capStreamSummaries(m, 1);
        chk("cap: 3->max1 evicts 2 (both closed)", n == 2 && m.size() == 1);
        chk("cap: the OPEN stream survives over closed ones", m.contains("c"));
    }

    // ===== orphan (openedAtMs==0) shed first ============================
    {
        QMap<QString, H2StreamSummary> m;
        m["orphan"] = mk(0, false);    // auto-created by a status/RST for unseen stream
        m["b"]      = mk(100, false);
        m["c"]      = mk(200, false);
        const int n = capStreamSummaries(m, 2);
        chk("cap: orphan (openedAt 0) evicted first", n == 1 && !m.contains("orphan"));
    }

    // ===== defensive: maxStreams <= 0 is a no-op ========================
    {
        QMap<QString, H2StreamSummary> m;
        m["a"] = mk(1, false);
        m["b"] = mk(2, false);
        m["c"] = mk(3, true);
        chk("cap: max 0 -> no-op (don't wipe all telemetry)", capStreamSummaries(m, 0) == 0 && m.size() == 3);
        chk("cap: max -1 -> no-op", capStreamSummaries(m, -1) == 0 && m.size() == 3);
    }

    // ===== eviction converges to exactly the cap ========================
    {
        QMap<QString, H2StreamSummary> m;
        for (int i = 0; i < 50; ++i)
            m[QString::number(i)] = mk(i, (i % 3) == 0);   // a third are closed
        const int n = capStreamSummaries(m, 10);
        chk("cap: 50->max10 evicts exactly 40", n == 40 && m.size() == 10);
        chk("cap: real production cap is generous", kMaxStreams >= 1024);
    }

    // ===== clampTelemetryField ==========================================
    chk("clamp: short string unchanged", clampTelemetryField("GET", 16) == "GET");
    chk("clamp: exactly maxLen unchanged", clampTelemetryField("abcd", 4) == "abcd");
    chk("clamp: over maxLen truncated", clampTelemetryField("abcdef", 4) == "abcd");
    chk("clamp: empty stays empty", clampTelemetryField("", 4).isEmpty());
    chk("clamp: negative maxLen -> unchanged (no clamp)", clampTelemetryField("abcdef", -1) == "abcdef");
    {
        const QString big(1'000'000, QChar('x'));   // a 1 MB :path
        chk("clamp: 1MB field truncated to the field cap", clampTelemetryField(big, kMaxTelemetryFieldLen).size() == kMaxTelemetryFieldLen);
    }
    chk("clamp: field cap is sane", kMaxTelemetryFieldLen > 0 && kMaxTelemetryFieldLen <= 1'000'000);

    std::fprintf(stderr, "h2_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

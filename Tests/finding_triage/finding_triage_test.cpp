// Unit corpus for the pure finding-triage logic. Locks the identity-key shape
// (it MUST match project_store's dedup key or a false-positive mark would never
// line up with its finding) and the two membership predicates that drive
// display-time filtering.
//
// Run via:  ctest -R finding_triage -V

#include "finding_triage_logic.hpp"

#include <QCoreApplication>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core::FindingTriageLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QChar US(QChar(0x1f));

    // ===== findingKey shape (must match ProjectStore::findingKey) ========
    {
        const QString k = findingKey("missing-csp", "app.test", "https://app.test/x", "No CSP header");
        const QString expected = QString("missing-csp") + US + "app.test" + US
                                 + "https://app.test/x" + US + "No CSP header";
        chk("key: exact US-delimited kind+host+url+summary", k == expected);
        chk("key: uses 0x1F separator (not a printable char)", k.contains(US));
    }
    chk("key: differs when kind differs",
        findingKey("a", "h", "u", "s") != findingKey("b", "h", "u", "s"));
    chk("key: differs when summary differs",
        findingKey("a", "h", "u", "s1") != findingKey("a", "h", "u", "s2"));
    chk("key: identical for identical finding fields",
        findingKey("a", "h", "u", "s") == findingKey("a", "h", "u", "s"));
    // A separator can't be spoofed by field content: "a|h" as kind must not equal
    // kind "a" + host "h" (distinct keys), because the real separator is 0x1F.
    chk("key: field content can't forge a boundary",
        findingKey(QString("a") + "h", "u1", "u2", "s")
        != findingKey("a", "h", QString("u1"), "u2s"));

    // ===== kindSuppressed =================================================
    {
        const QStringList sup = { "missing-csp", "verbose-sql-err" };
        chk("suppress: a suppressed kind matches", kindSuppressed("missing-csp", sup));
        chk("suppress: a non-suppressed kind does not", !kindSuppressed("leaked-aws-key", sup));
        chk("suppress: exact/case-sensitive (no partial)", !kindSuppressed("missing-csp-report", sup));
        chk("suppress: case matters", !kindSuppressed("Missing-CSP", sup));
        chk("suppress: empty kind never suppressed", !kindSuppressed("", sup));
        chk("suppress: empty set suppresses nothing", !kindSuppressed("missing-csp", {}));
    }

    // ===== keyIsFalsePositive ============================================
    {
        const QString k1 = findingKey("missing-csp", "a.test", "https://a.test/", "No CSP");
        const QString k2 = findingKey("leaked-aws-key", "a.test", "https://a.test/x", "AWS key");
        const QStringList fp = { k1 };
        chk("fp: a marked key matches", keyIsFalsePositive(k1, fp));
        chk("fp: an unmarked key does not", !keyIsFalsePositive(k2, fp));
        chk("fp: empty set marks nothing", !keyIsFalsePositive(k1, {}));
    }

    // ===== effectiveSeverity (per-finding override) =====================
    {
        const QString k1 = findingKey("missing-csp", "a.test", "https://a.test/", "No CSP");
        const QString k2 = findingKey("leaked-key",  "a.test", "https://a.test/x", "Key");
        QJsonArray ov;
        ov.append(QJsonObject{ { "key", k1 }, { "severity", "low" } });
        chk("severity: override replaces the original", effectiveSeverity(k1, "high", ov) == "low");
        chk("severity: no override -> original kept", effectiveSeverity(k2, "high", ov) == "high");
        chk("severity: empty overrides -> original", effectiveSeverity(k1, "medium", {}) == "medium");
        QJsonArray blank;
        blank.append(QJsonObject{ { "key", k1 }, { "severity", "" } });
        chk("severity: a blank override never masks the original",
            effectiveSeverity(k1, "high", blank) == "high");
    }

    std::fprintf(stderr, "finding_triage_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

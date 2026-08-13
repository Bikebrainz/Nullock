// Round-trip lock for the findings-persistence wire format (FindingSerial). A scan
// finding is written to <project>/findings.ndjson (one compact JSON object per line)
// and streamed back on reopen, so this proves toJson()->fromJson() preserves EVERY
// field -- including the original discovery timestamp and the enrichment block --
// and that the serialization is ndjson-safe (no raw newline can split a record) and
// crash-free on malformed / partial input.
//
// Run via:  ctest -R finding_serial -V

#include "finding_serial.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cstdio>

using Nullock::Core::Finding;
namespace FS = Nullock::Core::FindingSerial;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// A fully-populated finding: every field non-default so a dropped field is caught.
Finding sample() {
    Finding f;
    f.id         = 42;
    f.rowId      = 137;
    f.ts         = QDateTime::fromString(QStringLiteral("2026-08-13T12:34:56.789Z"),
                                         Qt::ISODateWithMs);
    f.severity   = QStringLiteral("high");
    f.kind       = QStringLiteral("missing-csp");
    f.summary    = QStringLiteral("Response has no Content-Security-Policy");
    f.evidence   = QStringLiteral("HTTP/1.1 200 OK\nServer: nginx");   // embedded newline
    f.host       = QStringLiteral("example.com");
    f.url        = QStringLiteral("https://example.com/app");
    f.cwe        = QStringLiteral("CWE-693");
    f.owasp      = QStringLiteral("A05:2021-Security Misconfiguration");
    f.cvssScore  = 6.5;
    f.cvssVector = QStringLiteral("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
    f.compliance = { QStringLiteral("PCI-DSS-6.5.7"), QStringLiteral("SOC2-CC6.1") };
    f.fixSummary = QStringLiteral("Add a Content-Security-Policy header");
    f.confidence = QStringLiteral("firm");
    return f;
}

bool sameFinding(const Finding &a, const Finding &b) {
    return a.id == b.id && a.rowId == b.rowId && a.ts == b.ts
        && a.severity == b.severity && a.kind == b.kind && a.summary == b.summary
        && a.evidence == b.evidence && a.host == b.host && a.url == b.url
        && a.cwe == b.cwe && a.owasp == b.owasp
        && qFuzzyCompare(a.cvssScore + 1.0, b.cvssScore + 1.0)
        && a.cvssVector == b.cvssVector && a.compliance == b.compliance
        && a.fixSummary == b.fixSummary && a.confidence == b.confidence;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== full round-trip: every field survives ========================
    const Finding orig = sample();
    const Finding back = FS::fromJson(FS::toJson(orig));
    chk("round-trip: id",         back.id == orig.id);
    chk("round-trip: rowId",      back.rowId == orig.rowId);
    chk("round-trip: ts (ms)",    back.ts == orig.ts);
    chk("round-trip: ts valid",   back.ts.isValid());
    chk("round-trip: severity",   back.severity == orig.severity);
    chk("round-trip: kind",       back.kind == orig.kind);
    chk("round-trip: summary",    back.summary == orig.summary);
    chk("round-trip: evidence (with newline)", back.evidence == orig.evidence);
    chk("round-trip: host",       back.host == orig.host);
    chk("round-trip: url",        back.url == orig.url);
    chk("round-trip: cwe",        back.cwe == orig.cwe);
    chk("round-trip: owasp",      back.owasp == orig.owasp);
    chk("round-trip: cvssScore",  qFuzzyCompare(back.cvssScore, orig.cvssScore));
    chk("round-trip: cvssVector", back.cvssVector == orig.cvssVector);
    chk("round-trip: compliance (both tags, in order)", back.compliance == orig.compliance);
    chk("round-trip: fixSummary", back.fixSummary == orig.fixSummary);
    chk("round-trip: confidence", back.confidence == orig.confidence);
    chk("round-trip: whole struct equal", sameFinding(orig, back));

    // ===== ndjson safety: compact, one line, survives a QJsonDocument line trip ==
    const QByteArray line = QJsonDocument(FS::toJson(orig)).toJson(QJsonDocument::Compact);
    chk("ndjson: serialization is a single line (no raw newline)",
        !line.contains('\n'));
    // The embedded newline in evidence must be JSON-escaped (\n), not a raw byte.
    chk("ndjson: embedded newline is escaped, not literal",
        line.contains("\\n") && !line.contains('\n'));
    const QJsonDocument reparsed = QJsonDocument::fromJson(line);
    chk("ndjson: reparses to an object", reparsed.isObject());
    chk("ndjson: reparsed finding equals original",
        sameFinding(orig, FS::fromJson(reparsed.object())));

    // ===== empty / default finding round-trips ==========================
    const Finding empt;                       // all-default
    const Finding emptBack = FS::fromJson(FS::toJson(empt));
    chk("default: id 0",        emptBack.id == 0);
    chk("default: empty kind",  emptBack.kind.isEmpty());
    chk("default: cvssScore 0", qFuzzyCompare(emptBack.cvssScore + 1.0, 1.0));
    chk("default: empty compliance", emptBack.compliance.isEmpty());

    // ===== malformed / partial input: defaults, never crashes ===========
    const Finding fromEmpty = FS::fromJson(QJsonObject{});
    chk("malformed: empty object -> default id 0", fromEmpty.id == 0);
    chk("malformed: empty object -> invalid ts (unparseable)", !fromEmpty.ts.isValid());
    chk("malformed: empty object -> empty kind", fromEmpty.kind.isEmpty());
    // Partial object (only a couple keys present) keeps those, defaults the rest.
    const Finding partial = FS::fromJson(QJsonObject{
        { "kind", QStringLiteral("sql-error") }, { "rowId", 9 },
    });
    chk("partial: present kind kept",  partial.kind == QStringLiteral("sql-error"));
    chk("partial: present rowId kept", partial.rowId == 9);
    chk("partial: absent summary defaults empty", partial.summary.isEmpty());
    chk("partial: absent cvssScore defaults 0", qFuzzyCompare(partial.cvssScore + 1.0, 1.0));
    // Wrong-typed ts (a number, not an ISO string) must not throw -> invalid ts.
    const Finding badTs = FS::fromJson(QJsonObject{ { "ts", 12345 } });
    chk("malformed: numeric ts -> invalid, no crash", !badTs.ts.isValid());

    std::fprintf(stderr, "finding_serial_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

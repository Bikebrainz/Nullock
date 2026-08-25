#pragma once

// Maps each finding kind to its CWE, OWASP Top 10 category, CVSS v3.1
// vector, compliance tags, and one-line fix summary. Run once per
// finding right after addFinding(). Burp Pro charges $475/yr for the
// equivalent; ours is open-data and editable.

#include "passive_scanner.hpp"

#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::FindingEnricher {

// Mutates the finding in place. Safe to call on already-enriched
// findings (overwrites with the canonical mapping).
void enrich(Finding &f);

// Public for tests / UI: returns true if the finding kind has a known
// mapping. False = we've just got generic severity-based defaults.
bool hasMapping(const QString &kind);

// Default confidence for a finding kind (Burp-style taxonomy):
//   "confirmed" -- proven out-of-band or by an active control round: any OAST
//                  callback kind, or a *-confirmed / time-based-reproduced kind.
//   "tentative" -- explicitly heuristic (*-possible, *-lead, reflected-* that
//                  wasn't corroborated).
//   "firm"      -- everything else (strong signal, low FP risk).
// enrich() applies this only when the finding didn't already carry a confidence
// (a scanner that did its own proof can set "confirmed" and we preserve it).
QString confidenceForKind(const QString &kind);

// --- Issue-definitions library (Burp's browsable "Issue definitions") -----
// One catalog entry per issue KIND the scanner can report, drawn from the same
// hand-curated enrichment table enrich() applies -- so the library and live
// findings always agree. cvssScore is 0.0 for kinds whose score is
// severity-dependent (informational / context findings); confidence is the
// kind's default (confirmed/firm/tentative).
struct IssueDefinition {
    QString     kind;
    QString     cwe;
    QString     owasp;
    double      cvssScore = 0.0;
    QString     cvssVector;
    QStringList compliance;
    QString     description;   // the canonical one-line detail / remediation
    QString     confidence;
};

// Every KIND in the enrichment table, sorted by kind. This is the enumerable
// set of issue types (the family-prefix and generic fallbacks are for kinds NOT
// in the table and are intentionally not listed as distinct definitions).
QList<IssueDefinition> issueCatalog();

} // namespace Nullock::Core::FindingEnricher

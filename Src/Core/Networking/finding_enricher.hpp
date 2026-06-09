#pragma once

// Maps each finding kind to its CWE, OWASP Top 10 category, CVSS v3.1
// vector, compliance tags, and one-line fix summary. Run once per
// finding right after addFinding(). Burp Pro charges $475/yr for the
// equivalent; ours is open-data and editable.

#include "passive_scanner.hpp"

namespace Nullock::Core::FindingEnricher {

// Mutates the finding in place. Safe to call on already-enriched
// findings (overwrites with the canonical mapping).
void enrich(Finding &f);

// Public for tests / UI: returns true if the finding kind has a known
// mapping. False = we've just got generic severity-based defaults.
bool hasMapping(const QString &kind);

} // namespace Nullock::Core::FindingEnricher

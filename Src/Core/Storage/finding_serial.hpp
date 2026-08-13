#pragma once

// Pure Finding <-> JSON round-trip. Split out of the scanner + persistence code so
// a unit test can exercise it directly, and so the on-disk schema for a project's
// findings lives in exactly one place.
//
// This is the wire format for <project>/findings.ndjson (one compact JSON object
// per line). A scan finding must survive app close / project reopen, so EVERY
// field the findings panel and the report builder read has to round-trip
// losslessly -- including the original discovery timestamp (which is evidence in a
// pentest report, not decoration) and the whole enrichment block. baseline.json
// reuses toJson() too, so the two durable finding artifacts can never diverge.

#include "passive_scanner.hpp"   // Nullock::Core::Finding

#include <QJsonObject>

namespace Nullock::Core::FindingSerial {

// Serialize every field of a Finding: id/rowId, ts (written as ISODateWithMs in
// UTC), the core fields, and the enrichment block
// (cwe/owasp/cvssScore/cvssVector/compliance/fixSummary/confidence).
QJsonObject toJson(const Finding &f);

// Inverse of toJson(). Missing keys default to an empty/zero field so the schema
// can grow without breaking old files; an unparseable ts yields an invalid
// QDateTime rather than throwing.
Finding fromJson(const QJsonObject &o);

} // namespace Nullock::Core::FindingSerial

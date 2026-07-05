#pragma once

// Processor: the payload-processing workbench behind the PROCESSOR tab. Given a
// single payload it emits filter-bypass VARIANTS (encoding / casing / comment /
// whitespace transforms) so an operator can test whether a target's input
// filters or WAF actually block a payload class and, if so, whether a well-known
// encoding slips past. This is the same standard, publicly-documented capability
// shipped by Burp's Payload Processing rules and sqlmap's tamper scripts -- for
// authorized engagements it measures the DEFENDER's filter coverage.
//
// PURE: QString in, structured variants out; no I/O / clock / randomness, links
// against Qt6::Core alone and is fully unit-testable.

#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::Processor {

struct Variant {
    QString name;     // transform id, e.g. "double-url-encode"
    QString output;   // the processed payload
    QString note;     // what filter class it targets
};

// All transform ids in stable display order.
QStringList transforms();

// Apply one named transform to `payload`. Unknown id -> the payload unchanged
// with name "identity".
Variant applyOne(const QString &id, const QString &payload);

// Apply every transform and return one Variant each (the common "give me bypass
// variants of this payload" call), in transforms() order.
QList<Variant> process(const QString &payload);

} // namespace Nullock::Core::Processor

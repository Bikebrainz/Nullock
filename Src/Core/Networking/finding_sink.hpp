#pragma once

#include <QString>

namespace Nullock::Core {

// Where a reported finding LANDS. PassiveScanner implements it.
//
// This interface exists for a build reason as much as a design one. The APIs
// library called exactly ONE PassiveScanner method -- reportFinding, from
// ExtensionsApi::reportFinding and OastCorrelator -- but taking that as a LINK
// dependency pulled in Networking's SHARED mocs_compilation.o, which references
// every QObject in that library, including Intruder and Repeater, whose
// ProxyModel symbols resolve only inside FrontEndGUI. The practical cost was
// that nothing in APIs could be unit-tested at all: a test target linking APIs
// died with
//
//   Networking.lib(intruder.obj) : LNK2019 unresolved external symbol
//     Nullock::FrontEnd::ProxyModel::requestRawAt(int) const   (+3 more)
//
// which is why two shipped security fixes to the extension permission model had
// to ride on hand-tracing alone. A pure interface is header-only, so depending
// on it costs nothing at link time and APIs no longer links Networking.
//
// Keep this dependency-free: QString and pure virtuals only. Anything heavier
// re-creates the coupling it exists to remove.
class IFindingSink {
public:
    virtual ~IFindingSink() = default;

    // rowId 0 means "not tied to a captured history row" (extension- or
    // OAST-originated). Implementations are expected to run whatever enrichment
    // they normally would.
    virtual void reportFinding(int rowId,
                               const QString &severity,
                               const QString &kind,
                               const QString &summary,
                               const QString &evidence,
                               const QString &host,
                               const QString &url) = 0;
};

} // namespace Nullock::Core

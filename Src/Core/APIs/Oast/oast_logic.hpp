#pragma once

// Pure OAST-callback token extraction, split out of oast_server.cpp so it can be
// unit-tested against Qt6::Core alone (oast_server.cpp pulls QtNetwork). The OAST
// HTTP sink listens on a publicly reachable interface, so BOTH inputs here -- the
// Host header and the request path -- are ATTACKER-controlled (a vulnerable target
// makes the callback). This function decides which callbacks correlate to one of
// our minted tokens, so its shape contract is security-relevant: only an EXACT
// 16-hex token (from the subdomain label or the /oast/<token>/ path segment) may
// ever be accepted -- a looser match would let an attacker forge correlations.

#include "oast_origin.hpp"

#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QString>

namespace Nullock::Core::OastLogic {

// Extract a 16-hex OAST token from an inbound callback's Host header (subdomain
// form: <token>.<base-host>[:port]) or request path (/oast/<token>/...). Returns
// the lowercased token, or an empty string if neither carries an exact-16-hex
// label. Memory-safe on any input.
QString extractToken(const QString &hostHeader, const QString &path);

// ---- Correlator persistence (pure serialize / deserialize) ----------------
// Serialize the correlator's registry (token -> origin) and already-confirmed
// token set to a JSON object, and parse it back. Kept here (Core-only) so the
// round-trip is unit-testable without the QtNetwork chain. deserializeState
// REPLACES the passed containers; a malformed / wrong-version object leaves them
// empty (a corrupt persistence file must never crash or half-load, only lose the
// saved state). Round-trip stable: deserialize(serialize(x)) == x.
QJsonObject serializeState(const QHash<QString, OastOrigin> &tokens,
                           const QSet<QString> &confirmed);
void        deserializeState(const QJsonObject &obj,
                             QHash<QString, OastOrigin> &tokens,
                             QSet<QString> &confirmed);

} // namespace Nullock::Core::OastLogic

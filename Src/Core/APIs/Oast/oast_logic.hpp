#pragma once

// Pure OAST-callback token extraction, split out of oast_server.cpp so it can be
// unit-tested against Qt6::Core alone (oast_server.cpp pulls QtNetwork). The OAST
// HTTP sink listens on a publicly reachable interface, so BOTH inputs here -- the
// Host header and the request path -- are ATTACKER-controlled (a vulnerable target
// makes the callback). This function decides which callbacks correlate to one of
// our minted tokens, so its shape contract is security-relevant: only an EXACT
// 16-hex token (from the subdomain label or the /oast/<token>/ path segment) may
// ever be accepted -- a looser match would let an attacker forge correlations.

#include <QString>

namespace Nullock::Core::OastLogic {

// Extract a 16-hex OAST token from an inbound callback's Host header (subdomain
// form: <token>.<base-host>[:port]) or request path (/oast/<token>/...). Returns
// the lowercased token, or an empty string if neither carries an exact-16-hex
// label. Memory-safe on any input.
QString extractToken(const QString &hostHeader, const QString &path);

} // namespace Nullock::Core::OastLogic

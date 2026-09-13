#pragma once

#include "header_audit.hpp"
#include <optional>

namespace Nullock::Core::HeaderAudit {

// Internal aggregate analysis for multiple serialized CSP policies. URL-source
// findings concern parser-inserted scripts without a matching nonce/integrity.
void auditCspIntersection(const QStringList &policies, bool reportOnly,
                          const QUrl &origin, bool tls, Result &result);
std::optional<bool> cspFrameAncestorsProtective(const QStringList &policies, const QUrl &origin, bool tls);

} // namespace Nullock::Core::HeaderAudit

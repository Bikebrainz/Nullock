#pragma once

// Extension permission model (capability gate). Nullock JS extensions run in a
// shared QJSEngine that itself has no filesystem or network access -- but the
// `nullock` bridge lets an extension MUTATE upstream requests (onRequest) and
// mutate responses (onResponse's return value). Those are the dangerous
// capabilities: an untrusted marketplace extension could silently rewrite auth
// headers or tamper with content. This module decides, from a declared
// permission set, whether an extension may hold such a capability -- DEFAULT
// DENY for the dangerous ones, so an extension that doesn't ask can't mutate.
//
// PURE: strings in, a decision out. Qt6::Core only.
//
// An extension declares its permissions with a header-comment directive, e.g.
//     // nullock:permissions modify-requests, modify-responses
//     // @nullock-permissions onRequest
// (case-insensitive, comma/space separated). Aliases: onRequest ->
// modify-requests; onResponse-mutate / modify-response -> modify-responses.
// Observation, logging, and reportFinding are always allowed and need no grant.

#include <QSet>
#include <QString>

namespace Nullock::Core::ExtensionPerms {

// Canonical dangerous capabilities that require an explicit grant.
inline const QString kModifyRequests  = QStringLiteral("modify-requests");
inline const QString kModifyResponses = QStringLiteral("modify-responses");

// Parse a permission declaration from an extension's JS source. Returns the
// canonical granted-capability set (empty if there's no directive). Only the
// first kMaxScan chars are scanned so a huge file can't stall.
QSet<QString> parsePermissions(const QString &jsSource);

// Does `capability` require an explicit grant (i.e. is it a dangerous one)?
bool requiresGrant(const QString &capability);

// May an extension with `granted` hold `capability`? A grant-requiring
// capability is allowed only when present in `granted`; everything else is
// always allowed.
bool isAllowed(const QSet<QString> &granted, const QString &capability);

} // namespace Nullock::Core::ExtensionPerms

#pragma once

// Pure recon helpers, split out of the ReconEngine QObject so they can be
// unit-tested against Qt6::Core alone (ReconEngine pulls QDnsLookup/QObject/
// QtConcurrent). Deterministic functions over names / IP lists -- no I/O.

#include <QString>
#include <QStringList>

namespace Nullock::Core::ReconLogic {

// Canonicalize a crt.sh name_value token: trim, lowercase, and strip ALL leading
// "*." wildcard labels ("*.*.example.com" -> "example.com"). The old single strip
// left a residual "*." that entered results as a literal wildcard "subdomain".
QString cleanName(QString s);

// Should a cleaned crt.sh name be reported as a discovered SUBDOMAIN of `domain`?
// Requires: in scope (a strict subdomain of `domain`), NOT the apex itself (a
// wildcard cert "*.example.com" collapses to the apex -- not a subdomain), and
// no residual wildcard character (a partial wildcard like "d*.example.com" is a
// cert-coverage pattern, never a resolvable host).
bool acceptCertName(const QString &cleaned, const QString &domain);

// Does a DNS answer record's owner name belong to the FQDN we asked for? Guards
// against OS search-domain suffix expansion injecting a different host's record.
// (A deeper name via a legitimate CNAME chain is accepted -- that IS the address
// the asked name resolves to.)
bool recordMatchesQuery(const QString &recordName, const QString &askedName);

// Is a wordlist candidate's resolution merely WILDCARD synthesis rather than a
// distinct host? True iff the candidate resolved (non-empty) and EVERY one of its
// addresses is in the domain's wildcard answer set -- a real distinct host has at
// least one address the wildcard doesn't. An empty wildcard set (no wildcard DNS)
// => always false (no filtering). Used to suppress the wildcard false positive
// where "*.example.com A 1.2.3.4" makes every candidate resolve.
bool isWildcardResolved(const QStringList &candidateIps, const QStringList &wildcardIps);

} // namespace Nullock::Core::ReconLogic

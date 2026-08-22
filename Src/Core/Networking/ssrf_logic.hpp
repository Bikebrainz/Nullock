#pragma once

#include "ssrf_scan.hpp"   // for SsrfScan::Request

#include <QByteArray>
#include <QString>

// Pure request-building logic for the SSRF scanner, split out of ssrf_scan.cpp
// so a unit test can link it against Qt6::Core alone (ssrf_scan.cpp's test()
// pulls HttpClient / the Networking I/O stack). The module header already
// promises it is "dependency-free so it is fully CI-regression-testable" -- this
// makes the request builder actually reachable from a test.
namespace Nullock::Core::SsrfScan {

// Serialize the raw HTTP request bytes for an SSRF probe. PURE (no I/O).
//
// Returns {} (empty) if a REQUEST-LINE / Host field (method, basePath, OR host)
// carries a CR or LF: those three are written RAW into the request line and the
// Host header, so an unescaped CR/LF would inject a header or split the request.
// `query` is already percent-encoded by the caller (QUrlQuery FullyEncoded), so
// it is appended as-is. Custom req.headers whose name or value carries CR/LF are
// SKIPPED individually (the request is still built); Host and Content-Length
// custom headers are dropped (Host is emitted from req.host, Content-Length is
// omitted for these bodyless probes).
QByteArray buildRequest(const Request &req, const QString &query);

// The FAIL-CLOSED confirmation gate for an SSRF hit. A probe only reports after a
// same-shape, non-fetchable "control" request has proven the signature tracks a
// FETCH and not the input shape (an error/WAF/echo template). Given whether that
// control request SUCCEEDED (`controlOk`) and whether it REPRODUCED the signature
// (`controlReproducedSig`), returns true only when the control ran cleanly AND
// did not carry the signature -- i.e. the finding is fetch-proven. A FAILED
// control leaves the FP defeater unrun and must NOT license a finding, so this
// returns false (suppress) rather than fail open. PURE (no I/O).
bool controlProvesFetch(bool controlOk, bool controlReproducedSig);

// The full per-probe SSRF CONFIRMED verdict (pure). A hit is real only when:
//   - the signature is NOT already served on the benign baseline (else it is
//     served unconditionally and proves no fetch -- the baseline-absence FP guard);
//   - the probe transported AND carried the signature (the detection); and
//   - the shaped control proves a fetch (controlProvesFetch: ran AND did not
//     reproduce the signature).
// `baseHasSig` = the baseline body already contained the signature. Only
// controlProvesFetch was previously unit-tested; the composition (the baseline
// guard + detection) was inline in scan()'s confirm lambda. PURE (no I/O).
bool ssrfConfirms(bool baseHasSig, bool probeOk, bool probeHasSig,
                  bool controlOk, bool controlReproducedSig);

// Does the IMDS security-credentials listing body look like a bare IAM ROLE
// name (gating the deeper two-step credential fetch that yields the CRITICAL
// aws-imds-iam AccessKeyId finding)? Non-empty, <= 128 chars, and free of the
// space / '<' / '{' that mark an error page or JSON envelope rather than a role.
// Must NOT reject legal AWS role characters (letters, digits, and +=,.@_-).
// Was inline in scan(); a too-strict regression silently misses real credential
// exposure, a too-loose one issues a follow-up to an attacker-shaped path. PURE.
bool isRoleLike(const QString &role);

} // namespace Nullock::Core::SsrfScan

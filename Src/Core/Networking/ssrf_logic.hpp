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

} // namespace Nullock::Core::SsrfScan

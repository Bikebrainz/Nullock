#pragma once

#include "http3_detect.hpp"   // Request, AltProtocol

#include <QByteArray>
#include <QList>
#include <QString>

// Pure request-building + Alt-Svc parsing for the HTTP/3 detection probe, split
// out of http3_detect.cpp so a unit test can link it against Qt6::Core alone
// (http3_detect.cpp's detect() pulls HttpClient / the Networking I/O stack).
namespace Nullock::Core::Http3Detect {

// Serialize the probe GET request bytes. PURE.
//
// Returns {} (empty) if req.host, req.path, or req.query carries a CR or LF:
// req.path/req.query form the request-line target and req.host the Host header,
// all written RAW below. An unescaped CR/LF in the target injects a header or
// splits the request line on the ALREADY-ESTABLISHED connection (keyed on the
// clean host), which is the more directly reachable vector; a CR/LF host is
// usually stopped earlier by DNS resolution failing, but is guarded too for
// consistency. Custom req.headers with CR/LF in the name or value are skipped
// individually; a custom Host header is dropped (Host comes from req.host).
QByteArray buildGet(const Request &req);

// True if an Alt-Svc protocol-id names HTTP/3: exactly "h3", or "h3-<draft>"
// (h3-29, h3-Q050, ...). Anchored on the '-' so "h3x" / "h2" do NOT match.
bool looksHttp3(const QString &id);

// Parse one RFC-7838 Alt-Svc field value (comma-separated protocol-id=authority
// with optional ; ma=N / ; persist=1 params) into protocol entries. "clear"
// yields none. Memory-safe on arbitrary attacker response bytes.
QList<AltProtocol> parseAltSvc(const QString &value);

} // namespace Nullock::Core::Http3Detect

#pragma once

// HTTP request smuggling / desync (CWE-444: Inconsistent Interpretation of HTTP
// Requests). When a front-end and back-end disagree on where a request ends --
// one trusting Content-Length, the other Transfer-Encoding -- an attacker
// prepends bytes onto the next user's request: credential theft, cache
// poisoning, auth bypass. We detect it the safe, reliable way (Albinowax timing
// technique): craft a CL.TE and a TE.CL payload whose ambiguity makes a
// vulnerable back-end block waiting for body bytes that never arrive, and flag
// the variant whose response is dramatically delayed versus a baseline. The
// delay must REPRODUCE on a re-send, and a valid-but-ambiguous control request
// must NOT also stall -- otherwise the server merely tarpits ambiguous input
// (not a real framing desync) and we suppress, to avoid a false critical.
//
// The probes carry Connection: close. That is a deliberate safety choice: the
// torn-down connection means the stranded bytes can't prepend onto a real
// user's request on a pooled connection. The trade-off is reduced sensitivity
// (a chain that only desyncs under keep-alive may be missed) -- we prefer a
// false negative over ever smuggling into production traffic.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::Smuggling {

struct Hit {
    QString variant;     // "CL.TE" | "TE.CL"
    int     delayMs = 0; // observed delay over baseline
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    int     baselineMs = 0;
    int     requestsSent = 0;
    QString error;
};

// Time a baseline request, then the CL.TE and TE.CL timing probes; flag any
// whose delay over baseline exceeds the threshold AND reproduces on a re-send.
Result test(const Request &req);

// --- Pure request builders, exposed for the unit test (in smuggling_logic.cpp) ---
// Byte-exact: a wrong Content-Length / chunk silently makes the probe inert.
// All four return {} when basePath/host carry CR/LF (a framing hazard for a
// smuggling probe).
QByteArray baselineRequest(const Request &req);
QByteArray clteProbe(const Request &req);
QByteArray teclProbe(const Request &req);
QByteArray ambiguousControl(const Request &req);

} // namespace Nullock::Core::Smuggling

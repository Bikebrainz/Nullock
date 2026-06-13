#pragma once

// CRLF / HTTP response splitting (CWE-113: Improper Neutralization of CRLF in
// HTTP Headers). When user input reaches a response header -- a redirect
// Location, a reflected Set-Cookie, a custom header -- without stripping CR/LF,
// an attacker injects their own header lines and even a response body: cache
// poisoning, a forced Set-Cookie (session fixation), or reflected XSS in the
// split body. We confirm it unambiguously: inject an encoded CRLF plus a
// uniquely-named marker header and check whether that header actually appears
// in the parsed response -- the server split the header, no guessing.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::CrlfInjection {

struct Hit {
    QString param;       // parameter the payload went into
    QString technique;   // "crlf", "lf-only", "double-encoded", "unicode", ...
    QString payload;     // the raw (URL-encoded) value injected
    QString evidence;    // the injected header that came back
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QString param;                              // param to test; empty => auto
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    QStringList testedParams;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject CRLF-bearing payloads into the target parameter(s) and flag any that
// land an attacker-controlled header in the response. If `param` is empty,
// every existing query parameter is tried (capped), or a small default set.
Result test(const Request &req);

QStringList defaultParams();

} // namespace Nullock::Core::CrlfInjection

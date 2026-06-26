#pragma once

// Reflected cross-site scripting (CWE-79). User input echoed into a response
// without context-correct encoding lets an attacker inject markup that runs in
// the victim's session. We confirm it conservatively: inject a random-marker
// tag and flag ONLY when (a) the response is HTML, (b) the angle brackets come
// back UNENCODED, and (c) the reflection sits in executable element content --
// not inside a comment, a raw-text element (script/style/textarea/...), or an
// attribute value, where the brackets are inert. An entity-encoded reflection
// (&lt;…&gt;) or a JSON/text response never matches, so findings are real.
// Scope: element-content injection; quote-only attribute breakout (where '<'
// is encoded but the delimiter quote isn't), DOM-based, and stored XSS are out
// of scope for this reflected check.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::XssReflected {

struct Hit {
    QString param;       // parameter the payload went into
    QString context;     // "html" (executable element content)
    QString payload;     // the injected value (decoded)
    QString evidence;    // the raw reflected marker found
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;
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

// Inject context-breakout marker payloads into the target parameter(s) and
// flag any whose marker reflects unencoded. If `param` is empty, existing
// query params are tried (capped), else a small default set.
Result test(const Request &req);

QStringList defaultParams();

// Exposed for tests (pure logic; live in xss_logic.cpp):
//   isHtmlContentType  -- is a lower-cased Content-Type browser-executable HTML?
//   inExecutingHtmlContext -- is the marker at `at` in runnable element content?
//   buildRequest -- render the GET, stripping CR/LF from method/host/path/query
//                   and dropping any CR/LF-bearing carried header.
//   queryWith -- set `param` to `value` (percent-encoded), preserving others.
bool isHtmlContentType(const QString &contentTypeLower);
bool inExecutingHtmlContext(const QString &body, int at);
QByteArray buildRequest(const Request &req, const QString &query);
QString queryWith(const QString &existing, const QString &param, const QString &value);

} // namespace Nullock::Core::XssReflected

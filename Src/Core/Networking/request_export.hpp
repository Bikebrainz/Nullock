#pragma once

// Reproduce a captured request in other forms -- pure string transforms,
// no network. Lives in Core so it's unit-testable (it was originally inline
// in control_server). Backs /api/csrf/poc and /api/request/curl.

#include <QString>
#include <QList>
#include <QPair>

namespace Nullock::Core::RequestExport {

// Auto-submitting HTML CSRF PoC (Burp "Generate CSRF PoC" equivalent).
// Picks a form (GET / x-www-form-urlencoded), a multipart scaffold, or a
// credentialed fetch() (JSON / other) based on the content-type. All
// attribute values are HTML-escaped; the fetch body is JS-string escaped
// (incl. '<') so the PoC cannot be malformed or break out of <script>.
// `note` receives a human-readable caveat about the chosen technique.
QString csrfPoc(const QString &method, const QString &url,
                const QString &contentType, const QString &body, QString &note);

// Reproduce a request as a runnable curl command: -X only when needed,
// every value single-quote shell-escaped, captured headers included
// (Host / Content-Length / HTTP-2 pseudo-headers skipped), --data-raw body.
QString curlCommand(const QString &method, const QString &url,
                    const QList<QPair<QString, QString>> &headers,
                    const QString &body);

} // namespace Nullock::Core::RequestExport

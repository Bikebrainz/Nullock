#pragma once

// Insecure deserialization (CWE-502, OWASP A08:2021). An endpoint that feeds
// attacker-controlled bytes to a native deserializer (Java ObjectInputStream,
// PHP unserialize, Python pickle, Ruby Marshal, .NET BinaryFormatter) is a
// remote-code-execution primitive via gadget chains.
//
// The passive scanner already flags when an app TRANSPORTS serialized blobs
// (rO0.../gAS.../O:.../BAh.../AAEAAAD... signatures in cookies, params, bodies).
// This is the ACTIVE half: confirm the endpoint actually DESERIALIZES the input.
//
// Confirmation is a WELL-FORMED-vs-MALFORMED differential, which is sound where
// a naive "benign value must not error" gate is not (a real deserializer errors
// on ANY non-serialized value, so that gate would suppress true positives). For
// each format we send a benign WELL-FORMED serialized object (a String, or the
// integer 1) and a MALFORMED one of the same format:
//   - a real deserializer ACCEPTS the well-formed object (no parse error) and
//     ERRORS on the malformed one (StreamCorruptedException, "Error at offset",
//     UnpicklingError, "marshal data too short", ...)  -> CONFIRMED;
//   - a shape-keyed WAF/blocklist errors on BOTH (it sniffs the magic, never
//     deserializes), so the well-formed control errors too -> not flagged;
//   - an echo/store sink errors on NEITHER -> not flagged.
// The well-formed object is inert and the malformed one references only a
// non-existent canary class, failing before any user gadget (__wakeup/readObject
// /REDUCE) runs -- a detection canary, never a weaponized gadget. (Java/Python/
// Ruby truncate during header/descriptor parse, before any class is resolved;
// PHP's O: token does look up the named -- nonexistent -- canary class and
// build an incomplete-class object, but still errors before __wakeup.)
//
// Scope (in-band, error-based): payloads ride the QUERY STRING (default), the
// RAW REQUEST BODY (location="body", the application/x-java-serialized-object
// sink), a named COOKIE (location="cookie", the Shiro/Spring rememberMe and Ruby
// Marshal-session class), or a named POST FORM FIELD (location="field", the .NET
// __VIEWSTATE / unserialize($_POST[...]) class). What it still can't see: a
// deserializer that SWALLOWS errors (display_
// errors off, custom 500) or a Java readObject gadget that fires server-side
// with no trace -- blind/OOB deserialization (URLDNS gadget -> OAST
// callback) is a separate OAST-backed probe. A clean result does not rule out
// CWE-502.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::DeserProbe {

struct Hit {
    QString param;     // the parameter the malformed stub went into
    QString format;    // confirmed engine: "Java" | "PHP" | "Python" | "Ruby" | ".NET"
    QString payload;   // the stub injected
    QString evidence;  // the deserialization-error fragment matched
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QString query;                              // existing query (encoded)
    QString param;                              // param to test; empty = auto-detect
    QString location;                           // "" / "query" (default) | "body" (raw request body)
    QString contentType;                        // body mode: override the per-format Content-Type
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QStringList testedParams;
    bool    vulnerable = false;
    QList<Hit> hits;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// Inject the malformed-stub battery into the named param (or each query param /
// the defaults if empty). Confirms only on a format-specific deserialization
// error absent from the baseline and not reproduced by a benign value.
Result test(const Request &req);

// Parameter names commonly carrying a serialized blob.
QStringList defaultParams();

// Map a confirmed engine label to its finding kind (deser-java, deser-php, ...).
QString kindForFormat(const QString &format);

} // namespace Nullock::Core::DeserProbe

#pragma once

// Client-side secret exposure (CWE-798: Use of Hard-coded Credentials). Front-
// end bundles routinely ship credentials that were only ever meant for the
// server: cloud keys, payment-provider secrets, CI tokens, even private-key
// blocks. We fetch a page and its same-origin scripts and scan for high-signal
// provider key shapes plus assigned high-entropy secrets, masking the match so
// the finding locates the leak without re-exposing it. Burp Community doesn't
// hunt secrets in JS; this is the truffleHog/gitleaks capability, in-line.

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::SecretScanner {

struct Hit {
    QString type;       // "aws-access-key-id", "stripe-secret-key", ...
    QString severity;   // low | medium | high | critical
    QString location;   // url the secret was found in
    QString masked;     // e.g. "AKIA…7E (len 20)"
    QString context;    // short surrounding snippet (also masked)
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QString query;
    QList<QPair<QString, QString>> headers;
    bool    followScripts = true;   // also fetch & scan same-origin <script src>
    int     maxScripts = 12;
};

struct Result {
    QList<Hit> hits;
    int     resourcesScanned = 0;
    int     requestsSent = 0;
    QString error;
};

// Fetch the URL (and, when followScripts, its same-origin scripts) and scan
// every body for exposed secrets. Matches are de-duplicated by type+value.
Result scan(const Request &req);

} // namespace Nullock::Core::SecretScanner

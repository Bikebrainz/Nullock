#pragma once

// Client-side secret exposure (CWE-798: Use of Hard-coded Credentials). Front-
// end bundles routinely ship credentials that were only ever meant for the
// server: cloud keys, payment-provider secrets, CI tokens, even private-key
// blocks. We fetch a page and its same-origin scripts and scan for high-signal
// provider key shapes plus assigned high-entropy secrets, masking the match so
// the finding locates the leak without re-exposing it. Burp Community doesn't
// hunt secrets in JS; this is the truffleHog/gitleaks capability, in-line.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QUrl>

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

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// detection + filtering logic against Qt6::Core alone.

double  shannon(const QString &s);

// Obvious non-secrets (documented EXAMPLE keys, your-/placeholder/sample,
// long single-char runs, ${...} interpolation). Now applied to EVERY match,
// not just the entropy-gated generic rule.
bool    looksPlaceholder(const QString &v);

// Accept a candidate secret: never a placeholder, and (for the generic
// entropy-gated rule) high-entropy. This is the per-match filter.
bool    acceptSecret(const QString &value, bool entropyGated);

// Mask a secret for display (never echoes the full value).
QString mask(const QString &secret);

// Scan one body for secrets (pure: regex table + acceptSecret + masking).
QList<Hit> scanText(const QString &body, const QString &location);

// Same-origin <script src> paths from an HTML body.
QStringList sameOriginScripts(const QString &body, const QUrl &base, int cap);

// Build the GET. Returns empty if host or path carries a CR/LF.
QByteArray buildGet(const Request &req, const QString &path, const QString &query);

// Cap on the bytes scanned per resource (a large minified bundle could
// otherwise pin a core across the regex table).
int maxScanBytes();

} // namespace Nullock::Core::SecretScanner

#pragma once

// Sensitive file / path exposure scanner. Probes a curated set of high-value
// paths (.git/config, .env, phpinfo.php, server-status, config backups, Spring
// Actuator, AWS creds, .DS_Store) and confirms each by a CONTENT signature, not
// a bare 200 -- so a catch-all server that 200s everything doesn't false-
// positive. Read-only GETs; identification, not exfiltration (the finding names
// the file, it doesn't dump its contents).

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::ExposureScan {

struct Hit {
    QString path;
    QString severity;
    QString summary;
    int     status = 0;
    QString evidence;    // the matched signature fragment
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePrefix = QStringLiteral("");   // optional path prefix
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QList<Hit> hits;
    int     probed = 0;
    bool    catchAll = false;   // a bogus path returned 2xx -> server 200s everything
    QString error;
};

// Probe the curated sensitive paths and return the confirmed exposures.
Result scan(const Request &req);

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// signature table + matcher against Qt6::Core alone.

struct Signature {
    QString path;
    QString pattern;        // content signature (regex) confirming exposure
    QString severity;
    QString summary;
    bool caseSensitive = false;  // .env keys are uppercase by convention -> match case-sensitively
    bool rejectHtml = false;     // a plain-text/binary config file is never the HTML app shell
    int  minMatches = 1;         // require N distinct matches (defeats a single coincidental line)
    bool redact = true;          // mask the matched content in evidence (file is named, not dumped)
};

const QList<Signature> &signatures();

// A short, regex-inert token for the bogus-path soft-404 calibration request.
QString randTok();

// Does the body look like an HTML document (the app shell / soft-404 page)?
bool looksHtml(const QByteArray &body);

// Run one signature over a body. Returns the (possibly redacted) evidence
// fragment on a confirmed match, or empty. Honors caseSensitive / rejectHtml /
// minMatches / redact.
QString matchSignature(const QByteArray &body, const Signature &sig);

// Catch-all suppression verdict (pure): a signature that matched the real file
// body is a genuine exposure UNLESS the host also 200s a known-bogus path AND
// the SAME signature fires on that control body -- then the host serves the
// content for any path (SPA fallback / soft-404) and it isn't file-specific.
// Returns true when the hit should be SUPPRESSED. Extracted from scan()'s
// inline guard so the report-vs-suppress composition is unit-tested; it re-runs
// matchSignature on the control body, so it correctly honors rejectHtml (a
// plain-text config signature never suppresses against an HTML control shell).
bool suppressAsCatchAll(bool controlIs2xx, const QByteArray &controlBody,
                        const Signature &sig);

// Build the GET. Returns empty if host or path carries a CR/LF.
QByteArray buildGet(const Request &req, const QString &path);

} // namespace Nullock::Core::ExposureScan

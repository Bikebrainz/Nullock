#pragma once

// Content / directory discovery (CWE-538-adjacent recon). Brute-forces a
// wordlist of common paths to surface unlinked endpoints -- admin panels,
// backups, API routes, VCS dirs, config files -- that the crawler never sees
// because nothing links to them. The ffuf / dirsearch / gobuster staple.
//
// The classic dirbuster failure mode is the "soft 404": a server that answers
// 200 (a friendly error page, an SPA shell) for EVERY path, so naive 200-means-
// found flags the entire wordlist. We defend against it by calibrating first:
// request a couple of random, certainly-absent paths and learn what "not found"
// looks like (its status and body size). A candidate is then reported only when
// it deviates from that baseline -- a different status (301/302/401/403, or 200
// when the baseline 404s) or a 200 whose body size differs materially from the
// soft-404 page. Read-only GETs; identification, not exploitation.

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::ContentDiscovery {

struct Hit {
    QString path;        // the path that responded (relative to base)
    int     status = 0;
    int     size = 0;    // response body size
    QString location;    // Location header for 3xx, else empty
    QString note;        // why it is interesting (e.g. "redirect", "auth-gated")
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;                           // dir to discover under (default "/")
    QList<QPair<QString, QString>> headers;     // carried headers (cookies, auth)
    QStringList wordlist;                        // relative paths; empty => default
    int     maxRequests = 300;                   // cap on wordlist entries probed
};

struct Result {
    QList<Hit> hits;
    int     softNotFoundStatus = 0;   // calibrated not-found status (0 if uncertain)
    int     softNotFoundSize = 0;
    bool    softNotFoundIs200 = false; // server soft-404s with 200
    int     requestsSent = 0;
    QString error;
};

// Calibrate the not-found baseline, then probe each wordlist path and report
// those that deviate from it. Sets Result::error (leaving hits empty) only when
// the initial calibration request fails outright.
Result discover(const Request &req);

// A focused default wordlist of high-value paths (admin/api/backup/vcs/config).
QStringList defaultWordlist();

} // namespace Nullock::Core::ContentDiscovery

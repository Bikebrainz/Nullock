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
#include <QSet>
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
    bool    calibrationReliable = false; // both same-depth calibration probes agreed
    bool    forbiddenSaturated = false;  // a large fraction of paths came back 401/403
                                         // (likely WAF pattern-blocking) -- the
                                         // per-path "auth-gated" hits were collapsed
    bool    wordlistTruncated = false;   // the wordlist exceeded maxRequests
    int     wordsTotal = 0;              // wordlist size before any cap
    int     wordsTried = 0;              // candidate paths actually probed
    int     requestsSent = 0;
    QString error;
};

// The calibrated "not found" profile (the soft-404 fingerprint), derived from the
// random-absent-path probes and consulted by classify(). Pure data.
struct CalibProfile {
    QSet<int> softStatuses;    // status code(s) an absent path returns
    int       softLen = 0;     // representative not-found body size
    int       jitter  = 64;    // body-size tolerance band (>= 64)
    QString   softLocation;    // the soft-404 redirect target, when soft is a 3xx
    bool      reliable = false;// the two same-depth probes returned the same status
};

// Calibrate the not-found baseline, then probe each wordlist path and report
// those that deviate from it. Sets Result::error (leaving hits empty) only when
// the initial calibration request fails outright.
Result discover(const Request &req);

// A focused default wordlist of high-value paths (admin/api/backup/vcs/config).
QStringList defaultWordlist();

// --- Pure classification logic, exposed for the unit test (no I/O; in
//     content_logic.cpp, links Qt6::Core alone -- discover()'s HttpClient work
//     stays in content_discovery.cpp).
//
//   normBase           -- normalise the base dir to "" or "/sub" (no trailing
//                         slash) so base + "/" + word is always a single join.
//   classify           -- decide whether a probed response is an interesting hit
//                         given the calibration: a redirect is suppressed only
//                         when its target matches the soft-404 redirect (a real
//                         dir-redirect to a DIFFERENT Location is reported); a
//                         401/403 is suppressed only when its body size matches
//                         the soft page (a distinct forbidden resource is
//                         reported); a 200 under a 200-soft-404 server is reported
//                         only when its size deviates beyond the jitter band.
//                         Returns "" (not interesting) or a note
//                         ("ok"/"ok-distinct"/"redirect"/"auth-gated").
//   forbiddenSaturated -- a 401/403 fraction high enough to read as WAF
//                         pattern-blocking rather than many real resources.
QString normBase(const QString &p);
QString classify(int status, int bodyLen, const QString &location, const CalibProfile &cal);
bool    forbiddenSaturated(int forbiddenHits, int wordsProbed);

} // namespace Nullock::Core::ContentDiscovery

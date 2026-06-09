#pragma once

// CVE correlation. Given a framework + version (extracted from Server:
// header, X-Generator: header, body marker, etc.), look up known
// vulnerabilities. Each match becomes a finding tagged with CVE ID,
// CVSS score, and fix-version.
//
// Data source: hand-curated table of high-impact CVEs from 2023-2026.
// In v2 we'll plumb this to NVD's JSON feeds; for v1 the static
// table covers the ~30 most-exploited CVEs across the frameworks we
// fingerprint. Editable in cve_database.cpp's table() function.
//
// Burp Pro doesn't auto-correlate findings to CVE data. We do, free.

#include <QList>
#include <QString>

namespace Nullock::Core::CveDatabase {

struct Match {
    QString cveId;        // "CVE-2024-21345"
    QString summary;      // one-line description
    double  cvss;         // base score 0-10
    QString cvssVector;   // CVSS v3.1 vector
    QString affectedRange;// "< 5.7.0" / ">= 4.0, < 4.2.1"
    QString fixVersion;   // "5.7.0" / "4.2.1"
    QString reference;    // canonical advisory URL
};

// Given a framework identifier (matches the kind we use in detectors,
// e.g. "cms-wordpress", "cms-drupal", "fw-spring", "server-apache")
// and an optional version string, returns matching CVEs.
//
// Version string is parsed as semver-ish ("Drupal 10.2.5", "Apache/2.4.41",
// "WordPress 6.1.2") with a tolerant pattern. If we can't parse it, the
// whole table for that framework is returned (so the user can manually
// triage instead of getting silence).
QList<Match> lookup(const QString &kind, const QString &versionString);

// Same but takes a full HTTP response so we can sniff multiple
// fingerprint sources (Server header, X-Generator, meta tags in body).
struct HttpFingerprint {
    QString server;       // Server header value
    QString xPoweredBy;   // X-Powered-By
    QString xGenerator;   // X-Generator
    QString bodyVersion;  // version we sniffed from body
};
QList<Match> lookupByFingerprint(const QString &kind, const HttpFingerprint &fp);

} // namespace Nullock::Core::CveDatabase

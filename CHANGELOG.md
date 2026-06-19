# Changelog

All notable changes to Nullock are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Dates are when a build went out.

The public, prose version lives at
<https://bikebrainz.github.io/Nullock/changelog.html>; this file is the
developer-facing record.

## [Unreleased]

### Added
- **Web Security Academy clone — 50 labs.** `labs/01`…`labs/50`, each a
  single-file intentionally-vulnerable app mapped to a Nullock probe
  (XXE, CRLF, dangerous HTTP methods, verb tampering, cache poisoning,
  sensitive-file exposure, robots disclosure, predictable session tokens,
  web-cache deception, insecure cookie flags, missing security headers,
  SSRF-to-metadata, OAuth `redirect_uri`, credentials-in-URL, and more).
- **Version → CVE coverage** for Atlassian Confluence (incl. CVE-2023-22515,
  CVE-2023-22518, CVE-2023-22527, CVE-2022-26134) and Jira (CVE-2022-0540,
  CVE-2019-8449, CVE-2019-11581), Jenkins (CVE-2024-23897), Grafana
  (CVE-2021-43798), Apache (CVE-2021-41773/42013), nginx (CVE-2021-23017),
  jQuery, and Bootstrap — all multi-branch ranged so patched builds aren't
  false-flagged, all verified end-to-end.
- **`nullock scope`** — in/out scope management from the CLI
  (`/api/scope/in|out/add|remove`, notes, list).
- **`nullock recon`** now also queries certificate transparency (crt.sh).
- **CSRF PoC generator** — `/api/csrf/poc` + `nullock csrf-poc <row-id>`
  turns a captured request into an auto-submitting HTML PoC.
- **Copy as curl** — `/api/request/curl` + `nullock curl <row-id>`
  reproduces a captured request as a runnable curl command.
- Permanent regression suites for the CVE database, the finding enricher,
  and the request-export transforms; all four test suites now run in CI on
  every push.

### Changed / Fixed
- **CVE database accuracy audit.** Web-verified every entry against
  NVD/vendor advisories; corrected ~11 entries (per-branch ranges that
  false-positived patched builds, wrong CVSS scores, mislabeled vulns) and
  removed 3 bogus/false-positive entries.
- **Finding enricher coverage.** ~53 of 97 emitted finding kinds were
  shipping with empty CWE/OWASP; added family-prefix fallbacks + a generic
  last-resort so every finding is enriched.
- **CI restored to green.** The Windows build had been failing at the Qt
  install step (`qtquickcontrols2` is not a Qt 6 aqt module); fixed, wired
  the regression suites into the pipeline, and re-synced the marketplace
  docs mirror.

## [3.6.0] — 2026-06-17
The platform release: a network scanning + reporting + recon suite.
Port-scan → findings bridge, recon → vuln pipeline (`nullock pipeline`),
WAF/CDN and robots/sitemap recon, a live CVE-feed overlay (`nullock cvefeed`),
and engagement reporting — HTML (A–F grade), JSON bundle, CycloneDX SBOM,
OWASP/compliance coverage, asset inventory, posture grade, baseline diff.
Each feature shipped with an adversarial review and a regression test.

## [3.5.0] — 2026-06-11
The active-testing climb: a full battery of injection, access-control, and
misconfiguration scanners (SQLi error + blind, NoSQLi, XXE, SSTI, OS cmd-i,
reflected XSS, CRLF, LFI/path-traversal, IDOR/BOLA, mass assignment, active
CORS, verb tampering, open redirect, web cache poisoning + deception,
header/CSP audit, secret scanning, request smuggling), plus identification
modules (service→CVE, TLS inspection, fingerprint, HTTP methods, subdomain
takeover, sensitive-file exposure) and **ScopeGuard** — one authorization
gate on every active test. HTTP-client correctness fixes throughout.

## [3.4.0] — 2026-06-11
Active testing & API-security: OAST auto-correlation + active OOB blast +
DNS sink, hidden-parameter mining, IDOR/BOLA, mass assignment, active CORS
exploitability. Each with adversarial review and false-positive guards.

## [3.3.0] — 2026-06-09
The "above the paid tools" release: CVE correlation, GraphQL attack probes,
DOM-XSS taint analysis, Repeater chains, and a JWT attack toolkit. Every
finding gained CWE / OWASP Top-10 2021 / CVSS v3.1 / one-line fix tags.

## [3.2.0] — 2026-06-02
Repeater side-by-side response diff with byte-level highlighting; streaming
scoped history export; SQLite write batching (~40% less capture overhead at
200k rows).

## [3.1.4] — 2026-05-18
Linux CA install fix under Wayland; match-and-replace empty-body fix;
`nullock vacuum` to compact history.

## [3.1.0] — 2026-04-29
Python extensions alongside JS; full-text search over request/response
bodies; glob scope syntax; large-response streaming leak fix.

## [3.0.0] — 2026-03-11
First native desktop release: cross-platform Qt6/C++20 app over the same
control server the CLI drives, SQLite-backed history (200k+ rows), config
under `~/.nullock/`.

[Unreleased]: https://github.com/Bikebrainz/Nullock/compare/v3.6.0...Nullock

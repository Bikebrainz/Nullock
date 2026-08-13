# Nullock

[![Release](https://img.shields.io/github/v/release/Bikebrainz/Nullock?color=9d4edd)](https://github.com/Bikebrainz/Nullock/releases/latest)
[![CI](https://github.com/Bikebrainz/Nullock/actions/workflows/ci.yml/badge.svg?branch=Nullock)](https://github.com/Bikebrainz/Nullock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![C++20 / Qt6](https://img.shields.io/badge/C%2B%2B-20%20%2F%20Qt6-00599C?logo=cplusplus&logoColor=white)

**FOSS web security toolkit.** MITM proxy + repeater + intruder + scanner + OAST + GraphQL/JWT tooling + AI-assisted payload generation. Self-host-first. No telemetry. MIT licensed.

[Download](https://github.com/Bikebrainz/Nullock/releases/latest) · [Docs](https://bikebrainz.github.io/Nullock/docs/index.html) · [Marketplace](https://bikebrainz.github.io/Nullock/marketplace/) · [Discussions](https://github.com/Bikebrainz/Nullock/discussions)

---

## What's in the box

```
Proxy             HTTP/1.1 + HTTP/2 + WebSocket, native frame visibility, intercept queue with
                  pivot-to-Repeater/Intruder/Comparer and one-click response-modification presets;
                  WS Repeater overlay injects text/binary/close/ping/pong frames into a live
                  WebSocket tunnel by session, direction, and opcode, with one-click resend-last;
                  H2 Frame Log overlay shows a per-stream summary table and a live-tailing raw
                  HTTP/2 frame feed (type/flags/bytes) on either MITM leg -- a frame-level view
                  Burp doesn't have at all;
                  HTTP history/Site map filter bar -- scope/params/404 chips, MIME class, extension
                  show/hide, case-sensitive toggle, and negative ("-term") search; a DB Search
                  overlay queries the SQLite-backed history index directly (method/host/path/
                  status/size/since filters) so a row can be found and its full raw request/
                  response opened even after it has scrolled out of the bounded on-screen window
Repeater          Multi-tab, send-from-history, edit-and-resend, request chains, Pretty view
                  auto-indents JSON/XML/HTML bodies, per-tab NOTES for tracking what each
                  tab is testing, AUTO-CL recomputes Content-Length from the edited body on
                  send (on by default; toggle off from the GUI to hand-craft a CL/TE desync)
Intruder          Sniper / Battering Ram / Pitchfork / Cluster Bomb via a GUI mode picker with a
                  per-position payload-set editor, a live-preview payload generator (numbers/dates/
                  brute-forcer/null/frobber/blocks/casemod/charsub/bitflip), a payload-processing rule chain (prefix/suffix/case/reverse/
                  match-replace/encode/decode/hash), sortable + filterable results, rate-limit-aware
Passive scanner   Header/cookie/secret/info-leak findings, every one CWE/OWASP/CVSS-enriched
Findings          ISSUES tab: flat or grouped-by-kind+host view (instance count, max CVSS, CWE/
                  OWASP rollup); a Baseline bar saves/diffs/clears a findings snapshot for
                  scan-to-scan delta (new vs fixed vs unchanged); a per-finding Triage button asks
                  a local Ollama model (falls back to a heuristic verdict) for impact/fix/
                  false-positive assessment -- all three were API-only before this; clicking a
                  finding opens an inline Advisory/Request/Response detail pane (CWE/OWASP/CVSS/
                  compliance/fix guidance, plus the underlying raw request/response with the
                  scanner's evidence string highlighted) instead of jumping straight to Proxy
Active scanner    SQLi (error + blind/time), NoSQLi, LDAP + XPath injection, XXE, SSTI, OS cmd-i,
                  CRLF, path traversal, reflected XSS, IDOR, verb tampering, open redirect, CORS,
                  mass assignment, SSRF (cloud-metadata/file/internal, fetch-proven), insecure
                  deserialization (Java/PHP/Python/Ruby/.NET), active JWT attacks (alg:none /
                  signature-not-verified / weak-secret / RS256->HS256 confusion), cross-site WebSocket hijacking,
                  host-header injection, server-side prototype pollution, security-header/CSP audit,
                  web cache poisoning + deception, dangerous HTTP methods, sensitive-file exposure
                  (curated .git/.env/actuator/backup paths, confirmed by content signature -- SCANS tab),
                  HTTP request smuggling, race conditions
Version -> CVE    Active fingerprint + service-banner version detection correlated to a curated CVE
                  database (WordPress/Drupal/Joomla/Confluence/Jira/Jenkins/Grafana/Elasticsearch/Kibana/Tomcat/PHP/...),
                  with multi-branch ranges so patched builds aren't flagged; runtime NVD feed overlay
                  (push entries directly for air-gapped use, or sync a JSON feed URL -- SCANS tab's
                  "CVE overlay" section); network-service banner-grab + CVE correlation reachable
                  from the SCANS tab
JS recon          Mines same-origin JS bundles for API endpoints, hardcoded secrets, and exposed
                  source maps -- SCANS tab
Recon             Port/CIDR sweeps (with nmap XML import for scans run outside Nullock, and a
                  one-click bridge promoting scan results into the shared findings list), DNS,
                  WHOIS, cert transparency, wordlist enum, robots/sitemap, WAF/CDN detection,
                  subdomain-takeover fingerprints, HTTP/3 (Alt-Svc) readiness probe -- SCANS
                  tab, scope-gated BFS crawler
Discovery         In-app content/directory brute-force (soft-404 calibrated), robots.txt + sitemap
                  recon, and start/stop control for the BFS crawler -- results feed Proxy history + Issues
TLS audit         Certificate + protocol/cipher inspection (expired/self-signed/weak-key/legacy proto) --
                  SCANS tab
OAST              In-process HTTP + DNS callback sinks for out-of-band confirmation -- one blast
                  confirms blind SSRF, RCE (OS command injection), XXE, and Log4Shell (jndi/DNS);
                  plus a deployable standalone server (nullock-oast) for a public / hosted tier.
                  Self-hosted Collaborator client tab: mint callback URLs, poll for HTTP
                  interactions, inspect hit detail (source IP, headers, body preview), and
                  fire the SSRF/XXE/RCE/Log4Shell blast at a target URL from a Blast panel
Orchestration     One-call host assessment + recon->vuln pipeline (point-at-host -> findings);
                  in-app SCANS tab drives target assess, synchronous audit-run, param miner,
                  multi-step request chains, exposure scan, service CVE correlation, JS recon,
                  TLS/certificate inspection, and the pipeline orchestrator, plus on-demand
                  posture grade / asset inventory /
                  OWASP-compliance coverage / CI-gate rollups -- all previously API-only
Template scanner  Nuclei-style detection templates (JSON or real nuclei .yaml): matchers + extractors
                  + request crafting with {{payload}} expansion; bundled starter library, hits feed the gate --
                  in-app "Detection templates" section (SCANS tab): pick a bundled template or paste a
                  custom JSON one, run against a target URL
CI security gate  Headless one-shot scan (NullockApp --scan URL --fail-on high -> nonzero exit) +
                  GET /api/gate pipeline pass/fail; composite GitHub Action + reference Dockerfile
Reporting         Markdown / styled HTML / JSON reports, posture grade, OWASP + compliance coverage,
                  asset inventory; in-app REPORTING tab also drives OpenAPI export/import, SBOM
                  download, and workspace push/pull (findings baseline/diff lives in ISSUES, see Findings)
Session rules     Auto-extract CSRF/JWT/nonces and re-inject (Burp macros equivalent); a named,
                  individually enable/disable-able rules editor lives in the SESSIONS tab
                  (host/path glob, extract-from header/cookie/JSON-path/regex, inject-into
                  header/cookie/body/URL) alongside the captured variable bag
Sequencer         Statistical randomness analysis of session tokens (Burp Sequencer equivalent);
                  in-app SEQUENCER tab -- paste/load-from-file/clipboard manual load with a
                  pre-analysis sample summary, full results (entropy, char class, hamming, LCS,
                  sequential-counter detection incl. wrapped counters (sess_1001, user-42) with
                  the recovered step, per-position + FIPS 140-2 bit-level tests where
                  applicable), plus sample-size guidance -- warns under ~100 tokens and flags the
                  20,000-bit FIPS conformance threshold
Extensions        JS plugin API, onRequest/onResponse hooks, marketplace catalog; an "Install
                  bundled" button in Settings copies the extensions shipped with the repo into
                  the user's extensions dir in one click
Decoders          JWT (security-annotated) + forge, base64, hex, JSON transcode; "Send to Decoder"
                  pivots from Proxy history/Site map (request/response), Repeater's request/response
                  panes, and the Intercept queue seed the Decoder tab's input directly
Inspector         Structured view of any request/response -- headers, cookies, query/body params, decoded JWTs;
                  docked live in Repeater, Proxy history, and Intruder's template editor, not just its own tab.
                  A Selection widget section shows highlighted-text character count and the first byte's
                  decimal/hex value, labelling non-printing bytes (\n/\t/\r/space) instead of hiding them.
                  JWT TOOLKIT mode: offline decode/weakness-analyze/HS*-secret-brute-force, alg:none and
                  HS256-resign/algorithm-confusion forging, and a live calibrated acceptance test against a
                  target -- active JWT auth-bypass testing Burp only offers via a paid extension
GraphQL toolkit   In-app PROBE tab: schema introspection with dangerous-mutation + sensitive-field
                  flagging, plus an active probe suite (introspection/field-suggestion/alias-amplification/
                  depth-bypass/batch-bypass) -- findings feed Issues like every other active test
Active tests      25 on-demand checks (SQLi/XSS/SSRF/SSTI/IDOR/XXE/...) launchable per-URL from the app, findings feed Issues
Deep audit sweep  One-click "Deep audit all rows" runs the full battery (cmdi/xxe/ldap/xpath/
                  smuggle/hostheader/cache-poison/deser/nosql/mass-assign/cors) against every
                  captured history row with params or a body, throttled, off the UI thread
CSRF PoC          One-click auto-submitting CSRF PoC generator for any captured request --
                  download or copy from Proxy history / Site map to host on an attacker page
Authz test        Multi-identity replay from Proxy history / Site map -- define named identities
                  (header overlays), replay a captured request as each, and see a per-identity
                  status/size table with a divergence flag (BOLA / horizontal / vertical
                  privilege, CWE-863); divergent runs also file a finding in Issues
Protocol detect   gRPC + GraphQL endpoints flagged in passive scan (fingerprint, not a full decoder)
Exports           SARIF, CycloneDX SBOM, nmap-XML, Postman, OpenAPI, HAR, XML issue report
                  (Burp-style, GET /api/report/xml)
SQLite history    200k+ row engagements stay snappy
AI payloads       Local Ollama expands a seed payload set into new candidates (opt-in)
Scriptable CLI    Drive every panel from your shell
Teaching labs     50 intentionally-vulnerable apps, each mapped to a Nullock probe (labs/)
Browser extension Chrome MV3 companion -- one-click proxy + CA install path
Engagement notes   Free-text per-project notes, editable from the Scope tab, persisted server-side
Project templates  Start a new project pre-seeded with scope + notes from a bundled template
                  (web-app/API/cloud pentest, OAuth review) -- picker + "Create from template"
                  button in Settings' Projects card
Cookie jar         Full per-host cookie inventory (Path, resolved Expires/session state, plus
                  httpOnly/Secure/SameSite coverage percentages) -- SESSIONS tab, alongside the
                  existing inject-focused per-host list
Update check       Dismissible in-app banner surfaces new-release availability + release notes
Command palette    Ctrl/Cmd+K (or the title bar's ⌘K button) fuzzy-searches every tab plus
                    intercept/tweaks/CA-path toggles; Ctrl/Cmd+1-9 jump straight to the first
                    nine tabs
```

## 30 seconds to first capture

### Windows
```cmd
:: download Nullock-3.7.0-win64.exe from Releases, run it
NullockApp --proxy-port=8080 --control-port=17777
```

### Linux
```sh
# Debian/Ubuntu
sudo apt install ./Nullock-3.7.0-Linux.deb
# Fedora/RHEL
sudo dnf install ./Nullock-3.7.0-Linux.rpm
# any distro
chmod +x Nullock-x86_64.AppImage && ./Nullock-x86_64.AppImage
```

### macOS
```sh
# download Nullock-3.7.0-Darwin.dmg, right-click -> Open the first time
```

On first launch it prints where everything is listening (`proxy http://127.0.0.1:8080`, `Nullock UI …`). Two one-time steps before any HTTPS traffic shows up:

1. **Trust the CA** it generated, so it can read TLS — easiest via the browser extension's one-click install, or import `ca.pem` from Nullock's data dir (`%APPDATA%\Nullock\Nullock\ca\` on Windows, `~/.local/share/Nullock/Nullock/ca/` on Linux/macOS) into your browser/OS trust store.
2. **Point your browser's HTTP proxy at `127.0.0.1:8080`** (the port from the startup banner).

Then browse your target and it flows into the history. From another terminal you can drive the same control server:
```sh
nullock status
nullock history 10
nullock scope add 'https://target.example/*'   # scope MITM to your target
nullock scan target.example top100
nullock oast mint            # for blind-bug testing
nullock crawler start https://target.example
```

Full quickstart: <https://bikebrainz.github.io/Nullock/docs/index.html>

## Why Nullock vs Burp / ZAP / mitmproxy

| | Nullock | Burp Community | Burp Pro | mitmproxy |
|---|---|---|---|---|
| Price | Free | Free | $475/yr | Free |
| Active scanner | ✓ (20+ classes) | — | ✓ | — |
| Version→CVE correlation | built-in | — | addon | — |
| Reporting (HTML/SARIF/SBOM/XML) | ✓ | — | partial | — |
| OAST (Collaborator) | in-process | — | hosted | — |
| Session handling rules | ✓ | — | ✓ | — |
| CLI control of every panel | ✓ | — | jython | ✓ |
| SQLite history at 200k+ | ✓ | — | partial | — |
| AI payload generation | local Ollama | — | — | — |
| Template scanning (nuclei) | ✓ (JSON + .yaml) | — | — | — |
| CI security gate (exit code) | ✓ + GH Action | — | Enterprise | — |
| GraphQL + JWT tooling | ✓ | — | paid addons | — |
| HTTP/3 / QUIC | — | — | — | — |
| Brand recognition | v1 | huge | huge | large |

Full honest comparison: <https://bikebrainz.github.io/Nullock/#compare>

## CI security gate & template scanning

Run Nullock headless in a pipeline and fail the build on findings:

```sh
# one-shot: scan a URL, exit nonzero if anything is high or worse
NullockApp --scan https://staging.example.com/ --fail-on high
echo $?          # 0 clean · 1 finding >= threshold · 2 bad URL · 3 target unreachable

# or drive scans over the API, then read the gate for a pass/fail + exit code
curl -s localhost:17777/api/gate?fail-on=high    # {"pass":false,"exitCode":1,...}
```

A composite GitHub Action wraps the one-shot gate (`.github/actions/nullock-scan`,
with a build-then-gate example in `.github/workflows/nullock-scan-example.yml`),
and a reference multi-stage `Dockerfile` runs the headless server — or a one-shot
scan — in a container.

**Template scanning** runs your own nuclei-style detection templates — JSON *or*
a real nuclei `.yaml` — with matchers, extractors, and request crafting
(`{{BaseURL}}` / `{{payload}}` + payload expansion). A bundled starter library
ships under `templates/detections/`:

```sh
curl -s  localhost:17777/api/template/list        # the bundled detections
curl -sX POST localhost:17777/api/template/run -H 'X-Nullock-UI: 1' \
  -d '{"url":"https://target.example/","templateId":"exposed-git-config"}'
```

Template hits report as findings, so they feed the same panel, gate, and
baseline diff as everything else.

## Architecture

```
   ┌──────────── headless backend (Qt6 / C++20) ────┐         ┌─── browser ───┐
   │                                                │         │               │
   │  ProxyServer    HTTP/1.1 + h2 + WS             │         │  React UI     │
   │  CertAuthority  forged leaf certs via OpenSSL  │         │  ui-v2/*.jsx  │
   │  Intercept      pause / forward / drop         │         │  Babel        │
   │  MatchReplace   regex per section              │ <─────> │  in-browser   │
   │  PassiveScanner 10 finding kinds               │  HTTP   │               │
   │  ActiveProbe    20+ vuln classes               │         │  23 tabs:     │
   │  PortScanner    CIDR + banner grab             │         │  proxy / scope│
   │  ReconEngine    DNS / crt.sh / wordlist        │         │  rules / find │
   │  Repeater       multi-tab                      │         │  scans / recon│
   │  Intruder       4 modes + rate-limit-aware     │         │  stats / repr │
   │  OastServer     in-process callback sink       │         │  intercept    │
   │  Crawler        BFS link-follower              │         │  intruder     │
   │  SessionRules   extract/inject variables       │         │  settings     │
   │  HistoryIndex   SQLite metadata + full rows    │         │               │
   │  Extensions     JS in QJSEngine                │         │               │
   │  UpdateChecker  GitHub Releases poll           │         │               │
   │  CrashReporter  local-only crash logs          │         │               │
   │                                                │         │               │
   │  ControlServer  REST API + static UI host      │         │               │
   │     127.0.0.1:17777 (CSRF + Host pinned)       │         │               │
   └────────────────────────────────────────────────┘         └───────────────┘
```

## Build from source

Requirements: CMake 3.24+, Qt 6.7+, C++20 (MSVC 2022 / GCC 13+ / Clang 16+), libnghttp2, OpenSSL.

```sh
git clone https://github.com/Bikebrainz/Nullock
cd Nullock
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To produce installer artifacts:
```sh
cd build && cpack
# outputs Nullock-3.7.0-<platform>.<ext>
```

Per-platform packaging notes: [`packaging/README.md`](packaging/README.md).

## Extensions

Extensions are small JavaScript files that hook the proxy — observe responses,
rewrite outgoing requests, or emit findings — evaluated in an embedded,
sandboxed `QJSEngine` (no filesystem, no network). Traffic-mutation is
capability-gated and default-deny: an extension must declare
`// nullock:permissions modify-requests` (or `modify-responses`) or it stays
observe-only. The Settings tab shows this per loaded script (badge derived
from the DOWNLOADED script's own declaration, not the catalog's marketing
copy). The in-app Marketplace supports search/category filtering and a
per-extension detail panel (author, permissions, sha256, source link).
Full authoring guide, API reference, and the permission model:
[`EXTENSIONS.md`](EXTENSIONS.md).

## Security model

Nullock by design handles untrusted bytes. The threat model + 23 explicit attack surfaces we defend against are documented in [`SECURITY.md`](SECURITY.md). We aim to respond to security reports within 72 hours; full SLA in the docs.

To report a vulnerability: [`github.com/Bikebrainz/Nullock/security/advisories`](https://github.com/Bikebrainz/Nullock/security/advisories).

## Roadmap

- [x] v1: proxy, repeater, intruder, scanner, OAST, extensions API, SQLite history
- [x] v1.1: TLS fingerprint shaping, browser extension, 8 labs, marketplace catalog
- [x] v2: native h2/gRPC/GraphQL/CBOR/SAML, reverse OpenAPI, AI triage, cookie tomography, 12 labs, CI
- [x] v2-ship: installers, marketing site, docs portal, crash reporter, update checker, project templates, report builder
- [ ] v3:
  - [x] HTTP/3 detection — Alt-Svc `h3` readiness probe (`nullock http3`, or the SCANS tab's HTTP/3 detection section); full QUIC client transport still pending a QUIC dependency
  - [x] code signing + Apple notarization — release CI wired (activates on cert secrets); see [`RELEASE_SIGNING.md`](RELEASE_SIGNING.md)
  - [x] hosted OAST tier — deployable `nullock-oast` server + Docker + [`DEPLOY_OAST.md`](DEPLOY_OAST.md) (you supply the host + DNS)
  - [ ] team workspaces — **Phase-1 findings-sync server shipped** (`nullock-workspace`, [`DEPLOY_WORKSPACE.md`](DEPLOY_WORKSPACE.md)); design + later phases: [`design/team-workspaces.md`](design/team-workspaces.md)
- [ ] v4:
  - [x] Web Security Academy clone — **50/50 labs** under [`labs/`](labs/)
  - [ ] enterprise SSO — design: [`design/enterprise-sso.md`](design/enterprise-sso.md)
  - [ ] SOC2 (organizational/audit process)

## Contributing

PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for build/test setup and
the patterns for adding a scanner, lab, or extension, and
[`INSTALL.md`](INSTALL.md) for per-platform install/build. Read
[`SECURITY.md`](SECURITY.md) for the threat model first if you're touching the
proxy or control server. Changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT. See [`LICENSE.md`](LICENSE.md).

Privacy + acceptable use: [`PRIVACY.md`](PRIVACY.md), [`TERMS.md`](TERMS.md).

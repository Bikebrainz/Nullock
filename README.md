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
                  pivot-to-Repeater/Intruder/Comparer/Decoder/Scanner and eight response-modification
                  presets as a standing auto-apply toggle set (persisted, applies to every future held
                  response the moment it's captured, plus manual one-off buttons on the current item);
                  a per-message FORWARD, HOLD RESPONSE button opts just the current held request into
                  response-holding without flipping the global RESPONSES toggle;
                  the held-message editor has EDIT/PARAMS/HEADERS/BODY/PREVIEW/HEX/INSPECTOR view tabs --
                  Pretty-printed JSON/XML, a hex dump of the body, an editable query/body-form/cookie
                  Params grid on a held request, and a structured Inspector side panel on the message
                  being intercepted (same view primitives and backend as Repeater's), plus the same
                  find-in-view search Repeater's panes have;
                  a live RULES panel decides which messages actually get held -- And/Or match rules
                  on file extension/method/URL regex/host glob/content-type/status code/header, per
                  rule negate and request/response/both direction, editable and reorderable in place
                  (an empty list holds everything, matching Burp);
                  a FIX NEW LINES toggle (on by default) repairs a hand-edited request's
                  header/body boundary before forwarding -- restoring a dropped terminating
                  blank line or trimming stray ones left behind -- while a request that
                  declares a real body (Content-Length / chunked) is always forwarded exactly
                  as typed, so a deliberate CL/TE desync probe still survives;
                  WS Repeater overlay injects text/binary/close/ping/pong frames into a live
                  WebSocket tunnel by session, direction, and opcode, with one-click resend-last;
                  a captured text-frame WS message in Proxy history can be sent straight to it,
                  pre-filled and pre-targeted at a still-open session on that same host:port;
                  a dedicated WEBSOCKETS tab groups captured WS traffic by connection with real
                  direction/type/length columns (not the pseudo-HTTP Status/Mime placeholders),
                  direction and message-type filtering, a per-message comment, and the same
                  Raw/Headers/Body/Hex/Inspector detail pane and Send-to-* pivots as HTTP history
                  (TLS-MITM leg only -- plaintext ws:// isn't relayed yet);
                  H2 Frame Log overlay shows a per-stream summary table and a live-tailing raw
                  HTTP/2 frame feed (type/flags/bytes) on either MITM leg -- a frame-level view
                  Burp doesn't have at all;
                  HTTP history/Site map filter bar -- scope/params/404/annotated chips, MIME class,
                  extension show/hide, case-sensitive toggle, and negative ("-term") search;
                  right-click a history row (or a Site map tree leaf) to flag it with one of 9
                  highlight colours and/or a free-text comment (client-side, browser-local
                  persistence), shown as a coloured row edge + a comment icon, filterable via the
                  ANNOTATED chip in either view; a DB Search
                  overlay queries the SQLite-backed history index directly (method/host/path/
                  status/size/since filters) so a row can be found and its full raw request/
                  response opened even after it has scrolled out of the bounded on-screen window;
                  Site map hosts expand into a full protocol://host:port -> directory -> file
                  tree (each path segment its own expandable folder, leaves deduped by
                  method+path, most recent request wins) that jumps straight to that message's
                  editor, no detour through the history table below; clicking a folder scopes
                  both the HTTP history table and Deep Search's regex-over-bodies results to
                  that branch (a scope banner in the Site map pane shows and clears it);
                  manual application mapping -- hand-add a URL to the Site map without sending it
                  (a text box in the Site map pane), or promote a robots.txt Disallow path / sitemap.xml
                  URL straight from the Discover tab with a one-click "+ map" button; every such
                  entry renders greyed-out/dashed in the tree ("not sent") to distinguish an
                  unrequested node from real captured traffic; right-click a host, a folder, or
                  a single leaf for COPY URLS (plain-text list) / COPY LINKS (clickable HTML,
                  pastes into tickets/docs) / SAVE SELECTED ITEMS (a Burp-site-map-shaped XML
                  download with the full captured request/response, base64) / DELETE HOST or
                  DELETE BRANCH (removes it from the site map, history table, and Compare Hosts
                  alike; a filter-bar chip shows how many are hidden and restores them in one
                  click) / REPORT ISSUES (a standalone HTML issue report, sorted by severity),
                  scoped to whatever was clicked -- the whole host, just that branch, or
                  one URL;
                  Settings' CA & TLS card can allow-list a self-signed/expired upstream host
                  (host:port) so it stays interceptable instead of getting permanently blocked
                  on the first bad handshake -- verification only relaxes for listed hosts, and
                  a read-only table shows exactly which leaf cert (sha256), which errors, and
                  when it was waived; an ANALYZE TARGET overlay (scoped to the Site map's current
                  host/branch selection, or all hosts) sizes the attack surface from history
                  already captured -- unique-URL/static/dynamic counts, a query-parameter-name
                  frequency list, and a per-path entry-point table (methods + params), computed
                  entirely client-side with no separate scan or backend call; a COMPARE HOSTS
                  overlay diffs the URL-path surface and the findings of any two hosts already
                  in HTTP history (two environments, or the same target under two roles/sessions
                  logged as distinct hosts) into only-A/common/only-B panes, also client-side
Repeater          Multi-tab, send-from-history, edit-and-resend, request chains, Pretty view
                  auto-indents JSON/XML/HTML bodies, per-tab NOTES for tracking what each
                  tab is testing, per-tab send history with ◀ ▶ navigation back through
                  prior sends, AUTO-CL recomputes Content-Length from the edited body on
                  send (on by default; toggle off from the GUI to hand-craft a CL/TE desync),
                  a FOLLOW selector (never / on-site / in-scope / always) chases 3xx chains to
                  the final page with a COOKIES toggle to thread Set-Cookie through every hop,
                  ⇄ METHOD toggles GET/POST (moving params between the query string and an
                  urlencoded body) and ⇄ ENCODING converts urlencoded <-> multipart/form-data
                  bodies, both recomputing Content-Type/Content-Length; the request pane can
                  also push the draft straight onward -- ↦ CMP/DEC/SEQ plus ↦ INT (promotes
                  it to a new Intruder attack template) and ↦ SCAN (runs the active-test
                  battery against it, findings streaming into Issues), so Repeater is no
                  longer a dead end for the other tools; an editable HEADERS view (add /
                  remove / reorder with per-row buttons, live in both the request editor
                  and Intercept's held request/response editors) round-trips straight into
                  the raw request
Intruder          Sniper / Battering Ram / Pitchfork / Cluster Bomb via a GUI mode picker with a
                  per-position payload-set editor, a live-preview payload generator (numbers/dates/
                  brute-forcer/null/frobber/blocks/casemod/charsub/bitflip), a payload-processing rule chain (prefix/suffix/case/reverse/
                  match-replace/encode/decode/hash), sortable + filterable results, rate-limit-aware
                  (concurrency/throttle plus a configurable retry count on network failure),
                  same FOLLOW/COOKIES redirect-chasing controls as Repeater so a bruteforce behind
                  a login/redirect grades against the real final page instead of a wall of 302s
Passive scanner   Header/cookie/secret/info-leak findings, every one CWE/OWASP/CVSS-enriched
Findings          ISSUES tab: flat, grouped-by-kind+host (instance count, max CVSS, CWE/
                  OWASP rollup), or Definitions view -- a browsable, filterable library of
                  every issue kind the scanner can report (CWE/OWASP/CVSS/compliance/
                  confidence/remediation) independent of whether it has been found yet,
                  drawn from the same enrichment table applied to live findings so the two
                  can never drift apart; a Baseline bar saves/diffs/clears a findings snapshot for
                  scan-to-scan delta (new vs fixed vs unchanged); a per-finding Triage button asks
                  a local Ollama model (falls back to a heuristic verdict) for impact/fix/
                  false-positive assessment -- all three were API-only before this; clicking a
                  finding opens an inline Advisory/Request/Response detail pane (CWE/OWASP/CVSS/
                  compliance/fix guidance, plus the underlying raw request/response with the
                  scanner's evidence string highlighted) instead of jumping straight to Proxy;
                  a per-finding false-positive mark, severity override, and soft-delete/restore,
                  plus per-kind mute -- all persisted in the project and reversible with no
                  re-scan -- are also now reachable from that same tab
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
Discovery         In-app content/directory brute-force (soft-404 calibrated, custom wordlist paste/file-
                  load, extension-bruteforce backup sweep, concurrency + throttle controls), robots.txt +
                  sitemap recon, and start/stop control for the BFS crawler -- results feed Proxy history + Issues
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
                  multi-step request chains (record steps straight from Proxy history row IDs),
                  exposure scan, service CVE correlation, JS recon,
                  TLS/certificate inspection, and the pipeline orchestrator, plus on-demand
                  posture grade / asset inventory /
                  OWASP-compliance coverage / CI-gate rollups -- all previously API-only
Template scanner  Nuclei-style detection templates (JSON or real nuclei .yaml): matchers + extractors
                  + request crafting with {{payload}} expansion; bundled starter library, hits feed the gate --
                  in-app "Detection templates" section (SCANS tab): pick a bundled template or paste a
                  custom JSON one, run against a target URL
CI security gate  Headless one-shot scan (NullockApp --scan URL --fail-on high -> nonzero exit) +
                  GET /api/gate pipeline pass/fail; composite GitHub Action + reference Dockerfile
Reporting         Markdown / styled HTML / JSON / Burp-style XML issue reports, posture grade, OWASP + compliance coverage,
                  asset inventory; in-app REPORTING tab also drives OpenAPI export/import, SBOM
                  download, and workspace push/pull (findings baseline/diff lives in ISSUES, see Findings)
Session rules     Auto-extract CSRF/JWT/nonces and re-inject (Burp macros equivalent); a named,
                  individually enable/disable-able rules editor lives in the SESSIONS tab
                  (host/path glob, extract-from header/cookie/JSON-path/regex, inject-into
                  header/cookie/body/URL) alongside the captured variable bag, plus a
                  Proxy/Repeater/Intruder/Scanner tools-scope checkbox row per rule
                  (Burp's "Tools scope"; enforced for Proxy, Repeater, and Intruder). A
                  companion Login macros section on the same tab names a recorded login
                  sequence (record steps straight from Proxy history), runs it on demand,
                  and auto-re-runs it when a logged-out status/body-regex condition matches
                  a live response -- Burp's "run a macro" rule action.
Sequencer         Statistical randomness analysis of session tokens (Burp Sequencer equivalent);
                  in-app SEQUENCER tab -- paste/load-from-file/clipboard manual load with a
                  pre-analysis sample summary, full results (entropy, char class, hamming, LCS,
                  sequential-counter detection incl. wrapped counters (sess_1001, user-42) with
                  the recovered step, per-position + FIPS 140-2 bit-level tests where
                  applicable), plus sample-size guidance -- warns under ~100 tokens and flags the
                  20,000-bit FIPS conformance threshold; a SEQUENCER/SEQ button in Proxy
                  history's DetailPane and Repeater's request/response panes sends the currently
                  selected text (a token) straight into the manual-load corpus, switching tabs
                  automatically -- builds up a sample set across several captures without
                  copy-paste; EXPORT HTML / EXPORT XML buttons download a standalone report of
                  the current analysis (client-generated, not yet wired into cmd_report or the
                  findings/baseline store); a Live capture panel drives the token-harvest engine
                  directly (host/port/TLS + a raw request template, extract-from header/cookie/
                  JSON-path/regex/status/start-end-delimiters, shot count + throttle, START/STOP/CLEAR
                  with a live progress readout) -- harvested tokens flow straight into the manual-load corpus
                  above, ready for analysis, Copy, Save, or export; in Cookie mode a "cookies seen
                  so far" dropdown auto-populates from the distinct Set-Cookie names the capture
                  has actually observed in responses, so the extraction key can be picked instead
                  of typed blind
Extensions        JS plugin API, onRequest/onResponse hooks, marketplace catalog; an "Install
                  bundled" button in Settings copies the extensions shipped with the repo into
                  the user's extensions dir in one click; a per-extension "Loaded" checkbox in
                  the Installed list disables one script without removing it from disk --
                  the choice persists and takes effect immediately, no reload needed; an
                  "Auto-reload (dev)" checkbox watches the extensions folder and debounce-
                  reloads all scripts ~300ms after any add/remove/edit, for iterating on an
                  extension without clicking Reload by hand
Decoders          JWT (security-annotated) + forge, base64, hex, JSON transcode, rot13, unicode escape,
                  gzip (client-side Compression Streams API, base64 in/out), and protocol decoders
                  (GraphQL pretty-print, gRPC framing, CBOR, SAML) all reachable from the Decoder tab's
                  own op-button row, not just the Proxy/Repeater codec bar;
                  "Send to Decoder" pivots from Proxy history/Site map (request/response), Repeater's
                  request/response panes, and the Intercept queue seed the Decoder tab's input directly
Inspector         Structured view of any request/response -- headers, cookies, query/body params, decoded JWTs;
                  docked live in Repeater, Proxy history, and Intruder's template editor, not just its own tab.
                  A Selection widget section shows highlighted-text character count and the first byte's
                  decimal/hex value, labelling non-printing bytes (\n/\t/\r/space) instead of hiding them.
                  Every header/cookie/query/body-param value gets an automatic, revisable multi-step
                  decode chain (URL/Base64/HTML, up to 6 layers, gated auto-detection with a per-step
                  override select) in both the standalone tab and Repeater's docked panel.
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
Clickjack PoC     One-click clickjacking PoC generator (invisible framed iframe over a decoy
                  button) for any captured request -- download from Proxy history / Site map
Authz test        Multi-identity replay from Proxy history / Site map -- define named identities
                  (header overlays), replay a captured request as each, and see a per-identity
                  status/size table with a divergence flag (BOLA / horizontal / vertical
                  privilege, CWE-863); divergent runs also file a finding in Issues
Protocol detect   gRPC + GraphQL endpoints flagged in passive scan (fingerprint, not a full decoder)
Exports           SARIF, CycloneDX SBOM, nmap-XML, Postman, OpenAPI, HAR, XML issue report
                  (Burp-style, GET /api/report/xml); a portable config document (scope,
                  match-and-replace rules, session-handling rules, intercept rules) exports/
                  imports as one JSON file, or saves/loads/deletes under a name in a global
                  config-preset library (Settings' Project card) that survives across projects
SQLite history    200k+ row engagements stay snappy
AI payloads       Local Ollama expands a seed payload set into new candidates (opt-in)
Scriptable CLI    Drive every panel from your shell
Teaching labs     55 intentionally-vulnerable apps, each mapped to a Nullock probe (labs/);
                  a LABS tab in the app itself (and the docs/labs site) rates each
                  Easy/Medium/Hard, gives 3 progressive hints before the full
                  walkthrough, and one click sends a GET /flag check straight to
                  Repeater; all 55 labs add a real /flag success-check endpoint
                  you solve by exploiting the bug server-side, not just reading
                  the walkthrough; solved labs and per-category XP/tracks are
                  tracked locally in the app
Browser extension Chrome MV3 companion -- one-click proxy + CA install path
Engagement notes   Free-text per-project notes, editable from the Scope tab, persisted server-side
Scope logging      "Log out-of-scope traffic" toggle in the Scope tab -- off (default, Burp's
                  behaviour) drops out-of-scope items from Proxy history and live tasks; on keeps all
                  (each retained out-of-scope row is dimmed with a ⊘ marker in the HTTP history table)
Project templates  Start a new project pre-seeded with scope + notes from a bundled template
                  (web-app/API/cloud pentest, OAuth review) -- picker + "Create from template"
                  button in Settings' Projects card
Cookie jar         Full per-host cookie inventory (Path, resolved Expires/session state, plus
                  httpOnly/Secure/SameSite coverage percentages) with Add/Edit/Del per cookie --
                  SESSIONS tab, alongside the existing inject-focused per-host list
Update check       Dismissible in-app banner surfaces new-release availability + release notes
Command palette    Ctrl/Cmd+K (or the title bar's ⌘K button) fuzzy-searches every tab plus
                    intercept/tweaks/CA-path toggles; Ctrl/Cmd+1-9 jump straight to the first
                    nine tabs -- all 10 bindings are user-remappable (palette entry
                    "Customize keyboard shortcuts…"), with live conflict detection and
                    per-binding reset, persisted across restarts
```

## 30 seconds to first capture

### Windows
```cmd
:: download Nullock-3.8.0-win64.exe from Releases, run it
NullockApp --proxy-port=8080 --control-port=17777
```

### Linux
```sh
# Debian/Ubuntu
sudo apt install ./Nullock-3.8.0-Linux.deb
# Fedora/RHEL
sudo dnf install ./Nullock-3.8.0-Linux.rpm
# any distro
chmod +x Nullock-x86_64.AppImage && ./Nullock-x86_64.AppImage
```

### macOS
```sh
# download Nullock-3.8.0-Darwin.dmg, right-click -> Open the first time
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
   │  ActiveProbe    20+ vuln classes               │         │  25 tabs:     │
   │  PortScanner    CIDR + banner grab             │         │  proxy / scope│
   │  ReconEngine    DNS / crt.sh / wordlist        │         │  rules / find │
   │  Repeater       multi-tab                      │         │  scans / recon│
   │  Intruder       4 modes + rate-limit-aware     │         │  stats / repr │
   │  OastServer     in-process callback sink       │         │  intercept    │
   │  Crawler        BFS link-follower              │         │  intruder     │
   │  SessionRules   extract/inject variables       │         │  websockets   │
   │  HistoryIndex   SQLite metadata + full rows    │         │  settings     │
   │  Extensions     JS in QJSEngine                │         │               │
   │  UpdateChecker  GitHub Releases poll           │         │               │
   │  CrashReporter  local-only crash logs          │         │               │
   │                                                │         │               │
   │  ControlServer  REST API + static UI host      │         │               │
   │     127.0.0.1:17777 (CSRF + Host pinned)       │         │               │
   └────────────────────────────────────────────────┘         └───────────────┘
```

## Build from source

Requirements: CMake 3.24+, C++20 (MSVC 2022 / GCC 12+ / Clang 15+), **Qt 6.7.3
with the `qtwebsockets` add-on module**, and the **dev headers** for libnghttp2
and OpenSSL. The two dev packages are the usual missing piece — install them first
(full per-platform steps in [`INSTALL.md`](INSTALL.md)):

```sh
# Debian/Ubuntu
sudo apt-get install build-essential cmake ninja-build libnghttp2-dev libssl-dev
# Fedora:  sudo dnf install gcc-c++ cmake ninja-build libnghttp2-devel openssl-devel
# macOS:   brew install nghttp2
```

Then build (Qt must be discoverable — set `CMAKE_PREFIX_PATH` to your Qt if `cmake`
can't find it, e.g. `-DCMAKE_PREFIX_PATH="$(qmake6 -query QT_INSTALL_PREFIX)"`):

```sh
git clone https://github.com/Bikebrainz/Nullock
cd Nullock
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To produce installer artifacts:
```sh
cd build && cpack
# outputs Nullock-3.8.0-<platform>.<ext>
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
copy). The in-app Marketplace supports search/category filtering, a
per-extension detail panel (author, permissions, sha256, source link), and
version-compatibility gating — an entry requiring a newer build shows an
"incompatible" badge with its Install/Update button disabled and the reason
in the tooltip.
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
  - [x] Web Security Academy clone — **55/50 labs** under [`labs/`](labs/) (past the original goal, still growing)
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

# In-app UI navigability audit (2026-08-02, updated 2026-08-12c)

> Originally: **97 of 173 backend `/api/` endpoints (56%) have NO ui-v2 caller** — reachable
> only via the API/CLI, hidden from the desktop GUI. As of 2026-08-11, waves closing the
> INSPECTOR, PROBE, TESTS, DISCOVER, REPORTING, COLLABORATOR, and SEQUENCER tabs, plus GUI
> reachability adds to existing tabs (deep-audit-all, the Intruder payload-generator dialog,
> the CSRF PoC generator, the Collaborator Blast spray, the SCANS tab's Assess & audit
> section covering all 9 unified scan/audit runners plus Exposure scan / Service CVE
> correlation / JS recon / TLS-certificate inspection, Inspector's JWT TOOLKIT covering the
> JWT attack toolkit, the ISSUES tab's Baseline bar / grouped view / per-finding Triage
> button, and the PROBE tab's GraphQL schema-introspection audit + 5-attack active probe
> suite), have wired 77 of those endpoints (TESTS covers 24 of the 26 originally-listed active
> checks — `/api/cache/poison` has a distinct request shape outside its uniform
> `/<type>/test` contract, and `/api/jwt/test` was deliberately pulled out of TEST_TYPES since
> that endpoint needs a `token` field the uniform `{url,param?,method?}` contract has no place
> for; both are wired elsewhere instead), leaving 20 of 173 (12%) orphaned as of 2026-08-11.
> The 2026-08-12 wave added a WS REPEATER overlay to the Proxy tab wiring `/api/ws/sessions`
> and `/api/ws/send`, leaving 18 of 173 (10%) orphaned. A same-day follow-up wired the
> nuclei-style detection-template engine (`/api/template/list`, `/api/template/run`) into a
> new "Detection templates" section in the SCANS tab, leaving 16 of 173 (9%) orphaned. A
> further same-day wave wired the session-handling-rules macro editor into the SESSIONS tab
> (`/api/session-rules/set`, `/api/session-rules/clear-vars`) but skipped updating this file's
> tracking at the time -- corrected here alongside this pass's own delta: an "HTTP/3
> detection" section was added to the SCANS tab's Assess & audit block wiring the
> previously-orphaned `/api/http3/detect` (reads the Alt-Svc response header for advertised
> h3/h3-* support), the same single-target-probe pattern as TLS inspection/exposure
> scan/service-CVE correlation/JS recon, true orphaned count corrected 16 -> 13 of 173 (8%).
> This run added an H2 FRAME LOG overlay to the Proxy tab's HTTP HISTORY pane-head, wiring
> the previously-orphaned `/api/h2/streams` (per-stream summary table) and `/api/h2/events`
> (a live-tailing raw frame feed polled with a `since` cursor) -- closing parity item #277's
> GUI-reachability gap, the last of "the 97 orphaned endpoints" plan's HTTP/2-specific asks.
> A further run added an "Import nmap XML" file-picker to the SCANS tab's port scanner (wiring
> `/api/portscan/import-nmap`), a "Port scan -> findings" Section in the Assess & audit block
> (wiring `/api/portscan/to-findings`), and an "Install bundled" button in Settings' Extensions
> card (wiring `/api/extensions/install-builtins`) -- the last one closing the "Other" bucket
> entirely. True orphaned count, re-verified by a fresh
> literal-string grep of every endpoint in this file against live `ui-v2/*.jsx` +
> `ui-v2/real-data.js`: 8 of 173 (5%) orphaned. This run closed the last real
> gaps in that 8: a Cookie Jar section on the SESSIONS tab wires `/api/cookies` (full
> per-host inventory with Path/Expires and httpOnly/secure/sameSite coverage percentages,
> beyond the inject-focused list already there), a CVE overlay section on the SCANS tab
> wires `/api/cve/overlay`, `/api/cve/overlay/clear`, and `/api/cve/sync` (push extra
> service CVEs directly or sync a feed URL, live entry count, Clear button), and a template
> picker + "Create from template" button on Settings' Projects card wires
> `/api/project/templates` + `/api/project/create-from-template`. The sole remaining
> endpoint, `/api/intruder/multi`, is intentionally left orphaned (a redundant synchronous
> alternative to the already-wired async Intruder flow -- see its own bucket note) --
> **true orphaned count corrected 8 -> 3 of 173 (2%), all three intentional**
> (`/api/cache/poison`, `/api/request/curl`, `/api/intruder/multi`). Verified
> per-bucket by grepping `ui-v2/*.jsx` and `ui-v2/real-data.js` for each path literal — with
> one correction to the stated methodology: `NL.actions.runTest` builds its URL as
> `"/api/" + type + "/test"`, one dynamic construction ui-v2 does use, so a pure
> literal-string grep alone would have missed that `jwt` sat in `TEST_TYPES` but could never
> actually succeed (the endpoint requires a captured `token`, which the generic TESTS form
> never collects) — this pass traced that path by hand rather than trusting the grep. This
> pass also caught doc drift from an earlier wave: the 2026-08-10 Issues/Baseline batch
> (06e1d6d/3e7cae8) wired `/api/baseline/{save,status,diff,clear}`, `/api/findings/grouped`,
> and `/api/triage/finding` into the ISSUES tab but this file was never updated to drop them
> from the orphaned list — corrected here (a fresh literal grep confirms all six are called
> from `ui-v2/app.jsx` / `ui-v2/real-data.js`). This is the work-list for surfacing every
> remaining feature. Closing an item = add a tab/menu/button that invokes the endpoint and
> renders its result, then flip the matching parity.json item and regenerate.

App exposes 25 top-level tabs: proxy, scope, rules, issues, scans, recon, payloads,
decoder, comparer, inspector, probe, sequencer, tests, discover, labs, collaborator, reporting,
processor, stats, sessions, websockets, repeater, intercept, intruder, settings. A dedicated
WEBSOCKETS tab groups the same NL.rows entries the Proxy tab already surfaced as pseudo-HTTP
WS↑/WS↓ rows into a per-host:port connection list, with real direction/type/length columns
(decoded out of the synthetic path string), direction/type filters, a per-message client-side
comment, and the shared DetailPane (Raw/Headers/Body/Hex/Inspector + every Send-to- pivot) --
closing parity item #269's tab/direction/length/comment/filtering ask; captured on the
TLS-MITM leg only (a real backend gap, not addressed here) and connections are grouped by
host:port only since a history row carries no per-tunnel session id. The SCANS tab now drives
port-scan (with an Import nmap XML file-picker alongside Export) + recon plus an Assess &
audit section (assess/audit-run/param-miner/chain-run/pipeline-run, posture/inventory/
compliance/gate rollups, exposure-scan/service-CVE-correlation/JS-recon/TLS-certificate-
inspection/HTTP-3-detection single-target probes, a Port scan -> findings bridge, and a
Detection templates section running the bundled nuclei-style template library or a
custom-JSON template against a target URL, and now a CVE overlay section for pushing/syncing
extra service CVEs into the correlation table). A same-day follow-up added a "Record from
history" control to the SCANS tab's Request chain section, wiring `/api/chain/record` (the
"record a macro from captured Proxy history" half of Repeater chains, alongside the
already-tracked `/api/chain/run`) -- present in the backend since before the last full
audit but never entered into this file's endpoint census, so it never showed up in the
"N of 173" counts above even while unwired; noted here as a same-bucket addendum rather than
rewriting those historical counts. The INSPECTOR tab now
has a PARSE / JWT TOOLKIT mode toggle — JWT TOOLKIT covers offline analyze/forge plus a live
acceptance test. The PROBE tab now has GraphQL schema/probe buttons alongside fingerprint/
header-audit/waf-detect/secret-scan. The SESSIONS tab now has a Cookie Jar section (full
per-host inventory: Path/Expires + httpOnly/secure/sameSite coverage percentages) below its
inject-focused per-host list. SETTINGS' Projects card now offers a template picker and a
"Create from template" button.

## Active vulnerability tests (1 remaining — 24 of the 26 `/<type>/test` family are wired via TESTS, `jwt` via Inspector's JWT TOOLKIT)
- `/api/cache/poison` — distinct shape from the `/api/<type>/test` family (not covered by the TESTS tab's uniform `{url,param?,method?}` -> `/api/<type>/test` contract)

(`/api/assess`, `/api/audit/run`, `/api/chain/run`, `/api/chain/record`, `/api/compliance`,
`/api/gate`, `/api/inventory`, `/api/paramminer`, `/api/pipeline/run`, `/api/posture` all
wired via the SCANS tab's Assess & audit / Request chain sections. `/api/headers/audit`
wired via PROBE tab.)

## Inspector / decoder / request tools (1)
- `/api/request/curl` — intentionally left orphaned: functionally superseded by the
  client-side COPY AS exporter (`renderRequestAs` in ui-v2/proxy.jsx, reachable from both
  Proxy history and Repeater) which already produces a curl command — plus 8 other formats
  (wget/httpie/powershell/fetch/sqlmap/postman/nuclei/burp-raw) — with sensitive-header
  redaction the backend endpoint doesn't do. Parity item on this ("Copy as curl command")
  is already `exceeds`. Wiring the backend endpoint too would add a second, weaker,
  redundant path to the same capability rather than close a real gap.

(`/api/inspect` wired via INSPECTOR tab. `/api/tls/inspect` wired via the SCANS tab's
Assess & audit section — a host:port TLS/certificate inspection probe alongside the
other single-target recon tools.)

(`/api/jwt/analyze`, `/api/jwt/forge`, `/api/jwt/test` wired via the INSPECTOR tab's
JWT TOOLKIT mode: offline decode/weakness-analyze/HS*-brute-force, alg:none and
HS256-resign/algorithm-confusion forging, and a live acceptance test against a target
with calibration. `jwt` was removed from the TESTS tab's TEST_TYPES — that generic
form has no `token` field, so it could never have actually worked.)

(`/api/export/sbom`, `/api/openapi/export`, `/api/openapi/import`, `/api/report/build`,
`/api/report/html`, `/api/report/json`, `/api/workspace/pull`, `/api/workspace/push`
wired via REPORTING tab.)

## Recon / discovery (0)

(`/api/h2/events`, `/api/h2/streams` wired via the Proxy tab's new H2 FRAME LOG
overlay (HTTP HISTORY pane-head) -- a per-stream summary table plus a live-tailing
raw frame feed, polled every 2s while open (#277).

`/api/fingerprint`, `/api/waf/detect`, `/api/secrets/scan` wired via PROBE tab;
`/api/content/discover`, `/api/crawler/start`, `/api/crawler/stop`, `/api/robots/scan`
wired via DISCOVER tab. `/api/exposure/scan`, `/api/servicevulns/scan`, `/api/jsrecon/scan`
wired via the SCANS tab's Assess & audit section -- Exposure scan (curated sensitive-path
probe), Service CVE correlation (banner-grab + curated CVE table), and JS recon
(same-origin JS bundle endpoint/secret/source-map mining). `/api/http3/detect` wired via the
same section's HTTP/3 detection probe (Alt-Svc h3/h3-* advertisement check).)

(`/api/oast/mint`, `/api/oast/poll` wired via COLLABORATOR tab. `/api/oast/blast` (the
multi-vector SSRF/XXE/blind-RCE/Log4Shell spray) wired via the tab's new Blast section —
a distinct "attack" action alongside Collaborator's "mint and watch" workflow.
`/api/sequencer/analyze` wired via the SEQUENCER tab's Manual Load -> Analyze now flow.
`/api/jwt/analyze`, `/api/jwt/forge`, `/api/jwt/test` wired via INSPECTOR's JWT TOOLKIT.
`/api/graphql/schema`, `/api/graphql/probe` wired via the PROBE tab's graphql schema /
graphql probe buttons.)

## Cookies / CVE overlay (0)

(`/api/cookies` wired via the SESSIONS tab's new Cookie Jar section -- full per-host
inventory (path/expiry + httpOnly/secure/sameSite coverage percentages) distinct from the
inject-focused per-host list above it, which reads the `/api/snapshot` sessions block
instead. `/api/cve/overlay`, `/api/cve/overlay/clear`, `/api/cve/sync` wired via the SCANS
tab's new "CVE overlay" section -- push extra service CVEs directly (air-gapped JSON array)
or sync from a feed URL, with a live entry count and a Clear button.)

(`/api/baseline/save`, `/api/baseline/status`, `/api/baseline/diff`, `/api/baseline/clear`,
`/api/findings/grouped`, `/api/triage/finding` wired via the ISSUES tab's Baseline bar,
FLAT/GROUPED toggle, and per-finding Triage button.)

## GraphQL / WS / session (1)
- `/api/intruder/multi` — intentionally left orphaned: a synchronous one-shot alternative
  to the already-wired async Intruder flow (`/api/intruder/set` + `/api/intruder/start`,
  polled via snapshot). Both accept the identical field set (host/port/tls/template/
  attackType/payloadSets) -- confirmed by reading both handlers side by side
  (control_server.cpp:3265-3299 set, :3446-3503 multi) -- so wiring a second GUI path to the
  same capability would be a redundant, weaker (no live progress, no resend, no rule chain)
  duplicate rather than closing a real gap. Same precedent as `/api/request/curl` below.

(`/api/project/templates`, `/api/project/create-from-template` wired via Settings' Projects
card -- a template `<select>` (name + description) next to the existing new-project-name
field, plus a "Create from template" button. `/api/intruder/generate`, `/api/intruder/generator-types` wired via Intruder's GENERATOR
dialog; `/api/intruder/rule-ops` wired via Intruder's RULES bar. `/api/graphql/probe`,
`/api/graphql/schema` wired via the PROBE tab. `/api/authz-test` wired via the AUTHZ TEST
button in Proxy history / Site map's DetailPane. `/api/ws/sessions`, `/api/ws/send` wired via
the Proxy tab's WS REPEATER overlay (HTTP HISTORY pane-head) -- session dropdown, direction/
opcode selectors, payload editor, resend-last. `/api/template/list`, `/api/template/run`
wired via the SCANS tab's new "Detection templates" section -- bundled template picker plus a
custom-JSON template editor, both firing against a target URL. `/api/session-rules/set`,
`/api/session-rules/clear-vars` wired via the SESSIONS tab's session-handling-rules editor
(named rule form + live captured-variables readout) -- this file's tracking had drifted since
that wave shipped, corrected here. `/api/portscan/import-nmap` wired via an "Import nmap XML"
file-picker button next to the port scanner's existing "Export nmap XML" (SCANS tab),
feeding a saved or externally-run nmap `-oX` scan into the same PortResult pipeline as a live
scan. `/api/portscan/to-findings` wired via a new "Port scan -> findings" Section in the
SCANS tab's Assess & audit block -- promotes the port scanner's current results (exposed
db/remote-admin/mgmt-API/cleartext/file-share, plus banner->CVE correlation) into the shared
findings list, idempotent on re-post.)

## Other (0)

(`/api/csrf/poc` wired via the CSRF POC button in Proxy history / Site map's DetailPane.
`/api/extensions/install-builtins` wired via an "Install bundled" button in Settings' Extensions
card, next to the existing "Reload" button -- copies the extensions shipped with the repo into
the user's extensions dir and reloads, removing the "go find the file in github and copy it
yourself" onboarding step.)

# In-app UI navigability audit (2026-08-02, updated 2026-08-11)

> Originally: **97 of 173 backend `/api/` endpoints (56%) have NO ui-v2 caller** — reachable
> only via the API/CLI, hidden from the desktop GUI. As of 2026-08-11, waves closing the
> INSPECTOR, PROBE, TESTS, DISCOVER, REPORTING, COLLABORATOR, and SEQUENCER tabs, plus GUI
> reachability adds to existing tabs (deep-audit-all, the Intruder payload-generator dialog,
> the CSRF PoC generator, the Collaborator Blast spray, the SCANS tab's Assess & audit
> section covering all 9 unified scan/audit runners, Inspector's JWT TOOLKIT covering the JWT
> attack toolkit, the ISSUES tab's Baseline bar / grouped view / per-finding Triage button,
> and the PROBE tab's GraphQL schema-introspection audit + 5-attack active probe suite), have
> wired 73 of those endpoints (TESTS covers 24 of the 26 originally-listed active checks —
> `/api/cache/poison` has a distinct request shape outside its uniform `/<type>/test` contract,
> and `/api/jwt/test` was deliberately pulled out of TEST_TYPES since that endpoint needs a
> `token` field the uniform `{url,param?,method?}` contract has no place for; both are wired
> elsewhere instead), leaving **24 of 173 (14%) still orphaned**. Verified per-bucket by
> grepping `ui-v2/*.jsx` and `ui-v2/real-data.js` for each path literal — with one correction
> to the stated methodology: `NL.actions.runTest` builds its URL as `"/api/" + type + "/test"`,
> one dynamic construction ui-v2 does use, so a pure literal-string grep alone would have missed
> that `jwt` sat in `TEST_TYPES` but could never actually succeed (the endpoint requires a
> captured `token`, which the generic TESTS form never collects) — this pass traced that path
> by hand rather than trusting the grep. This pass also caught doc drift from an earlier wave:
> the 2026-08-10 Issues/Baseline batch (06e1d6d/3e7cae8) wired `/api/baseline/{save,status,
> diff,clear}`, `/api/findings/grouped`, and `/api/triage/finding` into the ISSUES tab but this
> file was never updated to drop them from the orphaned list — corrected here (a fresh literal
> grep confirms all six are called from `ui-v2/app.jsx` / `ui-v2/real-data.js`). This is the
> work-list for surfacing every remaining feature. Closing an item = add a tab/menu/button that
> invokes the endpoint and renders its result, then flip the matching parity.json item and
> regenerate.

App exposes 23 top-level tabs: proxy, scope, rules, issues, scans, recon, payloads,
decoder, comparer, inspector, probe, sequencer, tests, discover, collaborator, reporting,
processor, stats, sessions, repeater, intercept, intruder, settings. The SCANS tab now drives
port-scan + recon plus an Assess & audit section (assess/audit-run/param-miner/chain-run/
pipeline-run, and posture/inventory/compliance/gate rollups). The INSPECTOR tab now has a
PARSE / JWT TOOLKIT mode toggle — JWT TOOLKIT covers offline analyze/forge plus a live
acceptance test. The PROBE tab now has GraphQL schema/probe buttons alongside fingerprint/
header-audit/waf-detect/secret-scan.

## Active vulnerability tests (1 remaining — 24 of the 26 `/<type>/test` family are wired via TESTS, `jwt` via Inspector's JWT TOOLKIT)
- `/api/cache/poison` — distinct shape from the `/api/<type>/test` family (not covered by the TESTS tab's uniform `{url,param?,method?}` -> `/api/<type>/test` contract)

(`/api/assess`, `/api/audit/run`, `/api/chain/run`, `/api/compliance`, `/api/gate`,
`/api/inventory`, `/api/paramminer`, `/api/pipeline/run`, `/api/posture` all wired via the
SCANS tab's Assess & audit section. `/api/headers/audit` wired via PROBE tab.)

## Inspector / decoder / request tools (2)
- `/api/request/curl`
- `/api/tls/inspect`

(`/api/inspect` wired via INSPECTOR tab.)

(`/api/jwt/analyze`, `/api/jwt/forge`, `/api/jwt/test` wired via the INSPECTOR tab's
JWT TOOLKIT mode: offline decode/weakness-analyze/HS*-brute-force, alg:none and
HS256-resign/algorithm-confusion forging, and a live acceptance test against a target
with calibration. `jwt` was removed from the TESTS tab's TEST_TYPES — that generic
form has no `token` field, so it could never have actually worked.)

(`/api/export/sbom`, `/api/openapi/export`, `/api/openapi/import`, `/api/report/build`,
`/api/report/html`, `/api/report/json`, `/api/workspace/pull`, `/api/workspace/push`
wired via REPORTING tab.)

## Recon / discovery (6)
- `/api/exposure/scan`
- `/api/h2/events`
- `/api/h2/streams`
- `/api/http3/detect`
- `/api/jsrecon/scan`
- `/api/servicevulns/scan`

(`/api/fingerprint`, `/api/waf/detect`, `/api/secrets/scan` wired via PROBE tab;
`/api/content/discover`, `/api/crawler/start`, `/api/crawler/stop`, `/api/robots/scan`
wired via DISCOVER tab.)

(`/api/oast/mint`, `/api/oast/poll` wired via COLLABORATOR tab. `/api/oast/blast` (the
multi-vector SSRF/XXE/blind-RCE/Log4Shell spray) wired via the tab's new Blast section —
a distinct "attack" action alongside Collaborator's "mint and watch" workflow.
`/api/sequencer/analyze` wired via the SEQUENCER tab's Manual Load -> Analyze now flow.
`/api/jwt/analyze`, `/api/jwt/forge`, `/api/jwt/test` wired via INSPECTOR's JWT TOOLKIT.
`/api/graphql/schema`, `/api/graphql/probe` wired via the PROBE tab's graphql schema /
graphql probe buttons.)

## Cookies / CVE overlay (4)
- `/api/cookies`
- `/api/cve/overlay`
- `/api/cve/overlay/clear`
- `/api/cve/sync`

(No matching parity-backlog item for the host-wide cookie-jar inventory endpoint — the
SESSIONS tab already renders per-host captured cookies from the `/api/snapshot` sessions
block, a different data path with the same underlying capture; `/api/cookies` adds
path/expires fields and httpOnly/secure/sameSite percentage rollups the SESSIONS tab
doesn't show. CVE overlay sync (air-gapped feed ingestion for ServiceVulns) has no UI
entry point at all yet.)

(`/api/baseline/save`, `/api/baseline/status`, `/api/baseline/diff`, `/api/baseline/clear`,
`/api/findings/grouped`, `/api/triage/finding` wired via the ISSUES tab's Baseline bar,
FLAT/GROUPED toggle, and per-finding Triage button.)

## GraphQL / WS / session (10)
- `/api/intruder/multi`
- `/api/portscan/import-nmap`
- `/api/portscan/to-findings`
- `/api/project/templates`
- `/api/session-rules/clear-vars`
- `/api/session-rules/set`
- `/api/template/list`
- `/api/template/run`
- `/api/ws/send`
- `/api/ws/sessions`

(`/api/intruder/generate`, `/api/intruder/generator-types` wired via Intruder's GENERATOR
dialog; `/api/intruder/rule-ops` wired via Intruder's RULES bar. `/api/graphql/probe`,
`/api/graphql/schema` wired via the PROBE tab. `/api/authz-test` wired via the AUTHZ TEST
button in Proxy history / Site map's DetailPane.)

## Other (1)
- `/api/extensions/install-builtins`

(`/api/csrf/poc` wired via the CSRF POC button in Proxy history / Site map's DetailPane.)

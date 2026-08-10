# In-app UI navigability audit (2026-08-02, updated 2026-08-10)

> Originally: **97 of 173 backend `/api/` endpoints (56%) have NO ui-v2 caller** — reachable
> only via the API/CLI, hidden from the desktop GUI. As of 2026-08-10, waves closing the
> INSPECTOR, PROBE, TESTS, DISCOVER, REPORTING, COLLABORATOR, and SEQUENCER tabs, plus GUI
> reachability adds to existing tabs (deep-audit-all, the Intruder payload-generator dialog,
> the CSRF PoC generator, and the Collaborator Blast spray), have wired 51 of those endpoints
> (TESTS covers 25 of the 26 originally-listed active checks — `/api/cache/poison` has a
> distinct request shape outside its uniform `/<type>/test` contract and remains orphaned),
> leaving **46 of 173 (27%) still orphaned**. Verified per-bucket by grepping `ui-v2/*.jsx` and
> `ui-v2/real-data.js` for each path literal (ui-v2 uses no dynamic `/api/${...}` URL
> construction, so a literal-string grep is exhaustive) — this pass also caught and corrected
> five endpoints (`/api/audit/all`, `/api/csrf/poc`, `/api/intruder/generate`,
> `/api/intruder/generator-types`, `/api/intruder/rule-ops`) that earlier waves had already
> wired into the GUI but never removed from this list. This is the work-list for surfacing
> every remaining feature. Closing an item = add a tab/menu/button that invokes the endpoint
> and renders its result, then flip the matching parity.json item and regenerate.

App exposes 23 top-level tabs: proxy, scope, rules, issues, scans, recon, payloads,
decoder, comparer, inspector, probe, sequencer, tests, discover, collaborator, reporting,
processor, stats, sessions, repeater, intercept, intruder, settings. The SCANS tab still only
drives port-scan + recon; the unified audit/assess/gate runners below have no control.

## Active vulnerability tests (1 remaining — the 26 uniform `/<type>/test` checks are wired via TESTS)
- `/api/cache/poison` — distinct shape from the `/api/<type>/test` family (not covered by the TESTS tab's uniform `{url,param?,method?}` -> `/api/<type>/test` contract)

## Unified scan / audit runners (9)
- `/api/assess`
- `/api/audit/run`
- `/api/chain/run`
- `/api/compliance`
- `/api/gate`
- `/api/inventory`
- `/api/paramminer`
- `/api/pipeline/run`
- `/api/posture`

(`/api/headers/audit` wired via PROBE tab.)

## Inspector / decoder / request tools (2)
- `/api/request/curl`
- `/api/tls/inspect`

(`/api/inspect` wired via INSPECTOR tab.)

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

## JWT / OAST / crypto (3)
- `/api/jwt/analyze`
- `/api/jwt/forge`
- `/api/jwt/test`

(`/api/oast/mint`, `/api/oast/poll` wired via COLLABORATOR tab. `/api/oast/blast` (the
multi-vector SSRF/XXE/blind-RCE/Log4Shell spray) wired via the tab's new Blast section —
a distinct "attack" action alongside Collaborator's "mint and watch" workflow.
`/api/sequencer/analyze` wired via the SEQUENCER tab's Manual Load -> Analyze now flow.)

## Baseline / findings / triage (11)
- `/api/baseline/`
- `/api/baseline/clear`
- `/api/baseline/diff`
- `/api/baseline/save`
- `/api/baseline/status`
- `/api/cookies`
- `/api/cve/overlay`
- `/api/cve/overlay/clear`
- `/api/cve/sync`
- `/api/findings/grouped`
- `/api/triage/finding`

## GraphQL / WS / session (13)
- `/api/authz-test`
- `/api/graphql/probe`
- `/api/graphql/schema`
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
dialog; `/api/intruder/rule-ops` wired via Intruder's RULES bar.)

## Other (1)
- `/api/extensions/install-builtins`

(`/api/csrf/poc` wired via the CSRF POC button in Proxy history / Site map's DetailPane.)

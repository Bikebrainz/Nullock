# In-app UI navigability audit (2026-08-02)

> **97 of 173 backend `/api/` endpoints (56%) have NO ui-v2 caller** — they are reachable only via the API/CLI, hidden from the desktop GUI. Verified: ui-v2 uses no dynamic `/api/${...}` URL construction, so these are genuinely un-wired, not a false negative. This is the work-list for surfacing every feature. Closing an item = add a tab/menu/button that invokes the endpoint and renders its result, then flip the matching parity.json item and regenerate.

App exposes 16 top-level tabs: proxy, scope, rules, issues, scans, recon, payloads, decoder, comparer, processor, stats, sessions, repeater, intercept, intruder, settings. **No Inspector tab despite a complete `/api/inspect` + inspector_logic backend.** The SCANS tab only drives port-scan + recon; the active-test arsenal has no control.

## Active vulnerability tests (whole arsenal hidden) (26)
- `/api/cache/poison`
- `/api/cachedeception/test`
- `/api/cmdi/test`
- `/api/cors/test`
- `/api/crlf/test`
- `/api/cswsh/test`
- `/api/deser/test`
- `/api/hostheader/test`
- `/api/idor/test`
- `/api/ldapi/test`
- `/api/massassign/test`
- `/api/methods/test`
- `/api/nosqli/test`
- `/api/openredirect/test`
- `/api/pathtraversal/test`
- `/api/protopollution/test`
- `/api/race/test`
- `/api/smuggle/test`
- `/api/sqli/test`
- `/api/ssrf/test`
- `/api/ssti/test`
- `/api/takeover/test`
- `/api/verbtamper/test`
- `/api/xpathi/test`
- `/api/xss/test`
- `/api/xxe/test`

## Unified scan / audit runners (11)
- `/api/assess`
- `/api/audit/all`
- `/api/audit/run`
- `/api/chain/run`
- `/api/compliance`
- `/api/gate`
- `/api/headers/audit`
- `/api/inventory`
- `/api/paramminer`
- `/api/pipeline/run`
- `/api/posture`

## Inspector / decoder / request tools (3)
- `/api/inspect`
- `/api/request/curl`
- `/api/tls/inspect`

## Reporting & export (8)
- `/api/export/sbom`
- `/api/openapi/export`
- `/api/openapi/import`
- `/api/report/build`
- `/api/report/html`
- `/api/report/json`
- `/api/workspace/pull`
- `/api/workspace/push`

## Recon / discovery (13)
- `/api/content/discover`
- `/api/crawler/start`
- `/api/crawler/stop`
- `/api/exposure/scan`
- `/api/fingerprint`
- `/api/h2/events`
- `/api/h2/streams`
- `/api/http3/detect`
- `/api/jsrecon/scan`
- `/api/robots/scan`
- `/api/secrets/scan`
- `/api/servicevulns/scan`
- `/api/waf/detect`

## JWT / OAST / crypto (7)
- `/api/jwt/analyze`
- `/api/jwt/forge`
- `/api/jwt/test`
- `/api/oast/blast`
- `/api/oast/mint`
- `/api/oast/poll`
- `/api/sequencer/analyze`

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

## GraphQL / WS / session (16)
- `/api/authz-test`
- `/api/graphql/probe`
- `/api/graphql/schema`
- `/api/intruder/generate`
- `/api/intruder/generator-types`
- `/api/intruder/multi`
- `/api/intruder/rule-ops`
- `/api/portscan/import-nmap`
- `/api/portscan/to-findings`
- `/api/project/templates`
- `/api/session-rules/clear-vars`
- `/api/session-rules/set`
- `/api/template/list`
- `/api/template/run`
- `/api/ws/send`
- `/api/ws/sessions`

## Other (2)
- `/api/csrf/poc`
- `/api/extensions/install-builtins`

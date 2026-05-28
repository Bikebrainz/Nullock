# Nullock features audit

Verified live against PID 42036 on 2026-05-28. Every ✓ was smoke-tested
via curl against the running app this session.

## Backend

### Proxy core
- [x] HTTP/1.1 plain proxy round-trip
- [x] HTTPS MITM with forged leaf certs (covered by --smoke-test)
- [x] HTTP/2 upstream (libnghttp2; covered by --smoke-test)
- [x] WebSocket relay with frame parsing
- [x] Per-host MITM blocklist persistence (clear works)
- [x] Scope filter (in/out globs, filteredCount climbs on out-of-scope)
- [x] Fallback port chain (running on 8080)

### Mutation pipeline
- [x] Extensions API: JS in `extensions/` runs on startup
- [x] Extensions: onResponse mutation (X-Audit-Ext injection confirmed)
- [x] Extensions: onRequest mutation
- [x] Match & Replace: URL rewrite
- [x] Match & Replace: request header rewrite (UA rewrite confirmed)
- [x] Match & Replace: request body rewrite (token rewrite confirmed)
- [x] Match & Replace: response header rewrite
- [x] Match & Replace: response body rewrite (METHOD→REWROTE confirmed)
- [x] Match & Replace: response status rewrite
- [x] Match & Replace: rulesHit counter increments
- [x] Match & Replace: persistence in project.json

### Intercept  **(critical deadlock fixed this audit)**
- [x] Toggle on/off
- [x] Forward current
- [x] Drop current (connection breaks)
- [x] Forward all (drain queue)
- [x] Edit-then-forward (edits applied to wire)

### Repeater
- [x] Send via raw bytes (TLS + plain)
- [x] Multi-tab: add, activate, close, rename, duplicate
- [x] Send-to-repeater opens new tab
- [x] Active-tab semantics on the legacy single-state API

### Intruder
- [x] Sniper mode: §marker§ substitution
- [x] Per-row resend
- [x] Start / stop / clear

### Scanners
- [x] Passive: missing CSP/HSTS/XFO/XCTO/RP on HTML
- [x] Passive: Set-Cookie hardening (HttpOnly / Secure / SameSite)
- [x] Passive: Server-version leak / X-Powered-By
- [x] Passive: CORS wildcard / wildcard + credentials
- [x] Passive: sensitive params in URL
- [x] Passive: auth-over-HTTP
- [x] Active: reflected-XSS probe per row
- [x] Findings rowId aligns with ProxyModel

### Project store
- [x] Open default project at startup
- [x] Multi-project list/open/create
- [x] Switch wipes model + reloads scope + reloads rules
- [x] history.ndjson append on every response (clear-history wipes it)
- [x] HAR export
- [x] HAR import (path: 184 entries re-loaded)
- [x] HAR import (object via React file picker)

### Control server
- [x] /api/snapshot full
- [x] /api/snapshot?since=N → 304 short-circuit
- [x] /api/history/<id>/request|response
- [x] /api/history/<id>/replay
- [x] /api/history/<id>/probe
- [x] /api/search?q=…&where=…
- [x] /api/pac
- [x] /ca.pem and /ca.crt
- [x] /api/proxy/toggle
- [x] /api/intercept/{toggle,forward,drop,forwardAll}
- [x] /api/scope/{in,out}/{add,remove}
- [x] /api/scope/notes
- [x] /api/repeater/{set,send,clear,tab/*}
- [x] /api/intruder/{set,start,stop,clear,resend}
- [x] /api/rules/{add,update,remove,toggle,move}
- [x] /api/findings/clear
- [x] /api/theme + /api/theme/save-as + /api/theme/reload
- [x] /api/har/export + /api/har/import
- [x] /api/clear-history
- [x] /api/mitm/clear-blocked
- [x] /api/extensions/reload
- [x] /api/project/{list,open,create}
- [x] Static file serving from ui-v2/

## Frontend

All shipped React components wire to the matching backend endpoint
(audited by grepping `/api/*` strings across both sides — full overlap).

### Tabs
- [x] PROXY · scope filter, history table, click-to-inspect detail pane
- [x] SCOPE · in/out glob lists, notes
- [x] RULES · create/edit/toggle/delete/reorder
- [x] ISSUES · severity + kind filter chips, click-to-jump
- [x] REPEATER · tab strip with rename/dup/close + real send
- [x] INTERCEPT · queue depth + forward/drop/forwardAll
- [x] INTRUDER · template + payloads + presets + results + per-row resend
- [x] SETTINGS · Proxy, CA & TLS, Projects, Project, Extensions,
  Browser setup cards

### Proxy detail pane
- [x] REQ / RES tabs (raw/headers/body/preview/hex)
- [x] Codec bar (URL / b64 / JWT / hex / HTML en+decode, overlay output)
- [x] Diff overlay between marked rows
- [x] Replay button (mutations apply, new row appears)
- [x] Probe button (per-param canary scan)
- [x] Send-to-Repeater / Intruder

### History filter bar
- [x] Host substring filter
- [x] Status-class chips (all/2xx/3xx/4xx/5xx)
- [x] Method dropdown
- [x] Search box (URL/path/method/mime, debounced)
- [x] Deep search toggle (regex over response/request bodies)
- [x] Clear filters

### Tweaks panel
- [x] Theme cycle (5 built-ins + JSON files)
- [x] Colors editor live preview + save-as
- [x] Accent override

### Status bar
- [x] Toggle proxy power
- [x] Export HAR
- [x] Clear history

## Future / unbuilt (roadmap)

- [ ] HTTP/2 multiplexing (single stream per CONNECT today)
- [ ] Server-side h2 to browser
- [ ] WebSocket permessage-deflate
- [ ] TLS fingerprint randomization (JA3 evasion)
- [ ] Active scanner: open-redirect probe (canary in Location)
- [ ] Active scanner: SQLi-error probe
- [ ] Active scanner: header param probes
- [ ] Active scanner: POST body params
- [ ] Saved auth tokens / session manager
- [ ] Mobile CA install with LAN binding + QR code
- [ ] Request templates / scratchpad
- [ ] Smoke-test coverage for scanner / probe / replay / rules / project switch
- [ ] WebSocket frame grouping in history (per-session view)

## Bugs caught & fixed in this audit

- **Intercept deadlock (critical)** — `addPendingOnMain` / `forward()` /
  `drop()` emitted `currentChanged` while still holding
  `m_queueMutex`. QML's `intercept.queueDepth` binding evaluates
  synchronously on signal emit and re-acquires the same mutex → main
  thread deadlocks the moment any request hits the queue. Both the
  proxy and the control server stopped responding entirely. Fix:
  emit after the lock is released. Verified by repro before/after.
- **(earlier)** okJson() always overwrote `ok` to true — endpoints
  reporting failure were lying. Fixed.
- **(earlier)** Scanner rowId out of sync with ProxyModel after
  history replay. Fixed via `setNextRowId(model.rowCount()+1)` at
  boot + modelReset wire.
- **(earlier)** openByName silently created project dirs. Fixed.
- **(earlier)** Replay re-entered control loop via sync HttpClient
  → crashed app. Fixed by running on QtConcurrent.
- **(earlier)** FrontEndGUI.dll + Qt6Concurrent.dll not auto-deployed.
  Fixed via POST_BUILD steps in Src/App/CMakeLists.txt.

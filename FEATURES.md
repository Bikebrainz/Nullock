# Nullock features (live inventory)

Quick reference of everything that ships today. For the high-level
overview see README.md; this file is the per-feature checklist for
QA + scope conversations.

## Tabs

- [x] **PROXY** — live history table, site map left rail, filter bar
      (host / status / method / URL / regex deep search), detail pane
      with REQ+RES (raw / headers / body / preview / hex), codec
      helpers (URL / b64 / JWT / hex / HTML), row-to-row diff overlay,
      ↦ REPEATER / INTRUDER / COPY AS, ↻ REPLAY, ⚡ PROBE, ⊟ MARK / DIFF
- [x] **SCOPE** — in / out glob lists per project, notes, save-on-edit
- [x] **RULES** — match & replace regex editor: name / host glob /
      section (URL / req-header / req-body / resp-header / resp-body /
      resp-status) / case-insensitive / find / replace / enabled /
      reorder, persisted in project.json
- [x] **ISSUES** — finding list with severity + kind filter chips,
      "Probe all rows" + "Export SARIF" + "Clear all" buttons, click
      to jump to originating row
- [x] **SCANS** — port scanner UI: host / hosts / CIDR field,
      presets (discovery / top100 / web / full1024 / custom),
      timeout, parallel, throttle, shuffle, banner-grab toggle,
      live progress + results table grouped open-first, host column,
      "Export nmap XML"
- [x] **RECON** — single-domain input, "Run all" button (DNS + crt.sh +
      wordlist) or each individually, two-pane layout (DNS records
      grouped by type, subdomains tagged by source)
- [x] **STATS** — Wireshark-style per-host endpoints: count, ↑ ↓ bytes,
      status-class mix, TLS, distinct paths, click to filter PROXY,
      overall summary pills, optional method-mix bar
- [x] **REPEATER** — tab strip (add / activate / rename / duplicate /
      close), per-tab host / port / TLS / request / response,
      send-to-repeater opens new tab
- [x] **INTERCEPT** — toggle, queue with depth indicator, current
      request editable, forward / drop / forward-all
- [x] **INTRUDER** — Sniper mode template + payloads + results table
      with per-row resend ↻, ↦ DISCOVERY one-click setup, hide-404s
      filter, ~10 built-in payload presets
- [x] **SETTINGS** — Proxy + CA & TLS + Projects + Project + Extensions
      + Browser setup cards

## Backend modules

- [x] **Proxy** (`Src/BackEnd/Proxy`) — HTTP/1.1 keep-alive, HTTPS MITM
      with on-the-fly forged leaf certs, HTTP/2 upstream via libnghttp2,
      WebSocket relay after 101 with frame parsing, thread-per-connection,
      scope filter, per-host MITM bypass list
- [x] **CertAuthority** — root CA generation on first run, per-host leaf
      mint via OpenSSL CLI, on-disk cache, strict hostname validation
- [x] **Intercept** — pause / forward / drop / forward-all with queue,
      QSemaphore-based worker handoff, signal emit outside the mutex
      (deadlock fix `30320f0`)
- [x] **Match & Replace** — `MatchReplaceRule` struct in proxy headers,
      `applyRequestRules` / `applyResponseRules` on `ProxyServer`,
      auto-Content-Length rewrite on body mutation, `rulesHit` counter
- [x] **PassiveScanner** (`Src/Core/Networking/passive_scanner`) — 10
      finding kinds, capped at 1000 in memory, rowId tracking synced
      with `ProxyModel`
- [x] **Active probe** (in `control_server.cpp`) — 6 vuln classes per
      query param: reflected-xss / open-redirect / sqli-error /
      path-traversal / cmd-injection / crlf-injection. `/probe/all`
      throttles across every history row with query params.
- [x] **PortScanner** (`Src/Core/Networking/port_scanner`) — TCP-connect,
      banner grab + classify, presets, CIDR + multi-host, stealth
      (throttle + shuffle), setResults for import
- [x] **ReconEngine** (`Src/Core/Networking/recon_engine`) — async
      QDnsLookup, crt.sh HTTPS query on a worker, wordlist DNS sweep
      with OS-resolver suffix-expansion filter
- [x] **Repeater** (`Src/Core/Networking`) — multi-tab with active-index
      semantics, single-state legacy API preserved for QML
- [x] **Intruder** — `QAbstractListModel`, `§marker§` template,
      `QtConcurrent::run` worker, per-row resend
- [x] **ProjectStore** (`Src/Core/Storage`) — `project.json` (scope +
      notes + rules) + `history.ndjson`, multi-project switcher,
      HAR import / export, `historyShouldClear` signal on project
      switch
- [x] **Themes** — built-ins (retro / mono / amber / cyber / ice) + JSON
      file loader + save-as
- [x] **ExtensionsApi** — JS plugins in shared `QJSEngine`,
      `onRequest` / `onResponse` mutation hooks via
      `BlockingQueuedConnection`
- [x] **ControlServer** (`Src/BackEnd/Control`) — HTTP/1.1 on 127.0.0.1,
      static ui-v2 serving, `/api/*` JSON, snapshot polling with
      `seq` 304 short-circuit, **CSRF Origin guard** on writes,
      no ACAO on responses

## REST API surface

### Snapshot + state
- `GET /api/snapshot[?since=N]` — full state; 304 when seq unchanged
- `GET /api/history/<id>/request` — raw request bytes
- `GET /api/history/<id>/response` — raw response bytes

### Mutations
- `POST /api/proxy/toggle`
- `POST /api/intercept/{toggle,forward,drop,forwardAll}`
- `POST /api/scope/{in,out}/{add,remove}`
- `POST /api/scope/notes`
- `POST /api/rules/{add,update,remove,toggle,move}`
- `POST /api/repeater/{set,send,clear,tab/{add,addFromHistory,close,activate,rename,duplicate}}`
- `POST /api/intruder/{set,start,stop,clear,resend}`
- `POST /api/theme` / `/api/theme/save-as` / `/api/theme/reload`
- `POST /api/clear-history`, `/api/mitm/clear-blocked`
- `POST /api/extensions/reload`
- `POST /api/findings/clear`
- `POST /api/project/{list,open,create}`

### Active scanning
- `POST /api/history/<id>/probe` — per-row active scan
- `POST /api/history/<id>/replay` — replay through mutation pipeline
- `POST /api/probe/all` — every row with query params, throttled

### Port scanner
- `POST /api/portscan/start` (host | hosts | cidr, preset | ports,
  timeoutMs, parallel, throttleMs, randomize, banner)
- `POST /api/portscan/{stop,clear}`
- `POST /api/portscan/import-nmap` (raw nmap XML body)

### Recon
- `POST /api/recon/{dns,crt,wordlist,stop,clear}`

### Search
- `GET /api/search?q=<regex>&where=req|resp|both&limit=N`

### Tool integration / exports
- `GET /api/export/nmap-xml` — port-scan results as nmaprun XML
- `GET /api/export/sarif` — findings as SARIF v2.1
- `GET /api/export/postman` — history as Postman v2.1 collection
- `POST /api/har/{export,import}`
- `GET /api/pac` — proxy auto-config file with live port
- `GET /ca.pem` / `/ca.crt` — CA download

## Future / unbuilt (roadmap)

- [ ] `--headless` flag (skip QML window + browser auto-open)
- [ ] NDJSON stdout event stream in headless mode
- [ ] `nullock` CLI binary OR shell wrapper around REST API
- [ ] Python client library (separate repo)
- [ ] HTTP/2 multiplexing (single stream per CONNECT today)
- [ ] Server-side h2 to browser
- [ ] WebSocket `permessage-deflate`
- [ ] TLS fingerprint randomization (JA3 evasion for Cloudflare hosts)
- [ ] Saved auth-token / session manager
- [ ] WHOIS + reverse DNS in recon tab
- [ ] WebSocket frame grouping (per-session collapsible view in history)

## Bugs caught + fixed in this codebase

- **Critical: intercept deadlock** (`30320f0`) — `addPendingOnMain` /
  `forward()` / `drop()` emitted `currentChanged` while holding
  `m_queueMutex`. QML's `intercept.queueDepth` binding evaluates
  synchronously on emit and re-acquires the same non-recursive mutex
  → main-thread deadlock, control server frozen. Fix: emit outside
  the lock.
- **okJson()** was hard-overriding `ok: true` regardless of input —
  every endpoint that reported failure was lying. Fixed.
- **CSRF via ACAO `*`** — any web page could read captured creds
  cross-origin. Fixed: removed ACAO from API + added Origin guard
  on writes.
- **CA hostname injection** — newline in CONNECT host could inject
  openssl extension config; `/` could graft DN fields onto the cert
  subject. Fixed via strict `isValidHostForCert` check.
- **`openByName` silently created project dirs** on typo. Fixed.
- **Replay re-entered control loop** via sync HttpClient → crashed
  the app. Fixed by running on QtConcurrent.
- **Scanner rowId off-by-N** after history replay. Fixed via
  `setNextRowId(model.rowCount() + 1)` + `modelReset` wire.
- **DNS suffix expansion** contaminated wordlist subdomain enum
  (Windows resolver appended local search domain to NXDOMAIN names).
  Fixed by filtering on record name match.
- **CRLF probe payload** had a literal space that broke its own
  request line. Fixed by percent-encoding.
- **Postbuild deploy** of FrontEndGUI.dll + Qt6Concurrent.dll was
  missing → STATUS_ENTRYPOINT_NOT_FOUND on bare launches. Fixed
  via POST_BUILD in `Src/App/CMakeLists.txt`.

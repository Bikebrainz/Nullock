# Nullock

A FOSS, all-in-one web security toolkit. C++20 + Qt6 backend, React-in-the-browser UI, CMake build.

Burp-flavored MITM proxy + nmap-flavored port scanner + Wireshark-flavored traffic stats + DNS / cert-transparency recon + JS extensions, all behind one local REST API and one retro-looking browser UI. Built as a fast, FOSS alternative to the Burp Pro / ZAP / nmap / mitmproxy combo for web hacking and bug-bounty work.

## Architecture

```
   ┌──────────── headless backend (Qt6) ────────────┐         ┌─── browser ───┐
   │                                                │         │               │
   │  ProxyServer (HTTP/1.1 + h2 upstream + WS)     │         │  React UI     │
   │  CertAuthority (forged leaf certs via OpenSSL) │         │  (ui-v2/      │
   │  Intercept controller (pause / forward / drop) │         │   *.jsx,      │
   │  Match & Replace engine (regex per section)    │ <─────> │   Babel       │
   │  Passive scanner (10 finding kinds)            │  HTTP   │   in-browser) │
   │  Active probe (6 vuln classes per param)       │         │               │
   │  Port scanner (TCP-connect + CIDR + banner)    │         │  9 tabs:      │
   │  Recon engine (DNS / crt.sh / wordlist)        │         │  proxy scope  │
   │  Repeater (multi-tab) + Intruder (sniper)      │         │  rules issues │
   │  Project store (history.ndjson, per-project)   │         │  scans recon  │
   │  Extensions API (JS in QJSEngine)              │         │  stats        │
   │                                                │         │  repeater     │
   │  ControlServer (REST API + static UI host)     │         │  intercept    │
   │       127.0.0.1:17777                          │         │  intruder     │
   │                                                │         │  settings     │
   └────────────────────────────────────────────────┘         └───────────────┘
```

Backend listens on a fallback chain `[8080, 8081, 8888, 8090, 9090]` for the proxy and `[17777, 27777, 37777, 47777, 57777]` for the control server (skipping common collisions like MinIO 9000/9001). The browser fetches `ui-v2/*.jsx` from the control server, polls `/api/snapshot?since=<seq>` every 250ms with a 304 short-circuit when nothing changed, and posts to `/api/*` for every mutation.

## Build

Requirements:
- CMake 3.24+
- Qt6 (Core, Gui, Qml, Quick, Network, Concurrent)
- A C++20 compiler (MSVC 2022 / GCC 13+ / Clang 16+)
- OpenSSL CLI (for MITM cert generation; on Windows install via `winget install ShiningLight.OpenSSL.Light`). `CertAuthority` looks for `openssl.exe` at the standard `C:\Program Files\OpenSSL-Win64\bin\` location and falls back to PATH.
- libnghttp2 (for HTTP/2 upstream support). Easiest via vcpkg: `vcpkg install nghttp2:x64-windows`. The Proxy CMakeLists picks up `NULLOCK_NGHTTP2_ROOT` (defaults to `D:/vcpkg/installed/x64-windows`); set via `-DNULLOCK_NGHTTP2_ROOT=...` if your vcpkg lives elsewhere. `nghttp2.dll` must be deployed alongside the exe.

```
cmake -S . -B Build -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_PREFIX_PATH="C:/Qt/6.7.3/msvc2019_64"
cmake --build Build --config Release --target NullockApp
```

On Windows the QML module library needs to live alongside the exe before running, and Qt's runtime needs to be deployed too. The build does this automatically as a `POST_BUILD` step, but for a manual deploy:

```
copy Build\Src\FrontEnd\GUI\Release\FrontEndGUI.dll Build\Src\App\Release\
"<Qt>/bin/windeployqt.exe" --release --qmldir Src\App ^
    Build\Src\App\Release\NullockApp.exe
```

Run from the project root so the relative QML / `ui-v2` paths resolve:

```
Build\Src\App\Release\NullockApp.exe
```

The control server opens `http://127.0.0.1:17777/` in your default browser on startup. The QML window is legacy — the React UI is what you'll actually use.

## First-run browser setup

Open **Settings → Browser setup**. Copy the PAC URL into your browser's "Automatic proxy configuration URL" field (Firefox: Settings → Network Settings; Chrome/Edge: System → Open your computer's proxy settings). Then install the CA cert from `%APPDATA%/Nullock/Nullock/ca/ca.pem` (or download via the Settings → CA & TLS card) so HTTPS interception doesn't throw warnings.

## What each tab does

**PROXY** — Live HTTP/HTTPS history table on the right, a Site Map of hosts on the left, a request/response detail pane on the bottom. Filter by host / status class / method / URL substring. Toggle "DEEP" to search inside request and response bodies via regex. Click any row to inspect:

- **REQ / RES tabs** with `raw / headers / body / preview / hex` views (preview pretty-prints JSON; hex is a canonical hexdump)
- **Codec bar** above each pane: URL / Base64 / JWT / Hex / HTML encode-decode operating on selection or whole pane, result in an overlay
- **↦ REPEATER / INTRUDER** — send the row to those tools
- **↻ REPLAY** — re-fire the captured request through the proxy's full mutation pipeline (extensions + match&replace) so you can A/B test what a new rule does
- **⚡ PROBE** — fire the active vuln probe against this row's query params
- **⊟ MARK / DIFF vs #NNN** — mark one row, then a second; opens a side-by-side line-level diff overlay (LCS-based)
- **↦ COPY AS ▾** — emit the request as a paste-ready command for `curl`, `wget`, `httpie`, PowerShell, `fetch()`, `sqlmap`, Postman v2.1 collection JSON, Nuclei template skeleton, or raw Burp-paste bytes

**SCOPE** — Glob-based in-scope / out-of-scope host lists per project (`*.example.com`-style). Out-of-scope hosts skip MITM and don't reach the model or `history.ndjson`. Editable notes field for engagement context.

**RULES** — Match & Replace engine. Regex find/replace targeting one of: request URL, request header, request body, response header, response body, response status. Per-project, persisted in `project.json`, applies on every in-scope round-trip after the extensions hook. `rulesHit` counter shows how often the rules actually fired.

**ISSUES** — Findings list from the passive + active scanners.
- **Passive scanner** runs on every response automatically: missing CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy on HTML, cookies missing HttpOnly / Secure / SameSite, `Server` version leak, `X-Powered-By`, CORS wildcard, ACAO `*` with credentials, sensitive params in URL (`token`, `auth`, `api_key`, etc.), `Authorization` over plaintext HTTP.
- **Active probe** is fired per-row (via the ⚡ PROBE button on a row, or **Probe all rows** here): for every query param, substitutes XSS canary / open-redirect canary / `'` SQLi / `../../etc/passwd` / `;id;#` / CRLF `%0d%0a` payloads and looks for tell-tale responses (reflected canary in body, canary host in `Location`, SQL error text, `root:x:0:0:`, `uid=` line, injected header).
- Filter chips for severity and kind. Click a finding to jump to its originating history row.
- **Export SARIF** dumps findings as SARIF 2.1.0 for CI ingestion (GitHub code scanning, Azure DevOps, etc.).

**SCANS** — Nmap-flavored TCP-connect port scanner.
- Host field accepts a single IP/host, a comma-separated list, or a CIDR (`192.168.1.0/24`).
- Presets: `discovery` (22/80/443/3389) for "is anything alive", `top100` (nmap's top-ports 100), `web`, `full1024` (all 1-1024), or custom comma-separated.
- Banner-grabs open ports and classifies the service via wire-format prefixes (`SSH-`, `HTTP/`, `+OK`, etc.) and port heuristics for the ~40 services that don't auto-banner.
- Stealth: throttle ms between probe launches + shuffle probe order, so a scan doesn't hammer one host in a tight burst.
- **Export nmap XML** for interop with everything that consumes nmap output (Metasploit workspaces, dnmap, the nmap GUI, vulnerability scanners). Reciprocal **import** lets you pull existing nmap XML scans into the UI.

**RECON** — Recon-for-web-testing (not OSINT-for-people). Three operations against a single domain input:
- **DNS lookups** — A / AAAA / MX / TXT / NS / CNAME records in parallel, ~500ms total on a warm resolver. MX priorities surfaced.
- **crt.sh** — certificate transparency log query for subdomains that have been issued certs for the target domain. Best-effort; crt.sh sits behind Cloudflare and rejects Qt's TLS fingerprint, so this one fails gracefully with a clear message when it does.
- **Wordlist** — prepends each of ~100 curated subdomains (`www`, `mail`, `api`, `admin`, `dev`, `staging`, `jenkins`, `grafana`, `ns1`, ...) to the target and resolves all of them. Resolved subs land in the panel; OS-resolver suffix expansion is filtered out so you don't get ghosts from your local DNS search list.

**STATS** — Wireshark-style "Endpoints" view. Per-host aggregation of every captured row:
- request count, ↑ out bytes, ↓ in bytes
- status-class mix (2xx / 3xx / 4xx / 5xx / WS) coloured inline
- TLS coverage, distinct path count
- click a row to filter the PROXY tab to that host
- Optional method-mix bar at the top breaks down GET vs POST vs WS↑/↓ across the whole capture

**REPEATER** — Multi-tab one-shot request editor. Each tab carries its own host/port/TLS/request/response. Send-to-repeater opens a new tab (doesn't clobber whatever's already open). Rename, duplicate, close, switch between tabs from the strip at the top.

**INTERCEPT** — Pause / forward / drop / forward-all in-flight requests. Toggle on, queue depth shown in status bar. Edit the raw request in the pane before forwarding to mutate it on the wire. **Critical deadlock fix here is documented in the commit log** — earlier versions froze the entire control server the moment a single request hit the queue (signal-emit-under-mutex with a QML binding re-entering).

**INTRUDER** — Burp-flavored Sniper mode. Take a request template with one `§marker§` insertion point, a newline-separated payload list, fire one request per payload on a worker thread, populate a live results table (id / payload / status / size / ms / error). Per-row resend button to re-fire a single variant. Built-in payload presets:
- numbers (1-100), common usernames, weak passwords
- sqli, xss, path-traversal, ssrf candidates, fuzz strings
- common files (`.env`, `.git/config`, `wp-config.php`, `swagger.json`, ...)
- **common paths (dir-brute)** — ~120 entries covering admin panels / dev-staging / VCS metadata / CI dashboards / cloud creds / classic webapp files
- user-agent rotation list
- **↦ DISCOVERY** button auto-fills target + template + dir-brute wordlist from a single URL prompt; hide-404s checkbox in the results pane floats the interesting paths to the top

**SETTINGS** — Six cards in one panel:
- **Proxy** status + bind / control port / HTTP/2 hops / filtered count / mitm bypass list, with Start/Stop/Clear-blocklist buttons
- **CA & TLS** with copyable CA path, "Download .crt" button (`/ca.crt` with proper `Content-Disposition` so the browser saves it), folder opener
- **Projects** — list every project under `<AppData>/Nullock/Nullock/projects/`, click to switch (wipes the model + reloads scope + reloads rules + replays history), text input + Enter to create
- **Project** — current project's stats, **Export HAR** (HAR 1.2), **Export Postman** (v2.1 collection of every captured row), **Import HAR** (drag-and-drop or file picker), **Clear history**
- **Extensions** — `.js` files in `<AppData>/Nullock/Nullock/extensions/` run in a shared `QJSEngine`. Global `nullock` object exposes `log(msg)`, `onRequest(fn)`, `onResponse(fn)`. Returning a modified entry from a hook mutates the wire bytes — header injection, body rewrites, method/path overrides all take effect. Reload button rescans the dir.
- **Browser setup** — HTTP proxy host:port, PAC URL (`/api/pac` returns a real PAC file with the live proxy port), copy-paste snippets for curl / PowerShell / Firefox `about:config`, short hints for Chrome/Edge/Firefox proxy menus.

## Tool integration

Nullock plays well with the rest of a tester's toolbox:

| Tool | Direction | How |
|---|---|---|
| curl | export | `↦ COPY AS ▾ → curl` on any row |
| wget | export | same dropdown |
| httpie | export | same dropdown |
| PowerShell `Invoke-WebRequest` | export | same dropdown |
| `fetch()` (JS) | export | same dropdown |
| sqlmap | export | same dropdown — pre-armed `--batch --random-agent`, `-H` per header, `--data` if POST, `--level=2 --risk=2` |
| Postman | export | per-row from the dropdown OR whole-project collection from Settings |
| Nuclei | export | template skeleton with the captured raw request embedded under `requests[].raw` and a placeholder matcher |
| Burp Repeater | export | "burp-raw" outputs just the on-the-wire bytes |
| HAR (Chrome DevTools, Burp, Charles, Insomnia) | both | `/api/har/export` + `/api/har/import` |
| nmap | both | `/api/export/nmap-xml` ⇆ `/api/portscan/import-nmap` |
| SARIF (GitHub code scanning, Azure DevOps) | export | `/api/export/sarif` |

## Smoke test

A self-test that exercises proxy + intercept + repeater + intruder + HAR + h2 + WebSocket parsing + extensions + match&replace + scanner + project switch + repeater multi-tab without GUI interaction:

```
Build\Src\App\Release\NullockApp.exe --smoke-test
```

Exits 0 on pass, 1 on fail. 14 cases; failures with `httpbin.org` in the message are usually their AWS LB flaking, not real regressions — re-run once.

## Project on disk

`<AppData>/Nullock/Nullock/`
- `ca/` — root CA + per-host leaves + persistent MITM bypass list
- `projects/<name>/`
  - `project.json` — scope (in/out globs), match-replace rules, notes
  - `history.ndjson` — append-only round-trip log (auto-streams into the model on open)
  - `exports/` — HAR exports land here
- `themes/` — drop a `<name>.json` here and it appears in the theme switcher
- `extensions/` — `.js` files run in a shared QJSEngine on startup / `/api/extensions/reload`

## Security model

The control server binds `127.0.0.1` only and applies two guards on top of that:

- **No `Access-Control-Allow-Origin`** on `/api/*` responses. Browser same-origin policy stops random web pages from reading captured creds via `fetch()`.
- **Origin check on writes**. `POST/PUT/PATCH/DELETE` requests with a non-matching `Origin` are 403'd. Empty Origin (curl, scripts) is allowed. Same-origin from the React UI works normally.

Plus a few hardening notes from the audit logs:

- Match-replace, scope globs, intruder payloads — none of these have authority to execute code locally. They get serialized to HTTP wire bytes and that's it.
- CA cert leaf minting validates the host string strictly against `[A-Za-z0-9._-]{1,253}` before feeding it to OpenSSL via `QProcess::setArguments` (no shell). A malicious CONNECT host with newlines or `/` characters can't inject openssl extension config or graft extra DN fields onto the cert subject.
- Project create/open rejects names containing `/`, `\`, or `..`.

## Module status

| Area | State | Notes |
|---|---|---|
| Proxy core | ✓ | HTTP/1.1 keep-alive, HTTPS MITM with forged leaf certs, HTTP/2 upstream via libnghttp2, WebSocket relay after 101, thread-per-connection, scope filter |
| Cert authority | ✓ | per-host leaf certs cached under `ca/leaves/`, strict hostname validation, OpenSSL fallback to blind-pipe |
| Intercept | ✓ | per-request pause/forward/drop + forward-all, multi-request queue (deadlock fix in commit `30320f0`) |
| Repeater | ✓ | multi-tab — each tab its own host/req/resp, rename/dup/close |
| Intruder | ✓ | Sniper mode with `§marker§`, payload library (~10 curated lists incl. dir-brute), per-row resend |
| Match & Replace | ✓ | regex rewrites of URL / headers / body / status, per-project persistence, live application |
| Passive scanner | ✓ | 10 finding kinds, severity, kind filters in UI |
| Active probe | ✓ | reflected-XSS / open-redirect / sqli-error / path-traversal / cmd-injection / crlf-injection; per-row or "probe all rows" with throttle |
| Port scanner | ✓ | TCP-connect, banner-grab, service classify, presets (discovery / top100 / web / full1024 / custom), CIDR + multi-host + stealth (throttle + shuffle) |
| Recon | ✓ | DNS A/AAAA/MX/TXT/NS/CNAME, crt.sh CT log (best-effort behind Cloudflare), wordlist subdomain enum with OS-resolver suffix-expansion filter |
| Network stats | ✓ | per-host aggregation: count / ↑↓ bytes / status mix / TLS / paths / method mix |
| Detail pane | ✓ | raw/headers/body/preview/hex, codec helpers (URL/b64/JWT/hex/HTML), copy-as for 9 tools, row-to-row diff |
| Site map | ✓ | aggregates hosts; click to filter history |
| HAR | ✓ | export + import; HAR 1.2 spec |
| Tool exports | ✓ | nmap XML, SARIF v2.1, Postman v2.1 collection, all 9 copy-as targets |
| Themes | ✓ | five built-ins (retro/mono/amber/cyber/ice), JSON palette files, live color editor with save-as |
| Extensions | ✓ | `.js` files in `extensions/` run in a shared `QJSEngine`; `onRequest` / `onResponse` mutation hooks; cross-thread safe |
| Projects | ✓ | multiple projects on disk; switch from Settings; each has its own scope/rules/history.ndjson |
| Control server | ✓ | HTTP/1.1 on 127.0.0.1:17777, static UI + `/api/*` JSON, snapshot polling with `seq` 304 short-circuit, CSRF Origin guard |
| Smoke test | ✓ | 14 cases covering proxy + intercept + repeater + intruder + HAR + h2 + WebSocket + extensions + rules + scanner + multi-tab + project switch |

## Roadmap

- [ ] `--headless` flag (skip QML window + auto-browser-open, just run proxy + control server — for CI / Docker / scripting)
- [ ] NDJSON stdout event stream in headless mode (tail-friendly, pipes into `jq`)
- [ ] `nullock` CLI binary or shell wrapper around the REST API
- [ ] Python client library (separate repo, `pip install pynullock`)
- [ ] HTTP/2 multiplexing (currently single-stream per CONNECT)
- [ ] Server-side h2 to the browser (we only speak h2 upstream)
- [ ] WebSocket `permessage-deflate`
- [ ] TLS fingerprint randomization (Cloudflare-style JA3 fingerprinting currently rejects our handshake on `crt.sh` and a handful of other Cloudflare-fronted hosts)
- [ ] Sessions / saved auth tokens manager
- [ ] WHOIS + reverse DNS in the recon tab
- [ ] WebSocket frame grouping in history (per-session collapsible view)

## License

MIT. See [LICENSE.md](LICENSE.md).

---

_Last updated: 2026-05-30_

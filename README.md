# Nullock

A FOSS, Burpsuite-style MITM HTTP proxy. C++20 + Qt6 backend, React-in-the-browser UI, CMake build.

The goal is to close the gap between Burpsuite's paywalled "save your project" experience and ZAP's clunky UI — a fast, retro-looking, open-source alternative for web hacking and bug bounty work.

## Architecture

```
   ┌──── headless backend (Qt) ────┐       ┌──── browser ────┐
   │  ProxyServer (HTTP/1.1 + h2)  │       │                 │
   │  MITM tunnel, intercept queue │       │  React UI       │
   │  Match & Replace pipeline     │ <───> │  (ui-v2/*.jsx,  │
   │  Passive scanner              │  HTTP │   Babel in-browser)
   │  Repeater, Intruder, Scope    │       │                 │
   │  Project store (ndjson)       │       └─────────────────┘
   │  ControlServer (127.0.0.1:17777)
   └────────────────────────────────┘
```

Backend listens on a fallback chain `[8080, 8081, 8888, 8090, 9090]` for the proxy and `[17777, 27777, 37777, 47777, 57777]` for the control UI (skipping common collisions like MinIO 9000/9001). The browser fetches `ui-v2/*.jsx` from the control server, polls `/api/snapshot?since=<seq>` every 250ms with cheap 304 short-circuit when nothing changed, and posts to `/api/*` for every mutation.

## Build

Requirements:
- CMake 3.24+
- Qt6 (Core, Gui, Qml, Quick, Network, Concurrent)
- A C++20 compiler (MSVC 2022 / GCC 13+ / Clang 16+)
- OpenSSL CLI (for MITM cert generation; on Windows install via `winget install ShiningLight.OpenSSL.Light`). `CertAuthority` looks for `openssl.exe` at the standard `C:\Program Files\OpenSSL-Win64\bin\` location and falls back to PATH.
- libnghttp2 (for HTTP/2 upstream support). Easiest via vcpkg: `vcpkg install nghttp2:x64-windows`. The Proxy CMakeLists picks up `NULLOCK_NGHTTP2_ROOT` (defaults to `D:/vcpkg/installed/x64-windows`); set it via `cmake -DNULLOCK_NGHTTP2_ROOT=...` if your vcpkg lives elsewhere. `nghttp2.dll` must be deployed alongside the exe.

Configure and build (point CMAKE_PREFIX_PATH at your Qt install):

```
cmake -S . -B Build -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_PREFIX_PATH="C:/Qt/6.7.3/msvc2019_64"
cmake --build Build --config Release --target NullockApp
```

On Windows the QML module library needs to live alongside the exe before
running, and Qt's runtime needs to be deployed too:

```
copy Build\Src\FrontEnd\GUI\Release\FrontEndGUI.dll Build\Src\App\Release\
"<Qt>/bin/windeployqt.exe" --release --qmldir Src\App ^
    Build\Src\App\Release\NullockApp.exe
```

Run from the project root so the relative QML / `ui-v2` path resolves:

```
Build\Src\App\Release\NullockApp.exe
```

The control server opens `http://127.0.0.1:17777/` in your default browser on startup. The QML window is legacy and headless — the React UI is what you'll actually use.

## First-run browser setup

Open Settings → Browser setup. Copy the PAC URL into your browser's "Automatic proxy configuration URL" field (Firefox: Settings → Network Settings; Chrome/Edge: System → Open your computer's proxy settings). Then install the CA cert from `%APPDATA%/Nullock/Nullock/ca/ca.pem` so HTTPS interception doesn't throw warnings.

## Smoke test

A self-test that exercises the proxy, intercept, and repeater end-to-end without GUI interaction lives behind a flag:

```
Build\Src\App\Release\NullockApp.exe --smoke-test
```

Exits 0 on pass, 1 on fail.

## Feature status

| Area | State | Notes |
|---|---|---|
| Proxy core | ✓ | HTTP/1.1 keep-alive, HTTPS MITM with forged leaf certs, HTTP/2 upstream via libnghttp2, WebSocket relay after 101, thread-per-connection |
| Cert authority | ✓ | per-host leaf certs cached under `ca/leaves/`, OpenSSL fallback to blind-pipe |
| Intercept | ✓ | per-request pause/forward/drop + forward-all, multi-request queue |
| Repeater | ✓ | multi-tab — each tab its own host/req/resp; send-to-repeater opens a new tab |
| Intruder | ✓ | Sniper mode with `§marker§`, payload library (SQLi/XSS/traversal/etc.), per-row resend |
| Scope filter | ✓ | glob-based include/exclude, out-of-scope hosts skip MITM and history |
| Match & Replace | ✓ | regex rewrites of URL / headers / body / status; per-project, on-the-fly |
| Passive scanner | ✓ | missing security headers, leaky cookies, ACAO misconfig, secrets-in-URL, auth-over-HTTP |
| History | ✓ | live table + filter bar + deep regex search across bodies |
| Detail pane | ✓ | request/response splits with raw/headers/body/preview/hex views + codec helpers (URL/b64/JWT/hex/HTML) + row-to-row diff overlay |
| Site map | ✓ | aggregates hosts; click to filter history |
| HAR | ✓ | export + import; HAR 1.2 spec, opens cleanly in DevTools / Burp / Charles |
| Themes | ✓ | five built-ins (retro/mono/amber/cyber/ice), JSON palette files, live color editor with save-as |
| Extensions | ✓ | `.js` files in `extensions/` run in a shared `QJSEngine`; mutate request/response via `onRequest` / `onResponse` |
| Projects | ✓ | multiple projects on disk; switch from Settings; each has its own scope/rules/history.ndjson |
| Issues tab | ✓ | live findings list with severity/kind filters and click-to-jump-to-row |
| Settings | ✓ | proxy + CA + project + extensions + browser-setup cards in one panel |
| Control server | ✓ | HTTP/1.1 on 127.0.0.1:17777, static UI + `/api/*` JSON, snapshot polling with `seq` 304 short-circuit |
| Smoke test | ✓ | `--smoke-test` exercises proxy + intercept + repeater + intruder + HAR + h2 + extensions |

## Roadmap

- [ ] HTTP/2 multiplexing (currently single-stream per CONNECT)
- [ ] Server-side h2 to the browser (we only speak h2 upstream)
- [ ] WebSocket `permessage-deflate`
- [ ] TLS fingerprint randomization (Cloudflare-style JA3 fingerprinting currently rejects our handshake on some hosts)
- [ ] Active scanner (light probes for XSS reflection, OPTIONS surface, etc.)
- [ ] Sessions / saved auth tokens
- [ ] Mobile CA install helper (QR code linking to ca.pem)
- [ ] Request templates / scratchpad

## License

MIT. See [LICENSE.md](LICENSE.md).

---

_Last updated: 2026-05-27_
